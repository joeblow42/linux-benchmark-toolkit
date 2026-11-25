"""Generated-content copy and rsync benchmarks for an explicit local destination."""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from .core_workloads import IOPressureGuard, MIB, local_filesystem
from .workload_process import ProcessLimit, capture, tool_path
from .workload_runtime import Cancelled, Context, Mode, Resources, Unavailable, Unsafe, Workload

CASES = ("backup-large", "backup-small", "backup-rsync", "backup-concurrent")


@dataclass(frozen=True)
class Backup:
    destination: Path
    reserve_bytes: int
    large_mib: int = 64
    small_files: int = 2048

    def __post_init__(self):
        if not 1 <= self.large_mib <= 1024 or not 1 <= self.small_files <= 8192:
            raise ValueError("backup bounds are 1–1024 MiB and 1–8192 small files")
        if self.reserve_bytes < 0:
            raise ValueError("backup reserve must be nonnegative")


def run_backup(context, config, case):
    destination = config.destination.absolute()
    if destination.is_symlink() or not destination.is_dir():
        raise Unavailable("BACKUP_DESTINATION_REQUIRED")
    destination = destination.resolve()
    filesystem = local_filesystem(destination)
    rsync = tool_path("rsync") if case == "backup-rsync" else ""
    guard = IOPressureGuard(context.check_stop)
    guarded = Context(context.scratch, guard.poll, context.inventory, context.evidence)
    metadata = destination.stat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise Unavailable("BACKUP_DESTINATION_WRITABLE_BY_OTHERS")
    outcome = None
    try:
        with TemporaryDirectory(prefix="lbt-backup-", dir=destination) as target:
            command = (sys.executable, str(Path(__file__).with_name("backup_worker.py").resolve()),
                       case, str(context.scratch.resolve()), target, str(config.large_mib),
                       str(config.small_files), str(config.reserve_bytes), rsync)
            response = capture(guarded, command, seconds=300, output_bytes=64 * 1024)
            outcome = (json.loads(response.stdout) if response.returncode == 0
                       else {"error": "BACKUP_WORKER_FAILED", "exit_code": response.returncode})
            guard.poll(force=True)
    except (Cancelled, KeyboardInterrupt):
        outcome = {"error": "BACKUP_INTERRUPTED"}
        raise
    except Unsafe as error:
        outcome = {"error": str(error)}
        raise
    except ProcessLimit as error:
        outcome = {"error": str(error)}
    except OSError as error:
        outcome = {"error": "BACKUP_DESTINATION_OR_CLEANUP_ERROR", "errno": error.errno}
    except (ValueError, TypeError):
        outcome = {"error": "BACKUP_WORKER_FAILED"}
    finally:
        if context.evidence is not None:
            context.evidence.mkdir(mode=0o700)
            (context.evidence / "backup.json").write_text(
                json.dumps(outcome or {"error": "BACKUP_INTERRUPTED"}) + "\n", encoding="utf-8")
    if "unavailable" in outcome:
        raise Unavailable(outcome["unavailable"])
    if "error" in outcome or not outcome["integrity"]["verified"]:
        raise RuntimeError("backup transfer or integrity check failed")
    return {**outcome, "destination_filesystem": filesystem, "peak_io_pressure_percent": guard.peak}


def backup_workloads(config):
    return tuple(
        Workload(case, "backup", Mode.EXTENDED, Resources(cpu_workers=1, memory_bytes=32 * MIB),
                 lambda context, case=case: run_backup(context, config, case), requires_selection=True)
        for case in CASES
    )
