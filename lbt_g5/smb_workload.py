"""Explicit guest SMB benchmark with bounded transfer and cleanup."""
import json
from pathlib import Path
import re
import sys
import uuid

from .core_workloads import IOPressureGuard, MIB
from .workload_process import ProcessLimit, capture
from .workload_runtime import Cancelled, Context, Mode, Resources, Unsafe, Workload

DEFAULTS = Path(__file__).resolve().parents[1] / "config" / "backup.local.json"


def smb_target(override=None):
    target = override
    if target is None and DEFAULTS.is_file():
        target = json.loads(DEFAULTS.read_text(encoding="utf-8"))["smb_target"]
    if not isinstance(target, str) or not re.fullmatch(r"//[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*", target):
        raise ValueError("provide an SMB target in //host/share form or set smb_target in config/backup.local.json")
    return target


def run_smb(context, target, size):
    guard = IOPressureGuard(context.check_stop)
    guarded = Context(context.scratch, guard.poll, context.inventory, context.evidence)
    filename = f"lbt-backup-{uuid.uuid4().hex}.tmp"
    url = "smb:" + target + "/" + filename
    marker = context.scratch / "smb-created"
    worker = str(Path(__file__).with_name("smb_worker.py").resolve())
    outcome = {}

    def invoke(operation, ctx, deadline):
        response = capture(ctx, (sys.executable, worker, operation, url, str(size), str(marker)),
                           seconds=deadline, output_bytes=16 * 1024)
        if response.returncode:
            return {"error": "SMB_WORKER_FAILED", "exit_code": response.returncode}
        return json.loads(response.stdout)

    try:
        outcome = invoke("transfer", guarded, 120)
        guard.poll(force=True)
    except (Cancelled, KeyboardInterrupt):
        outcome["error"] = "SMB_INTERRUPTED"
        raise
    except Unsafe as error:
        outcome["error"] = str(error)
        raise
    except (ProcessLimit, OSError, ValueError):
        outcome["error"] = "SMB_TRANSFER_INCOMPLETE"
    finally:
        if marker.exists():
            # Cleanup is limited to the file this run opened with O_EXCL.
            cleanup_context = Context(context.scratch, lambda: None, {})
            try:
                removed = invoke("delete", cleanup_context, 15).get("deleted", False)
            except (ProcessLimit, OSError, ValueError):
                removed = False
            outcome["cleanup"] = "COMPLETE" if removed else "FAILED"
            if not removed:
                outcome["cleanup_filename"] = filename
        if context.evidence is not None:
            context.evidence.mkdir(mode=0o700)
            (context.evidence / "backup.json").write_text(json.dumps(outcome) + "\n", encoding="utf-8")
    if "error" in outcome or not outcome["integrity"]["verified"] or outcome.get("cleanup") != "COMPLETE":
        raise RuntimeError("SMB transfer, verification or cleanup failed")
    return {**outcome, "peak_io_pressure_percent": guard.peak}


def smb_workload(target, mib):
    if not 1 <= mib <= 256:
        raise ValueError("SMB fixture must be between 1 and 256 MiB")
    return Workload("backup-smb", "backup", Mode.EXTENDED,
                    Resources(cpu_workers=1, memory_bytes=16 * MIB),
                    lambda context: run_smb(context, target, mib * MIB), requires_selection=True)
