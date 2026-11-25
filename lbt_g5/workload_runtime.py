"""RP-06 development runtime. The production launcher cutover is separately gated."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Callable

from .canonical_session import build_canonical
from .engine import UnifiedCollectorEngine
from .private_inventory import read_private_inventory


class Mode(str, Enum):
    DISCOVERY = "discovery"
    STANDARD = "standard"
    EXTENDED = "extended"
    INTERACTIVE = "interactive"


class Status(str, Enum):
    COMPLETE = "COMPLETE"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


class Cancelled(Exception):
    """A cooperative workload stop."""


class Unsafe(Exception):
    """Stop subsequent workloads when a safety limit is reached."""


class Unavailable(Exception):
    """A workload prerequisite is unavailable."""


@dataclass(frozen=True)
class Resources:
    cpu_workers: int = 0
    memory_bytes: int = 0
    disk_bytes: int = 0

    def __post_init__(self):
        if any(type(value) is not int or value < 0 for value in
               (self.cpu_workers, self.memory_bytes, self.disk_bytes)):
            raise ValueError("resource quantities must be nonnegative integers")


@dataclass(frozen=True)
class Context:
    scratch: Path
    check_stop: Callable[[], None]
    inventory: dict
    evidence: Path | None = None


@dataclass(frozen=True)
class Workload:
    id: str
    group: str
    tier: Mode
    resources: Resources
    run: Callable[[Context], dict]
    requires_selection: bool = False


@dataclass
class Session:
    mode: Mode
    directory: Path
    inventory_state: str = "NOT_STARTED"
    state: str = "RUNNING"
    results: list = field(default_factory=list)

    def save(self):
        # Atomic single-file update. Completed results survive later cancellation.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                         dir=self.directory, delete=False) as stream:
            staging = Path(stream.name)
            try:
                json.dump({"mode": self.mode.value, "state": self.state,
                           "inventory_state": self.inventory_state, "results": self.results},
                          stream, indent=2, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
                staging.replace(self.directory / "workloads.json")
            finally:
                staging.unlink(missing_ok=True)


class Runtime:
    """Select registered workloads, acquire inventory once and run serially."""

    def __init__(self, workloads, *, limits: Resources, disk_reserve_bytes: int):
        self.workloads = tuple(workloads)
        ids = [item.id for item in self.workloads]
        if (len(set(ids)) != len(ids) or any(not re.fullmatch(r"[a-z][a-z0-9-]*", i) for i in ids)
                or any(item.tier not in (Mode.STANDARD, Mode.EXTENDED)
                       or not re.fullmatch(r"[a-z][a-z0-9-]*", item.group)
                       for item in self.workloads)):
            raise ValueError("invalid workload registry")
        if type(disk_reserve_bytes) is not int or disk_reserve_bytes < 0:
            raise ValueError("disk reserve must be a nonnegative integer")
        self.limits = limits
        self.disk_reserve_bytes = disk_reserve_bytes

    def plan(self, mode, *, selections=()):
        mode = Mode(mode)
        selections = tuple(selections)
        if mode is Mode.INTERACTIVE:
            valid = {item.id for item in self.workloads} | {
                f"group:{item.group}" for item in self.workloads if not item.requires_selection}
            if not selections or set(selections) - valid:
                raise ValueError("interactive mode requires registered workload or group selections")
            return tuple(item for item in self.workloads if item.id in selections
                         or (not item.requires_selection and f"group:{item.group}" in selections))
        if selections:
            raise ValueError("workload selection requires interactive mode")
        return tuple(item for item in self.workloads if not item.requires_selection and (
            mode is Mode.EXTENDED or mode is Mode.STANDARD and item.tier is Mode.STANDARD))

    def _reserve(self, request, directory):
        if (request.cpu_workers > self.limits.cpu_workers
                or request.memory_bytes > self.limits.memory_bytes
                or request.disk_bytes > self.limits.disk_bytes):
            raise Unavailable("RESOURCE_LIMIT")
        if request.disk_bytes:
            free = os.statvfs(directory)
            if free.f_bavail * free.f_frsize < request.disk_bytes + self.disk_reserve_bytes:
                raise Unavailable("DISK_RESERVE")

    def execute(self, directory, mode, *, selections=(), collectors=None, cancelled=lambda: False):
        if os.getuid() == 0 or os.geteuid() == 0:
            raise PermissionError("run the workload runtime as an ordinary user")
        mode = Mode(mode)
        workloads = self.plan(mode, selections=selections)
        directory = Path(directory)
        mode_bits = directory.stat()
        if (directory.is_symlink() or not directory.is_dir()
                or mode_bits.st_uid != os.geteuid() or mode_bits.st_mode & 0o077):
            raise PermissionError("results root must be an owner-only directory")
        session = Session(mode, Path(tempfile.mkdtemp(prefix="workload-", dir=directory)))
        run_id = datetime.now(timezone.utc).strftime("run-%Y%j%H%M%S")
        inventory_dir = session.directory / run_id
        inventory_dir.mkdir(mode=0o700)
        session.save()

        def check_stop():
            if cancelled():
                raise Cancelled()

        stop_reason = None
        inventory = None
        try:
            completed = UnifiedCollectorEngine(str(inventory_dir), run_id).run(
                collectors, cancel_requested=cancelled)
            manifest = build_canonical(inventory_dir, completed)
            inventory = read_private_inventory(inventory_dir)
            session.inventory_state = manifest["completion_state"]
            if completed.execution.terminal_state == "INTERRUPTED":
                raise Cancelled()
        except (Cancelled, KeyboardInterrupt):
            session.state, stop_reason = "INTERRUPTED", "CANCELLED"
        except Exception:
            session.state, stop_reason = "FAILED", "INVENTORY_FAILED"
            session.inventory_state = "FAILED"
            self._record_skips(session, workloads, stop_reason)
            session.save()
            raise
        session.save()

        for item in workloads:
            if stop_reason:
                self._record_skips(session, (item,), stop_reason)
                continue
            status, reason, measurements = Status.COMPLETE, "OK", {}
            started = time.monotonic()
            try:
                check_stop()
                with tempfile.TemporaryDirectory(prefix=f"{item.id}-", dir=session.directory) as staging:
                    self._reserve(item.resources, staging)
                    evidence = session.directory / f"{item.id}-evidence"
                    measurements = item.run(Context(Path(staging), check_stop, inventory, evidence))
                    if not isinstance(measurements, dict) or not measurements:
                        raise ValueError("workloads must return measured values")
                    json.dumps(measurements, allow_nan=False)
            except Unavailable as error:
                status, reason = Status.UNAVAILABLE, str(error)
            except (Cancelled, KeyboardInterrupt):
                session.state, stop_reason = "INTERRUPTED", "CANCELLED"
                status, reason = Status.SKIPPED, stop_reason
            except Unsafe as error:
                session.state, stop_reason = "FAILED", "SAFETY_STOP"
                status, reason = Status.FAILED, str(error)
            except Exception:
                status, reason = Status.FAILED, "WORKLOAD_ERROR"
            session.results.append({"id": item.id, "status": status.value, "reason": reason,
                                    "elapsed_seconds": time.monotonic() - started,
                                    "measurements": measurements if status is Status.COMPLETE else {}})
            session.save()
        if session.state == "RUNNING":
            session.state = ("PARTIAL" if session.inventory_state != "COMPLETE" or any(
                row["status"] != Status.COMPLETE.value for row in session.results) else "COMPLETE")
        session.save()
        return session

    @staticmethod
    def _record_skips(session, workloads, reason):
        session.results.extend({"id": item.id, "status": Status.SKIPPED.value, "reason": reason,
                                "elapsed_seconds": 0.0, "measurements": {}}
                               for item in workloads)
