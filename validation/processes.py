"""Bounded subprocess execution with process-group cleanup on POSIX Linux."""
import os
import signal
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool


def run_bounded(args: list[str], cwd: str, timeout: float) -> ProcessResult:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    proc = subprocess.Popen(
        args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )
    try:
        output, errors = proc.communicate(timeout=timeout)
        return ProcessResult(proc.returncode, output, errors, False)
    except subprocess.TimeoutExpired:
        # Killing the entire process group prevents orphaned shell/benchmark
        # children. The worker and all of its descendants belong to this group
        # unless a child deliberately detaches itself.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, errors = proc.communicate()
        return ProcessResult(proc.returncode, output, errors, True)
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        raise
