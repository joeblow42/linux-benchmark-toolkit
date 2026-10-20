"""Bounded, non-shell subprocess probes with normalized collection statuses."""
from dataclasses import dataclass
import os
import shutil
import subprocess
from typing import Callable, Optional, Sequence, Tuple

from .core import CollectionStatus


@dataclass(frozen=True)
class ProbeResult:
    status: CollectionStatus
    command: Tuple[str, ...]
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    reason: str = ""

    def provenance(self) -> dict:
        """Stable tool-and-status metadata; no raw diagnostic data by default."""
        return {
            "tool": self.command[0] if self.command else "",
            "status": self.status.value,
            "exit_code": self.exit_code,
            "reason": self.reason,
        }


def run_probe(command: Sequence[str], *, timeout: float = 5,
              max_stdout: int = 32768, max_stderr: int = 2048,
              which: Callable[[str], Optional[str]] = shutil.which,
              runner: Callable = subprocess.run) -> ProbeResult:
    """Execute a known argument vector without a shell or automatic elevation.

    Callers must use fixed/trusted command arguments; capture is intentionally
    bounded in the returned result, and callers must redact before persistence.
    """
    if not command or any(not isinstance(arg, str) or not arg for arg in command):
        raise ValueError("command must be a nonempty list of nonempty strings")
    if timeout <= 0 or max_stdout < 0 or max_stderr < 0:
        raise ValueError("invalid probe limits")
    args = tuple(command)
    if which(args[0]) is None:
        return ProbeResult(CollectionStatus.TOOL_MISSING, args, reason="tool not installed")
    try:
        result = runner(
            list(args), capture_output=True, text=True, timeout=timeout,
            check=False, env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(CollectionStatus.FAILED, args, reason="timeout")
    except PermissionError:
        return ProbeResult(CollectionStatus.PERMISSION_DENIED, args, reason="permission denied")
    except OSError as exc:
        return ProbeResult(CollectionStatus.FAILED, args, reason=type(exc).__name__)
    out = (result.stdout or "")[:max_stdout]
    err = (result.stderr or "")[:max_stderr]
    if result.returncode == 0:
        status, reason = CollectionStatus.COMPLETE, ""
    elif result.returncode in (126, 13) or "permission denied" in err.lower():
        status, reason = CollectionStatus.PERMISSION_DENIED, "permission denied"
    else:
        status, reason = CollectionStatus.FAILED, "nonzero exit"
    return ProbeResult(status, args, result.returncode, out, err, reason)
