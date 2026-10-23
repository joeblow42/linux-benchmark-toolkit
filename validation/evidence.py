"""Local-only diagnostic artifacts, separate from portable redacted reports.

Logs may contain host identifiers. Directory and file permissions are private,
and report evidence refers to an opaque case ID, not a personal filesystem path.
"""
import os
from pathlib import Path
import re
import tempfile

_ID = re.compile(r"^VAL-[A-Z0-9]+(?:-[A-Z0-9]+)*$")


def private_diagnostic(results_dir: Path, case_id: str, detail: str) -> str:
    """Persist detail privately; failure to write must not hide test failure."""
    if not _ID.fullmatch(case_id):
        return ""
    try:
        folder = Path(results_dir) / "logs"
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder.chmod(0o700)
        target = folder / (case_id + ".log")
        fd, temporary = tempfile.mkstemp(prefix=".diagnostic-", dir=folder)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(detail[:250000])
                if len(detail) > 250000:
                    stream.write("\n[diagnostic truncated]\n")
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return "log:" + case_id
    except OSError:
        return ""
