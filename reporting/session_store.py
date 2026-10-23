"""IC-03: explicit, private, single-file session persistence.

This writer is intentionally not connected to the Phase 1 CLI. No session
directories are created automatically and no legacy artifacts are migrated.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

from .session_schema import SessionSchemaError, SCHEMA_VERSION, validate_system_document

_REQUIRED_FINAL = frozenset((
    "system.json", "benchmarks.json", "assessments.json",
    "discovery.csv", "report.html",
))
_ALLOWED = _REQUIRED_FINAL
_STATES = frozenset(("COMPLETE", "INCOMPLETE", "FAILED", "INTERRUPTED"))


class SessionPersistenceError(RuntimeError):
    """Explicit structured persistence failure with no sensitive path exposure."""

    def __init__(self, category: str, message: str):
        self.category = category
        super().__init__(message)


def _directory(session_dir) -> Path:
    try:
        path = Path(session_dir)
    except (TypeError, ValueError) as exc:
        raise SessionPersistenceError("VALIDATION_ERROR",
                                      "invalid session directory") from exc
    if path.is_symlink() or not path.is_dir() or not path.name.startswith("session_"):
        raise SessionPersistenceError("VALIDATION_ERROR",
                                      "existing non-symlink session directory required")
    return path


def _existing_target_is_safe(target: Path, session_id: str) -> None:
    if target.is_symlink():
        raise SessionPersistenceError("VALIDATION_ERROR",
                                      "refuse symbolic-link canonical target")
    if target.exists():
        try:
            obj = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise SessionPersistenceError("VALIDATION_ERROR",
                                          "existing canonical file cannot be verified") from exc
        if not isinstance(obj, dict) or obj.get("schema_version") != SCHEMA_VERSION:
            raise SessionPersistenceError("LEGACY_SESSION_PROTECTED",
                                          "refuse replacement of non-v2 system.json")
        if obj.get("session_id") != session_id:
            raise SessionPersistenceError("VALIDATION_ERROR",
                                          "existing session identity disagrees")


def _sync_directory(directory: Path) -> None:
    """Best effort metadata durability; individual-file atomicity is primary."""
    fd = None
    try:
        fd = os.open(str(directory), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        os.fsync(fd)
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)


def write_system_document(session_dir, document: dict) -> None:
    """Commit a validated v2 system.json with mode 0600 or raise.

    Writes no other artifact. Existing Phase 1 system.json is never replaced.
    """
    directory = _directory(session_dir)
    try:
        validate_system_document(document, session_id=directory.name)
        body = (json.dumps(document, sort_keys=True, ensure_ascii=False,
                           allow_nan=False, indent=2) + "\n").encode("utf-8")
    except SessionSchemaError as exc:
        category = ("PRIVACY_REJECTION" if "private" in str(exc)
                    or "unapproved" in str(exc) else "VALIDATION_ERROR")
        raise SessionPersistenceError(category,
                                      "canonical session validation failed") from exc
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SessionPersistenceError("VALIDATION_ERROR",
                                      "canonical serialization failed") from exc
    target = directory / "system.json"
    _existing_target_is_safe(target, directory.name)

    temp_name = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=".system-json-", suffix=".tmp",
                                        dir=str(directory))
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        # Recheck a legacy target before replacing; the normal CLI must
        # never have its 1.0.0 file silently upgraded.
        _existing_target_is_safe(target, directory.name)
        os.replace(temp_name, target)
        temp_name = None
        _sync_directory(directory)
    except PermissionError as exc:
        raise SessionPersistenceError("PERMISSION_DENIED",
                                      "canonical file write denied") from exc
    except SessionPersistenceError:
        raise
    except OSError as exc:
        raise SessionPersistenceError("IO_FAILURE",
                                      "canonical file write failed") from exc
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def build_session_manifest(session_dir, *, state: str = "INCOMPLETE") -> dict:
    """Build, but DO NOT write, optional completion metadata.

    State COMPLETE requires all five authoritative session artifacts to
    exist; other states only hash files that actually exist. Does not
    reinterpret a legacy session without a manifest as incomplete.
    """
    directory = _directory(session_dir)
    if not isinstance(state, str) or state not in _STATES:
        raise SessionPersistenceError("VALIDATION_ERROR", "invalid manifest state")
    records = {}
    try:
        for name in sorted(_ALLOWED):
            path = directory / name
            if path.is_symlink():
                raise SessionPersistenceError("VALIDATION_ERROR",
                                              "manifest cannot hash symlink artifacts")
            if path.is_file():
                data = path.read_bytes()
                records[name] = {
                    "sha256": sha256(data).hexdigest(),
                    "bytes": len(data),
                }
        if state == "COMPLETE":
            if set(records) != _REQUIRED_FINAL or not (directory / "logs").is_dir():
                raise SessionPersistenceError("VALIDATION_ERROR",
                                              "required session outputs not finalized")
            # "COMPLETE" may only refer to a verified canonical 2.0.0 file.
            system = json.loads((directory / "system.json").read_text("utf-8"))
            validate_system_document(system, session_id=directory.name)
    except (OSError, ValueError, UnicodeError, SessionSchemaError) as exc:
        raise SessionPersistenceError("VALIDATION_ERROR",
                                      "session manifest source invalid") from exc
    return {
        "manifest_version": "1.0",
        "session_id": directory.name,
        "schema_version": SCHEMA_VERSION,
        "state": state,
        "files": records,
    }


def read_session_manifest(session_dir) -> dict | None:
    """None means no manifest (legacy-compatible), NEVER presumed COMPLETE."""
    directory = _directory(session_dir)
    path = directory / "session.manifest.json"
    if not path.exists():
        return None
    if path.is_symlink():
        raise SessionPersistenceError("VALIDATION_ERROR", "manifest symlink rejected")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise SessionPersistenceError("VALIDATION_ERROR", "manifest invalid") from exc
    if (not isinstance(doc, dict)
        or set(doc) != {"manifest_version", "session_id", "schema_version",
                       "state", "files"}
        or doc.get("session_id") != directory.name
        or doc.get("manifest_version") != "1.0"
        or doc.get("schema_version") != SCHEMA_VERSION
        or not isinstance(doc.get("state"), str)
        or doc.get("state") not in _STATES
        or not isinstance(doc.get("files"), dict)
        or not set(doc["files"]).issubset(_ALLOWED)):
        raise SessionPersistenceError("VALIDATION_ERROR", "manifest schema invalid")
    if doc["state"] == "COMPLETE":
        if set(doc["files"]) != _REQUIRED_FINAL or not (directory / "logs").is_dir():
            raise SessionPersistenceError("VALIDATION_ERROR",
                                          "manifest falsely claims completion")
    try:
        for name, info in doc["files"].items():
            if (not isinstance(info, dict)
                or set(info) != {"sha256", "bytes"}
                or type(info["bytes"]) is not int
                or info["bytes"] < 0
                or not isinstance(info["sha256"], str)
                or len(info["sha256"]) != 64
                or any(ch not in "0123456789abcdef" for ch in info["sha256"])):
                raise SessionPersistenceError("VALIDATION_ERROR",
                                              "manifest checksum record invalid")
            file = directory / name
            if file.is_symlink():
                raise SessionPersistenceError("VALIDATION_ERROR",
                                              "manifest references a symlink")
            data = file.read_bytes()
            if len(data) != info["bytes"] or sha256(data).hexdigest() != info["sha256"]:
                raise SessionPersistenceError("VALIDATION_ERROR",
                                              "manifest checksum mismatch")
        if doc["state"] == "COMPLETE":
            validate_system_document(
                json.loads((directory / "system.json").read_text(encoding="utf-8")),
                session_id=directory.name)
    except (OSError, UnicodeError, ValueError, SessionSchemaError) as exc:
        raise SessionPersistenceError("VALIDATION_ERROR",
                                      "manifest verification failed") from exc
    return doc
