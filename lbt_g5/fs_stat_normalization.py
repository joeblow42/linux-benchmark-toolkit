"""Pure bounded parser for sealed SRC-15 D1 FS_STAT worker stdout.

The worker's Python os.statvfs result is serialized as one fixed-schema JSON
line. This parser never reads a filesystem, resolves a mount, executes a
command, or infers filesystem health or physical storage classification.
"""
import json

MAX_FSSTAT_BYTES = 1024 * 1024
MAX_U64 = (1 << 64) - 1
NUMERIC_FIELDS = frozenset((
    "fragment_size", "block_size", "blocks", "free_blocks",
    "available_blocks", "files", "free_files"
))
ALL_FIELDS = NUMERIC_FIELDS | {"mount"}

class FSStatParseError(ValueError):
    """A specific malformed/inconsistent original FS_STAT stdout."""

def _unique_fields(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise FSStatParseError("FSSTAT_DUPLICATE_JSON_KEY")
        result[k] = v
    return result

def _reject_constant(_):
    raise FSStatParseError("FSSTAT_NONFINITE_JSON_NUMBER")

def parse_fs_stat_stdout(raw, *, source_path):
    """Return fixed-schema original snapshot, with checked mount attribution."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FSSTAT_BYTES:
        raise FSStatParseError("FSSTAT_INVALID_INPUT_OR_BOUND")
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw or b"\x00" in raw:
        raise FSStatParseError("FSSTAT_INVALID_WORKER_RECORD_BOUNDARY")
    if (type(source_path) is not str or not source_path.startswith("/")
            or len(source_path) > 4096 or "\x00" in source_path
            or any(0xD800 <= ord(ch) <= 0xDFFF for ch in source_path)):
        raise FSStatParseError("FSSTAT_UNVERIFIED_MOUNT_PATH")
    try:
        decoded = raw.decode("utf-8", "strict")
        data = json.loads(decoded, object_pairs_hook=_unique_fields,
                          parse_constant=_reject_constant)
    except FSStatParseError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise FSStatParseError("FSSTAT_INVALID_JSON") from exc
    if type(data) is not dict or set(data) != ALL_FIELDS:
        raise FSStatParseError("FSSTAT_INVALID_WORKER_FIELDS")
    if type(data["mount"]) is not str or data["mount"] != source_path:
        raise FSStatParseError("FSSTAT_MOUNT_AND_RECEIPT_DISAGREE")
    for key in NUMERIC_FIELDS:
        value = data[key]
        if type(value) is not int or value < 0 or value > MAX_U64:
            raise FSStatParseError("FSSTAT_INVALID_UNSIGNED_COUNTER_" + key.upper())
    # These are the worker's original reported values; calculate neither
    # purported free capacity nor device/health conclusions at parse time.
    return data
