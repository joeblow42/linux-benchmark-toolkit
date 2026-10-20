"""Read-only filesystem readers used by hardware collectors."""
from pathlib import Path

from .core import CollectionStatus


def read_text(path, *, max_bytes=65536):
    """Return (text, status) without allowing unbounded reads."""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return None, CollectionStatus.FAILED
        return raw.decode("utf-8", errors="replace"), CollectionStatus.COMPLETE
    except PermissionError:
        return None, CollectionStatus.PERMISSION_DENIED
    except FileNotFoundError:
        return None, CollectionStatus.UNAVAILABLE
    except OSError:
        return None, CollectionStatus.FAILED


def kv_lines(text, separator=":"):
    output = {}
    for line in text.splitlines():
        if separator in line:
            key, _, value = line.partition(separator)
            key = key.strip()
            if key:
                output[key] = value.strip().strip('"')
    return output


def integer(text):
    try:
        return int(text.strip())
    except (ValueError, AttributeError, TypeError):
        return None
