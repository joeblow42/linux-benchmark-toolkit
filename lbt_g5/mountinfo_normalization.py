"""Pure, bounded decoding of an already-sealed SRC-14 Linux mountinfo file.

Source grammar: Linux kernel proc(5) mountinfo. No filesystem access,
mountpoint resolution, cross-record topology inference, command execution,
device access, or filesystem health/writeability inference.
"""
import re

MAX_MOUNTINFO_BYTES = 1024 * 1024
MAX_MOUNTINFO_RECORDS = 4096
MAX_MOUNTINFO_LINE = 8192
MAX_MOUNTINFO_TOKEN = 4096
MAX_MOUNTINFO_OPTIONAL_FIELDS = 64
MAX_U64 = (1 << 64) - 1
MAX_U32 = (1 << 32) - 1
_OCTAL = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
_ESCAPE = re.compile(r"\\([0-7]{3})")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
_TYPE = re.compile(r"[A-Za-z0-9_.+:-]{1,128}\Z")
_OPTIONAL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?::[^\s:][^\s]*)?\Z")


class MountinfoParseError(ValueError):
    """Invalid or unclassifiable mountinfo: retain original byte evidence."""


def _unsigned(raw, label, maximum=MAX_U64, *, positive=False):
    if type(raw) is not str or not _DECIMAL.fullmatch(raw):
        raise MountinfoParseError("MOUNTINFO_BAD_" + label)
    val = int(raw)
    if val > maximum or (positive and val == 0):
        raise MountinfoParseError("MOUNTINFO_OUT_OF_RANGE_" + label)
    return val


def _decoded_path(raw, *, absolute=False):
    if type(raw) is not str or not raw or len(raw) > MAX_MOUNTINFO_TOKEN:
        raise MountinfoParseError("MOUNTINFO_INVALID_PATH_FIELD")
    pos = 0
    out = []
    for match in _ESCAPE.finditer(raw):
        if "\\" in raw[pos:match.start()]:
            raise MountinfoParseError("MOUNTINFO_INVALID_ESCAPE")
        code = match.group(1)
        if code not in _OCTAL:
            raise MountinfoParseError("MOUNTINFO_UNKNOWN_ESCAPE")
        out.append(raw[pos:match.start()])
        out.append(_OCTAL[code])
        pos = match.end()
    if "\\" in raw[pos:]:
        raise MountinfoParseError("MOUNTINFO_INVALID_ESCAPE")
    out.append(raw[pos:])
    result = "".join(out)
    if (not result or "\x00" in result
            or (absolute and not result.startswith("/"))):
        raise MountinfoParseError("MOUNTINFO_INVALID_PATH")
    return result


def _options(raw, kind):
    # Preserve the exact option string, not a claim that the file system
    # possesses any independently verified mode or property.
    if (not raw or len(raw) > MAX_MOUNTINFO_TOKEN
            or any(not item for item in raw.split(","))):
        raise MountinfoParseError("MOUNTINFO_INVALID_" + kind)
    return raw


def parse_mountinfo(raw):
    """Return an immutable tuple of opaque, ordered Linux mount records."""
    if type(raw) is not bytes or len(raw) > MAX_MOUNTINFO_BYTES:
        raise MountinfoParseError("MOUNTINFO_INPUT_TYPE_OR_BOUND")
    if not raw or not raw.endswith(b"\n"):
        raise MountinfoParseError("MOUNTINFO_MISSING_FINAL_RECORD_BOUNDARY")
    try:
        content = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise MountinfoParseError("MOUNTINFO_NON_UTF8") from exc
    if ("\x00" in content or "\r" in content or "\t" in content
            or any(0 < ord(x) < 32 and x != "\n" for x in content)):
        raise MountinfoParseError("MOUNTINFO_CONTROL_BYTES")
    lines = content[:-1].split("\n")
    if len(lines) > MAX_MOUNTINFO_RECORDS:
        raise MountinfoParseError("MOUNTINFO_TOO_MANY_RECORDS")
    records = []
    mount_ids = set()
    for line in lines:
        if not line or len(line) > MAX_MOUNTINFO_LINE:
            raise MountinfoParseError("MOUNTINFO_EMPTY_OR_EXCESSIVE_LINE")
        parts = line.split()
        if len(parts) < 10:
            raise MountinfoParseError("MOUNTINFO_TOO_FEW_FIELDS")
        if len(parts) > 6 + MAX_MOUNTINFO_OPTIONAL_FIELDS + 4:
            raise MountinfoParseError("MOUNTINFO_EXCESSIVE_FIELDS")
        separators = [i for i, value in enumerate(parts) if value == "-"]
        if len(separators) != 1 or separators[0] < 6 or len(parts)-separators[0] != 4:
            raise MountinfoParseError("MOUNTINFO_INVALID_FIELD_SEPARATOR")
        sep = separators[0]
        if any(len(s) > MAX_MOUNTINFO_TOKEN for s in parts):
            raise MountinfoParseError("MOUNTINFO_EXCESSIVE_TOKEN")
        mid = _unsigned(parts[0], "MOUNT_ID", positive=True)
        parent = _unsigned(parts[1], "PARENT_ID")
        if mid in mount_ids:
            raise MountinfoParseError("MOUNTINFO_DUPLICATE_MOUNT_ID")
        mount_ids.add(mid)
        device = parts[2].split(":")
        if len(device) != 2:
            raise MountinfoParseError("MOUNTINFO_BAD_MAJOR_MINOR")
        major = _unsigned(device[0], "DEVICE_MAJOR", MAX_U32)
        minor = _unsigned(device[1], "DEVICE_MINOR", MAX_U32)
        root = _decoded_path(parts[3], absolute=True)
        point = _decoded_path(parts[4], absolute=True)
        per_mount = _options(parts[5], "MOUNT_OPTIONS")
        optional = parts[6:sep]
        if any(not _OPTIONAL.fullmatch(x) for x in optional):
            raise MountinfoParseError("MOUNTINFO_INVALID_OPTIONAL_FIELD")
        fs_type, mount_source, super_options = parts[sep+1:]
        if not _TYPE.fullmatch(fs_type):
            raise MountinfoParseError("MOUNTINFO_INVALID_FILESYSTEM_TYPE")
        source = _decoded_path(mount_source)
        super_options = _options(super_options, "SUPER_OPTIONS")
        records.append({
            "mount_id": mid, "parent_id": parent,
            "major": major, "minor": minor,
            "root": root, "mount_point": point,
            "mount_options": per_mount,
            "optional_fields": list(optional),
            "filesystem_type": fs_type,
            "mount_source": source,
            "super_options": super_options,
        })
    if not records:
        raise MountinfoParseError("MOUNTINFO_EMPTY_RECORD_SET")
    return tuple(records)
