"""Pure SRC-14 /proc/self/mountinfo parser for hash-checked D0 original bytes.

Linux kernel proc/filesystems contract: six fields, optional opaque tags, "-"
separator, and exactly three trailing fields. This is NOT mount reconciliation,
filesystem health inference, realpath resolution, or live namespace probing.
"""
import re

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 4096
MAX_LINE = 16384
MAX_TOKEN = 8192
_U64 = 18446744073709551615
_U32 = 4294967295
_ESCAPE = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
_UNESCAPE_PATTERN = re.compile(r"\\([0-7]{3})")
_NUMERIC = re.compile(r"[0-9]{1,20}\Z")
_DEVNO = re.compile(r"([0-9]{1,10}):([0-9]{1,10})\Z")


class MountinfoParseError(ValueError):
    """Malformed, ambiguous, unbounded or truncated mountinfo original."""


def _number(value, limit):
    if not _NUMERIC.fullmatch(value):
        raise MountinfoParseError("MOUNTINFO_INVALID_DECIMAL")
    n = int(value)
    if n > limit:
        raise MountinfoParseError("MOUNTINFO_NUMERIC_OVERFLOW")
    return n


def _unescape_path(raw):
    """Translate precisely the documented Linux mountinfo escape repertoire.

    Encoded \040 followed by an unescaped '0' is valid and means ' 0'.
    Do not use generic octal escapes or interpret the result as a host path.
    """
    if len(raw) > MAX_TOKEN:
        raise MountinfoParseError("MOUNTINFO_PATH_BOUND")
    result = []
    i = 0
    while i < len(raw):
        if raw[i] != "\\":
            result.append(raw[i])
            i += 1
            continue
        token = raw[i + 1:i + 4]
        if len(token) != 3 or token not in _ESCAPE:
            raise MountinfoParseError("MOUNTINFO_UNKNOWN_ESCAPE")
        result.append(_ESCAPE[token])
        i += 4
    result = "".join(result)
    if not result.startswith("/"):
        raise MountinfoParseError("MOUNTINFO_NONABSOLUTE_MOUNT_PATH")
    if any(ord(ch) == 0 for ch in result):
        raise MountinfoParseError("MOUNTINFO_INVALID_PATH_CONTROL")
    return result


def parse_mountinfo(raw):
    """Return ordered immutable-data records from sealed mountinfo bytes only."""
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise MountinfoParseError("MOUNTINFO_INPUT_TYPE_OR_BOUND")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise MountinfoParseError("MOUNTINFO_NON_UTF8") from exc
    if not text or not text.endswith("\n"):
        raise MountinfoParseError("MOUNTINFO_EMPTY_OR_TRUNCATED")
    if any((ord(c) < 32 and c != "\n") or ord(c) == 127 for c in text):
        raise MountinfoParseError("MOUNTINFO_UNESCAPED_CONTROL")
    lines=text[:-1].split("\n")
    if len(lines) > MAX_RECORDS:
        raise MountinfoParseError("MOUNTINFO_EXCESSIVE_RECORDS")
    seen_ids=set()
    output=[]
    for line in lines:
        if not line or len(line) > MAX_LINE:
            raise MountinfoParseError("MOUNTINFO_EMPTY_OR_EXCESSIVE_LINE")
        tokens=line.split(" ")
        if any(not token or len(token) > MAX_TOKEN for token in tokens):
            raise MountinfoParseError("MOUNTINFO_EMPTY_OR_EXCESSIVE_TOKEN")
        if len(tokens) < 10 or tokens.count("-") != 1:
            raise MountinfoParseError("MOUNTINFO_MISSING_OR_DUPLICATE_SEPARATOR")
        separator=tokens.index("-")
        if separator < 6 or len(tokens)-separator != 4:
            raise MountinfoParseError("MOUNTINFO_INVALID_FIELD_COUNT")
        mount_id = _number(tokens[0], _U64)
        parent_id = _number(tokens[1], _U64)
        dev = _DEVNO.fullmatch(tokens[2])
        if dev is None:
            raise MountinfoParseError("MOUNTINFO_INVALID_MAJOR_MINOR")
        major,minor=(_number(dev.group(1),_U32),_number(dev.group(2),_U32))
        if mount_id in seen_ids:
            raise MountinfoParseError("MOUNTINFO_DUPLICATE_ID")
        seen_ids.add(mount_id)
        root = _unescape_path(tokens[3])
        point = _unescape_path(tokens[4])
        mount_options=tokens[5]
        optional=tokens[6:separator]
        fstype,source,superopts=tokens[separator+1:]
        # Values may contain private path components or vendor-specific tags;
        # preserve rather than classify them or guess filesystem health.
        output.append({
            "mount_id":mount_id,
            "parent_id":parent_id,
            "major":major,
            "minor":minor,
            "root":root,
            "mount_point":point,
            "mount_options":mount_options,
            "optional_fields":optional,
            "filesystem_type":fstype,
            "mount_source":_unescape_source(source),
            "super_options":superopts,
        })
    return output


def _unescape_source(source):
    """The source is filesystem-specific; decode documented escapes only."""
    if "\\" not in source:
        return source
    result=[]
    i=0
    while i<len(source):
        if source[i] != "\\":
            result.append(source[i]); i+=1
            continue
        token=source[i+1:i+4]
        if len(token) != 3 or token not in _ESCAPE:
            raise MountinfoParseError("MOUNTINFO_UNKNOWN_SOURCE_ESCAPE")
        result.append(_ESCAPE[token]); i+=4
    return "".join(result)
