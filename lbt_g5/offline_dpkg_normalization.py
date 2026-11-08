"""Pure bounded parser for sealed SRC-28 dpkg-query -W local database lines.

The pinned G5-03 adapter reads local package database and emits
Package<TAB>Version<LF>. Package names and versions are only source-reported
metadata; without dpkg status fields they do not prove installed state,
driver initialization, codec usability or working configurations.

Do not collapse duplicate package names: the approved Package display field
may omit an architecture qualifier for distinct database entries.
"""
import re

MAX_BYTES=8*1024*1024
MAX_ROWS=100000
MAX_LINE=2048
MAX_NAME=256
MAX_VERSION=512
_NAME=re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?\Z")
_VERSION=re.compile(r"[A-Za-z0-9.+:~\-]*\Z")

class OfflineDpkgParseError(ValueError):
    """Malformed or unbounded package/version records from sealed stdout."""

def parse_offline_dpkg(raw):
    if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES or not raw.endswith(b"\n"):
        raise OfflineDpkgParseError("DPKG_INVALID_INPUT_BOUNDARY_OR_SIZE")
    try:
        source=raw.decode("utf-8","strict")
    except UnicodeDecodeError as exc:
        raise OfflineDpkgParseError("DPKG_INVALID_UTF8") from exc
    if "\x00" in source or "\r" in source:
        raise OfflineDpkgParseError("DPKG_FORBIDDEN_CONTROL_BYTES")
    rows=source[:-1].split("\n")
    if rows==[""]:
        rows=[]
    if len(rows)>MAX_ROWS:
        raise OfflineDpkgParseError("DPKG_RECORD_COUNT_LIMIT")
    records=[]
    for row in rows:
        if (len(row)>MAX_LINE or row.count("\t")!=1
                or any(ord(c)<32 and c!="\t" for c in row)):
            raise OfflineDpkgParseError("DPKG_ROW_DELIMITER_OR_SIZE")
        package,version=row.split("\t",1)
        if (not package or len(package)>MAX_NAME
                or _NAME.fullmatch(package) is None):
            raise OfflineDpkgParseError("DPKG_PACKAGE_NAME_INVALID")
        if len(version)>MAX_VERSION or _VERSION.fullmatch(version) is None:
            raise OfflineDpkgParseError("DPKG_VERSION_INVALID")
        records.append({"package":package,"reported_version":version})
    return records
