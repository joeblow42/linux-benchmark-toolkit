"""G5-04 CP-03 bounded pure Linux source normalization.

Only bytes ALREADY SEALED by IC-02 enter this module. There are no filesystem,
subprocess, device, network, sudo or import-time probes. Parser availability is
explicit: an unregistered source cannot be called successfully parsed.
An invoked parser that raises SourceParseError has attributable parser-error
evidence; a source with no parser has NOT failed parsing.
"""
from dataclasses import dataclass
import math
import re
import shlex


MAX_PARSER_BYTES = 1024 * 1024
MAX_FIELDS = 4096
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_MEM_LINE = re.compile(r"([A-Za-z_][A-Za-z0-9_()]*)\s*:\s*([0-9]+)(?:\s+(kB))?\s*\Z")
_PRESSURE_PARTS = {"some", "full"}
_PRESSURE_METRICS = {"avg10", "avg60", "avg300", "total"}


class SourceParseError(ValueError):
    """A real attempted parser failure with a bounded, source-local reason."""


@dataclass(frozen=True)
class ParsedDatum:
    datum_path: str
    observed_value: object
    normalized_value: object
    value_type: str
    unit: str | None = None


@dataclass(frozen=True)
class ParseResult:
    parser_id: str
    values: tuple[ParsedDatum, ...]


def _text(raw):
    if type(raw) is not bytes or len(raw) > MAX_PARSER_BYTES:
        raise SourceParseError("PARSER_INPUT_TYPE_OR_BOUND")
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SourceParseError("PARSER_NON_UTF8_INPUT") from exc


def _parse_os_release(raw):
    result = []
    seen = set()
    for line in _text(raw).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SourceParseError("OS_RELEASE_MALFORMED_ASSIGNMENT")
        key, value = line.split("=", 1)
        if not _KEY.fullmatch(key) or key in seen:
            raise SourceParseError("OS_RELEASE_INVALID_OR_DUPLICATE_KEY")
        seen.add(key)
        try:
            words = shlex.split(value, comments=False, posix=True)
        except ValueError as exc:
            raise SourceParseError("OS_RELEASE_INVALID_QUOTING") from exc
        if len(words) != 1:
            raise SourceParseError("OS_RELEASE_INVALID_VALUE")
        result.append(ParsedDatum("os.release." + key, value,
                                  words[0], "STRING"))
        if len(result) > MAX_FIELDS:
            raise SourceParseError("OS_RELEASE_EXCESSIVE_KEYS")
    if "ID" not in seen:
        raise SourceParseError("OS_RELEASE_MISSING_ID")
    return ParseResult("linux-os-release-v1", tuple(result))


def _parse_meminfo(raw):
    result = []
    keys = set()
    for line in _text(raw).splitlines():
        match = _MEM_LINE.fullmatch(line)
        if not match:
            raise SourceParseError("MEMINFO_MALFORMED_LINE")
        key, number, unit = match.groups()
        if key in keys:
            raise SourceParseError("MEMINFO_DUPLICATE_KEY")
        keys.add(key)
        raw_count = int(number)
        result.append(ParsedDatum(
            "memory.meminfo." + key, number if unit is None else number + " kB",
            raw_count * 1024 if unit == "kB" else raw_count, "INTEGER",
            "bytes" if unit == "kB" else "count"))
        if len(result) > MAX_FIELDS:
            raise SourceParseError("MEMINFO_EXCESSIVE_KEYS")
    if "MemTotal" not in keys:
        raise SourceParseError("MEMINFO_MISSING_MEMTOTAL")
    return ParseResult("linux-proc-meminfo-v1", tuple(result))


def _parse_swaps(raw):
    lines = _text(raw).splitlines()
    if not lines or lines[0].split() != ["Filename", "Type", "Size", "Used", "Priority"]:
        raise SourceParseError("SWAPS_INVALID_HEADER")
    entries = []
    for line in lines[1:]:
        if not line.strip():
            continue
        cells = line.split()
        if len(cells) != 5:
            raise SourceParseError("SWAPS_INVALID_ENTRY")
        path, kind, size, used, priority = cells
        try:
            size_kib, used_kib, priority = int(size), int(used), int(priority)
        except ValueError as exc:
            raise SourceParseError("SWAPS_NONNUMERIC_ENTRY") from exc
        if size_kib < 0 or used_kib < 0 or used_kib > size_kib:
            raise SourceParseError("SWAPS_INVALID_EXTENT")
        entries.append({
            "name": path, "type": kind,
            "size_bytes": size_kib * 1024,
            "used_bytes": used_kib * 1024, "priority": priority,
        })
        if len(entries) > MAX_FIELDS:
            raise SourceParseError("SWAPS_EXCESSIVE_ENTRIES")
    return ParseResult("linux-proc-swaps-v1", (
        ParsedDatum("memory.swap.entries", "SWAPS_TABLE", entries, "ARRAY"),
    ))


def _parse_memory_pressure(raw):
    fields = []
    sections = set()
    for line in _text(raw).splitlines():
        pieces = line.split()
        if not pieces:
            continue
        section = pieces[0]
        if section not in _PRESSURE_PARTS or section in sections:
            raise SourceParseError("PRESSURE_INVALID_SECTION")
        sections.add(section)
        seen = set()
        for piece in pieces[1:]:
            if piece.count("=") != 1:
                raise SourceParseError("PRESSURE_MALFORMED_METRIC")
            name, value = piece.split("=", 1)
            if name not in _PRESSURE_METRICS or name in seen:
                raise SourceParseError("PRESSURE_INVALID_METRIC")
            seen.add(name)
            try:
                normalized = int(value) if name == "total" else float(value)
            except ValueError as exc:
                raise SourceParseError("PRESSURE_NONNUMERIC_METRIC") from exc
            if (normalized < 0 or not math.isfinite(normalized)
                    or (name != "total" and normalized > 100)):
                raise SourceParseError("PRESSURE_OUT_OF_RANGE")
            fields.append(ParsedDatum(
                "memory.pressure." + section + "." + name,
                value, normalized, "INTEGER" if name == "total" else "NUMBER",
                "microseconds" if name == "total" else "percent"))
        if seen != _PRESSURE_METRICS:
            raise SourceParseError("PRESSURE_INCOMPLETE_METRICS")
    if "some" not in sections:
        raise SourceParseError("PRESSURE_MISSING_SOME")
    return ParseResult("linux-psi-memory-v1", tuple(fields))


# Intentional bounded list. Unsupported source families are not normalized
# by interpreting raw bytes as arbitrary meaningful inventory fields.
PARSERS = {
    "SRC-02": _parse_os_release,
    "SRC-08": _parse_meminfo,
    "SRC-09": _parse_swaps,
    "SRC-10": _parse_memory_pressure,
}


def parser_available(source_id):
    return source_id in PARSERS


def normalize_sealed_source(source_id, raw):
    """Return None if no parser exists; ParseResult or attributed exception otherwise."""
    parser = PARSERS.get(source_id)
    if parser is None:
        return None
    return parser(raw)
