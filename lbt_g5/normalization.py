"""G5-04 CP-03 bounded pure Linux source normalization.

Only bytes ALREADY SEALED by IC-02 enter this module. There are no filesystem,
subprocess, device, network, sudo or import-time probes. Parser availability is
explicit: an unregistered source cannot be called successfully parsed.
An invoked parser that raises SourceParseError has attributable parser-error
evidence; a source with no parser has NOT failed parsing.
"""
from dataclasses import dataclass
import math
import json
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
        if len(number) > 24:
            raise SourceParseError("MEMINFO_NUMERIC_BOUND")
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
        if any(len(value.lstrip("+-")) > 24
               for value in (size, used, priority)):
            raise SourceParseError("SWAPS_NUMERIC_BOUND")
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
            if len(value) > 48:
                raise SourceParseError("PRESSURE_NUMERIC_BOUND")
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



# CP-03 increment 02: deterministic, sealed D0 platform and tool snapshots.
# Parsers use no host access; these formats are emitted by passive_worker.py.
_TOOLS = frozenset(("lscpu", "lsblk", "lspci", "ip", "smartctl", "nvme",
                    "vainfo", "python3", "dpkg-query", "rpm"))
_PRINTABLE = re.compile(r"[\x20-\x7e]{1,256}\Z")


def _strict_json_object(raw, source):
    def unique_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise SourceParseError(source + "_DUPLICATE_JSON_KEY")
            obj[key] = value
        return obj
    try:
        value = json.loads(_text(raw), object_pairs_hook=unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               SourceParseError(source + "_NONFINITE_JSON")))
    except (ValueError, TypeError) as exc:
        if isinstance(exc, SourceParseError):
            raise
        raise SourceParseError(source + "_INVALID_JSON") from exc
    if type(value) is not dict:
        raise SourceParseError(source + "_EXPECTED_OBJECT")
    return value


def _parse_platform_api(raw):
    data = _strict_json_object(raw, "PLATFORM")
    if set(data) != {"system", "machine", "release"}:
        raise SourceParseError("PLATFORM_UNEXPECTED_FIELDS")
    if (any(type(v) is not str or not _PRINTABLE.fullmatch(v)
            for v in data.values()) or data["system"] != "Linux"):
        raise SourceParseError("PLATFORM_INVALID_LINUX_IDENTITY")
    return ParseResult("linux-platform-api-v1", tuple(
        ParsedDatum("os.kernel." + key, data[key], data[key], "STRING")
        for key in ("system", "machine", "release")))


def _parse_efi_presence(raw):
    if raw not in (b"present\n", b"absent\n"):
        raise SourceParseError("EFI_INVALID_PRESENCE_MARKER")
    marker = raw == b"present\n"
    return ParseResult("linux-efi-presence-v1", (
        ParsedDatum("firmware.efi.present", "present" if marker else "absent",
                    marker, "BOOLEAN"),
    ))


def _parse_tool_resolver(raw):
    item = _strict_json_object(raw, "TOOL")
    if set(item) != {"tool", "path"}:
        raise SourceParseError("TOOL_UNEXPECTED_FIELDS")
    name, path = item["tool"], item["path"]
    if type(name) is not str or name not in _TOOLS:
        raise SourceParseError("TOOL_UNKNOWN_NAME")
    if path is not None:
        # The G5-02 worker calls which() against a fixed PATH. Reject
        # traversal or nested paths even when an allowed prefix matches.
        roots = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
        if type(path) is not str or path not in tuple(
                directory + "/" + name for directory in roots):
            raise SourceParseError("TOOL_INVALID_RESOLVED_PATH")
    return ParseResult("linux-tool-resolver-v1", (
        ParsedDatum("tools.resolution." + name, item,
                    {"available": path is not None, "resolved_path": path},
                    "OBJECT"),
    ))



# CP-03 increment 03: typed CPU/optical metadata from sealed static files.
_CPU_KEY = re.compile(r"[A-Za-z0-9_ .(),/#-]{1,96}\Z")
_DEVICE_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")


def _parse_cpuinfo(raw):
    processors, current = [], {}
    record_fields = 0

    def flush():
        if not current:
            return
        if "processor" not in current:
            raise SourceParseError("CPUINFO_MISSING_PROCESSOR_ID")
        ident = current["processor"]
        if not ident.isdecimal() or len(ident) > 8 or int(ident) > 1048575:
            raise SourceParseError("CPUINFO_INVALID_PROCESSOR_ID")
        if any(p["processor"] == int(ident) for p in processors):
            raise SourceParseError("CPUINFO_DUPLICATE_PROCESSOR_ID")
        normalized = {"processor": int(ident)}
        for name, target in (
            ("vendor_id", "vendor"),
            ("model name", "model_name"),
            ("physical id", "physical_package_id"),
            ("core id", "core_id"),
            ("cpu cores", "cpu_cores"),
            ("siblings", "siblings"),
        ):
            if name not in current:
                continue
            value = current[name]
            if target in ("physical_package_id", "core_id", "cpu_cores", "siblings"):
                if not value.isdecimal() or len(value) > 8:
                    raise SourceParseError("CPUINFO_INVALID_COUNT")
                normalized[target] = int(value)
            else:
                normalized[target] = value
        if "cpu MHz" in current:
            value = current["cpu MHz"]
            if len(value) > 32:
                raise SourceParseError("CPUINFO_INVALID_FREQ")
            try:
                mhz = float(value)
            except ValueError as exc:
                raise SourceParseError("CPUINFO_INVALID_FREQ") from exc
            if not math.isfinite(mhz) or not 0 < mhz < 1e9:
                raise SourceParseError("CPUINFO_INVALID_FREQ")
            normalized["frequency_mhz"] = mhz
        if "flags" in current:
            flags = current["flags"].split()
            if len(flags) > 512:
                raise SourceParseError("CPUINFO_EXCESSIVE_FLAGS")
            normalized["flags"] = flags
        processors.append({"processor": int(ident), "original": dict(current),
                           "normalized": normalized})
        if len(processors) > 1024:
            raise SourceParseError("CPUINFO_EXCESSIVE_PROCESSORS")
        current.clear()

    for line in _text(raw).splitlines():
        if not line.strip():
            flush()
            continue
        if ":" not in line:
            raise SourceParseError("CPUINFO_MALFORMED_LINE")
        key, value = (part.strip() for part in line.split(":", 1))
        if (not _CPU_KEY.fullmatch(key) or key in current
                or len(value) > 8192 or "\x00" in value):
            raise SourceParseError("CPUINFO_INVALID_OR_DUPLICATE_FIELD")
        current[key] = value
        record_fields += 1
        if record_fields > 20000:
            raise SourceParseError("CPUINFO_EXCESSIVE_FIELDS")
    flush()
    if not processors:
        raise SourceParseError("CPUINFO_EMPTY")
    return ParseResult("linux-proc-cpuinfo-v1", tuple(
        ParsedDatum("cpu.logical_processor." + str(p["processor"]),
                    p["original"], p["normalized"], "OBJECT")
        for p in processors))


def _parse_cdrom_info(raw):
    rows = {}
    for line in _text(raw).splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            raise SourceParseError("CDROM_INFO_MALFORMED_LINE")
        key, value = (part.strip() for part in line.split(":", 1))
        if (not _CPU_KEY.fullmatch(key) or key in rows or len(value) > 8192
                or "\x00" in value):
            # Metadata keys are controlled by the Linux cdrom driver.
            raise SourceParseError("CDROM_INFO_INVALID_OR_DUPLICATE_ROW")
        rows[key] = value
        if len(rows) > 128:
            raise SourceParseError("CDROM_INFO_EXCESSIVE_ROWS")
    if "drive name" not in rows:
        raise SourceParseError("CDROM_INFO_MISSING_DRIVE_NAME_ROW")
    names = rows["drive name"].split()
    if (len(names) > 128 or len(names) != len(set(names))
            or any(not _DEVICE_NAME.fullmatch(n) for n in names)):
        raise SourceParseError("CDROM_INFO_INVALID_DRIVE_NAMES")
    drives = [{"name": n, "capabilities": {}} for n in names]
    for key, value in rows.items():
        if key in ("drive name", "CD-ROM information, Id"):
            continue
        tokens = value.split()
        if len(tokens) != len(names):
            raise SourceParseError("CDROM_INFO_COLUMN_MISMATCH")
        for drive, token in zip(drives, tokens):
            if len(token) > 32:
                raise SourceParseError("CDROM_INFO_VALUE_BOUND")
            if token.isdecimal() and len(token) <= 16:
                number = int(token)
                drive["capabilities"][key] = (
                    bool(number) if (key.startswith(("Can ", "Reports "))
                                     and number in (0, 1)) else number)
            else:
                drive["capabilities"][key] = token
    return ParseResult("linux-proc-cdrom-info-v1", (
        ParsedDatum("optical.cdrom.drives", rows,
                    {"device_count": len(drives), "drives": drives}, "OBJECT"),
    ))



# G4-07 SRC-04 exposes selected readable public DMI attributes only.
# This fixed allowlist is deliberately independent of acquired VALUE bytes.
# Cross-module contract tests must also compare it to the accepted G5-03
# worker's DMI allowlist. No dmidecode or host reads occur here.
_DMI_PREFIX = "/sys/class/dmi/id/"
_DMI_PUBLIC_FIELDS = frozenset((
    "sys_vendor", "product_name", "product_version", "product_family",
    "board_vendor", "board_name", "board_version",
    "bios_vendor", "bios_version", "bios_date",
    "chassis_type", "chassis_vendor", "chassis_version",
))


def dmi_field_from_source_path(source_path):
    """Return the exact approved SRC-04 field, never an inferred path."""
    if type(source_path) is not str or not source_path.startswith(_DMI_PREFIX):
        return None
    field = source_path[len(_DMI_PREFIX):]
    if field not in _DMI_PUBLIC_FIELDS or source_path != _DMI_PREFIX + field:
        return None
    return field


def _parse_dmi_public(raw, *, source_path):
    field = dmi_field_from_source_path(source_path)
    if field is None:
        raise SourceParseError("DMI_SOURCE_PATH_NOT_APPROVED")
    observed = _text(raw)
    # Sysfs DMI attributes are bounded single-line text with optional LF.
    # Unexpected binary/multiline content is preserved in original evidence,
    # but is not silently converted into a trusted semantic field.
    if (len(observed) > 4096 or "\x00" in observed or "\r" in observed
            or observed.count("\n") > 1
            or ("\n" in observed and not observed.endswith("\n"))):
        raise SourceParseError("DMI_INVALID_TEXT_OR_BOUND")
    return ParseResult("linux-sysfs-dmi-public-v1", (
        ParsedDatum("platform.dmi." + field, observed,
                    observed.rstrip("\n").strip(" \t"), "STRING"),
    ))



# Accepted G5-03 SRC-07 passive worker: CPU directory names are lexically
# sorted, then attributes are visited in THIS order. Do not sort by CPU index
# or alphabetize per-CPU attributes: either would misbind preserved originals.
_CPU_SYSFS_ROOT = "/sys/devices/system/cpu/"
_CPU_SYSFS_ROOT_ATTRS = ("online", "possible", "present")
_CPU_SYSFS_ITEM_ATTRS = (
    "topology/core_id", "topology/physical_package_id",
    "topology/thread_siblings_list", "topology/core_siblings_list",
    "online", "cpufreq/scaling_cur_freq", "cpufreq/cpuinfo_max_freq",
    "cpufreq/scaling_min_freq", "cpufreq/scaling_max_freq",
)
_CPU_SYSFS_CPU_NAME = re.compile(r"cpu[0-9]+\Z")
_CPU_SYSFS_INT = re.compile(r"-?[0-9]+\Z")
_CPU_SYSFS_NAT = re.compile(r"[0-9]+\Z")
_CPU_SYSFS_RANGE = re.compile(r"([0-9]+)(?:-([0-9]+))?\Z")


def cpu_sysfs_path_identity(source_path):
    """Approved SRC-07 datum, expected worker ordering key, semantic attribute.

    Returns None for unapproved or ambiguous original paths. The caller
    validates entire receipt order before dereferencing sealed original bytes.
    """
    if (type(source_path) is not str
            or not source_path.startswith(_CPU_SYSFS_ROOT)):
        return None
    relative = source_path[len(_CPU_SYSFS_ROOT):]
    if relative in _CPU_SYSFS_ROOT_ATTRS:
        return ("cpu.sysfs.global." + relative,
                (0, _CPU_SYSFS_ROOT_ATTRS.index(relative)), relative)
    parts = relative.split("/", 1)
    if len(parts) != 2 or not _CPU_SYSFS_CPU_NAME.fullmatch(parts[0]):
        return None
    name, attribute = parts
    if attribute not in _CPU_SYSFS_ITEM_ATTRS:
        return None
    return ("cpu.sysfs." + name + "." + attribute.replace("/", "."),
            (1, name, _CPU_SYSFS_ITEM_ATTRS.index(attribute)), attribute)


def _cpu_sysfs_cpu_ranges(value):
    """Parse Linux CPU-list ranges without expanding very large ranges."""
    if not value or len(value) > 4096:
        raise SourceParseError("CPU_SYSFS_CPU_LIST_EMPTY_OR_BOUND")
    ranges = []
    previous_last = -1
    for token in value.split(","):
        match = _CPU_SYSFS_RANGE.fullmatch(token)
        if match is None or len(ranges) >= 1024:
            raise SourceParseError("CPU_SYSFS_CPU_LIST_MALFORMED")
        first = int(match.group(1))
        last = int(match.group(2)) if match.group(2) is not None else first
        if first > last or first <= previous_last or last > 2147483647:
            raise SourceParseError("CPU_SYSFS_CPU_LIST_INVALID_ORDER_OR_BOUND")
        ranges.append([first, last])
        previous_last = last
    return {"ranges": ranges}


def _cpu_sysfs_integer(value, *, signed):
    if len(value) > 12 or not (_CPU_SYSFS_INT if signed else _CPU_SYSFS_NAT).fullmatch(value):
        raise SourceParseError("CPU_SYSFS_INVALID_DECIMAL")
    number = int(value)
    if signed and not (-2147483648 <= number <= 2147483647):
        raise SourceParseError("CPU_SYSFS_DECIMAL_OUT_OF_RANGE")
    if not signed and number > 1000000000:
        raise SourceParseError("CPU_SYSFS_DECIMAL_OUT_OF_RANGE")
    return number


def _parse_cpu_sysfs(raw, *, source_path):
    identity = cpu_sysfs_path_identity(source_path)
    if identity is None:
        raise SourceParseError("CPU_SYSFS_SOURCE_PATH_NOT_APPROVED")
    datum_path, _, attribute = identity
    observed = _text(raw)
    if (not observed or len(observed) > 4096
            or "\x00" in observed or "\r" in observed
            or observed.count("\n") > 1
            or ("\n" in observed and not observed.endswith("\n"))):
        raise SourceParseError("CPU_SYSFS_INVALID_SCALAR_OR_BOUND")
    value = observed.removesuffix("\n")
    if not value:
        raise SourceParseError("CPU_SYSFS_EMPTY_SCALAR")
    if attribute in ("possible", "present", "topology/thread_siblings_list",
                     "topology/core_siblings_list") or datum_path == "cpu.sysfs.global.online":
        normalized = _cpu_sysfs_cpu_ranges(value)
        value_type, unit = "OBJECT", "logical_cpu_id"
    elif attribute in ("topology/core_id", "topology/physical_package_id"):
        normalized = _cpu_sysfs_integer(value, signed=True)
        value_type, unit = "INTEGER", None
    elif attribute == "online":
        if value not in ("0", "1"):
            raise SourceParseError("CPU_SYSFS_INVALID_ONLINE_FLAG")
        normalized = value == "1"
        value_type, unit = "BOOLEAN", None
    elif attribute.startswith("cpufreq/"):
        normalized = _cpu_sysfs_integer(value, signed=False)
        value_type, unit = "INTEGER", "kHz"
    else:
        raise SourceParseError("CPU_SYSFS_UNSUPPORTED_ATTRIBUTE")
    return ParseResult("linux-sysfs-cpu-v1", (
        ParsedDatum(datum_path, observed, normalized, value_type, unit),
    ))



# SRC-12 contract derives from the G5-03 D0 passive worker. Attribute order
# is fixed by that worker, NOT sorted alphabetically. Device entry names are
# sorted lexically. No device nodes, sysfs, or private host files are opened.
_BLOCK_SYSFS_ROOT = "/sys/class/block/"
_BLOCK_SYSFS_ATTRS = (
    "size", "ro", "removable", "queue/logical_block_size",
    "queue/physical_block_size", "device/vendor", "device/model",
    "device/rev",
)
_BLOCK_SYSFS_DEVICE = re.compile(r"[A-Za-z0-9_.:-]+\Z")
_BLOCK_SYSFS_NUMBER = re.compile(r"[0-9]+\Z")


def block_sysfs_path_identity(source_path):
    """Registered SRC-12 identity and worker-order sort key, if unambiguous."""
    if (type(source_path) is not str
            or not source_path.startswith(_BLOCK_SYSFS_ROOT)):
        return None
    relative = source_path[len(_BLOCK_SYSFS_ROOT):]
    parts = relative.split("/", 1)
    if len(parts) != 2:
        return None
    name, attr = parts
    if (not name or name.startswith(".")
            or _BLOCK_SYSFS_DEVICE.fullmatch(name) is None
            or attr not in _BLOCK_SYSFS_ATTRS):
        return None
    return ("storage.block." + name + "." + attr.replace("/", "."),
            (name, _BLOCK_SYSFS_ATTRS.index(attr)), attr)


def _block_scalar_text(raw):
    observed = _text(raw)
    if (not observed or len(observed) > 4096
            or "\x00" in observed or "\r" in observed
            or observed.count("\n") > 1
            or ("\n" in observed and not observed.endswith("\n"))):
        raise SourceParseError("BLOCK_SYSFS_INVALID_SCALAR_OR_BOUND")
    return observed, observed.removesuffix("\n")


def _block_nonnegative_decimal(value):
    if (not value or len(value) > 20 or
            _BLOCK_SYSFS_NUMBER.fullmatch(value) is None):
        raise SourceParseError("BLOCK_SYSFS_INVALID_DECIMAL")
    number = int(value)
    if number > 18446744073709551615:
        raise SourceParseError("BLOCK_SYSFS_INTEGER_OUT_OF_RANGE")
    return number


def _parse_block_sysfs(raw, *, source_path):
    identity = block_sysfs_path_identity(source_path)
    if identity is None:
        raise SourceParseError("BLOCK_SYSFS_SOURCE_PATH_NOT_APPROVED")
    path, _, attr = identity
    observed, value = _block_scalar_text(raw)
    if attr in ("ro", "removable"):
        if value not in ("0", "1"):
            raise SourceParseError("BLOCK_SYSFS_INVALID_FLAG")
        normalized, value_type, unit = value == "1", "BOOLEAN", None
    elif attr == "size":
        normalized, value_type, unit = (
            _block_nonnegative_decimal(value), "INTEGER", "512-byte-sectors")
    elif attr in ("queue/logical_block_size", "queue/physical_block_size"):
        normalized = _block_nonnegative_decimal(value)
        if normalized == 0:
            raise SourceParseError("BLOCK_SYSFS_INVALID_BLOCK_SIZE")
        value_type, unit = "INTEGER", "bytes"
    else:
        normalized, value_type, unit = value.strip(" \t"), "STRING", None
    return ParseResult("linux-sysfs-block-v1", (
        ParsedDatum(path, observed, normalized, value_type, unit),
    ))


# Intentional bounded list. Unsupported source families are not normalized
# by interpreting raw bytes as arbitrary meaningful inventory fields.
PARSERS = {
    "SRC-12": _parse_block_sysfs,
    "SRC-07": _parse_cpu_sysfs,
    "SRC-04": _parse_dmi_public,
    "SRC-01": _parse_platform_api,
    "SRC-02": _parse_os_release,
    "SRC-03": _parse_efi_presence,
    "SRC-06": _parse_cpuinfo,
    "SRC-16": _parse_cdrom_info,
    "SRC-27": _parse_tool_resolver,
    "SRC-08": _parse_meminfo,
    "SRC-09": _parse_swaps,
    "SRC-10": _parse_memory_pressure,
}


def parser_available(source_id):
    return source_id in PARSERS


def normalize_sealed_source(source_id, raw, *, source_path=None):
    """Normalize sealed bytes; SRC-04 additionally requires verified source path."""
    parser = PARSERS.get(source_id)
    if parser is None:
        return None
    if source_id in ("SRC-04", "SRC-07", "SRC-12"):
        return parser(raw, source_path=source_path)
    if source_path is not None:
        raise SourceParseError("SOURCE_PATH_NOT_APPLICABLE")
    return parser(raw)
