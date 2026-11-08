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
from .src13_normalization import parse_src13, SRC13ParseError
from .mountinfo_normalization import parse_mountinfo, MountinfoParseError
from .fs_stat_normalization import parse_fs_stat_stdout, FSStatParseError


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



# SRC-17 registered optical identity only. The G5-03 passive worker enumerates
# srN lexical directory names and the fixed attribute tuple below; it does not
# open /dev/srN or test inserted media. No host reads occur in normalization.
_OPTICAL_SYSFS_ROOT = "/sys/class/block/"
_OPTICAL_SYSFS_DEVICE = re.compile(r"sr[0-9]+\Z")
_OPTICAL_SYSFS_ATTRS = (
    "removable", "device/type", "device/vendor", "device/model",
)


def optical_sysfs_path_identity(source_path):
    """Exact approved optical source identity + G5 worker sort order."""
    if (type(source_path) is not str
            or not source_path.startswith(_OPTICAL_SYSFS_ROOT)):
        return None
    relative = source_path[len(_OPTICAL_SYSFS_ROOT):]
    parts = relative.split("/", 1)
    if len(parts) != 2:
        return None
    name, attr = parts
    if (_OPTICAL_SYSFS_DEVICE.fullmatch(name) is None
            or attr not in _OPTICAL_SYSFS_ATTRS):
        return None
    return ("optical.sysfs." + name + "." + attr.replace("/", "."),
            (name, _OPTICAL_SYSFS_ATTRS.index(attr)), attr)


def _parse_optical_sysfs(raw, *, source_path):
    identity = optical_sysfs_path_identity(source_path)
    if identity is None:
        raise SourceParseError("OPTICAL_SYSFS_SOURCE_PATH_NOT_APPROVED")
    datum_path, _, attr = identity
    observed = _text(raw)
    if (not observed or len(observed) > 4096
            or "\x00" in observed or "\r" in observed
            or observed.count("\n") > 1
            or ("\n" in observed and not observed.endswith("\n"))):
        raise SourceParseError("OPTICAL_SYSFS_INVALID_SCALAR_OR_BOUND")
    value = observed.removesuffix("\n")
    if attr == "removable":
        if value not in ("0", "1"):
            raise SourceParseError("OPTICAL_SYSFS_INVALID_REMOVABLE")
        normalized, value_type = value == "1", "BOOLEAN"
    elif attr == "device/type":
        if (not value or len(value) > 20
                or _BLOCK_SYSFS_NUMBER.fullmatch(value) is None
                or int(value) > 18446744073709551615):
            raise SourceParseError("OPTICAL_SYSFS_INVALID_PERIPHERAL_TYPE")
        normalized, value_type = int(value), "INTEGER"
    else:
        normalized, value_type = value.strip(" \t"), "STRING"
    return ParseResult("linux-sysfs-optical-identity-v1", (
        ParsedDatum(datum_path, observed, normalized, value_type),
    ))



# SRC-19 accepted passive worker: cardN lexical names, fixed PCI identity
# attribute order, no DRM render nodes, GPU workload or control writes.
_DRM_ROOT = "/sys/class/drm/"
_DRM_CARD = re.compile(r"card[0-9]+\Z")
_DRM_PCI_ATTRS = (
    "device/vendor", "device/device", "device/subsystem_vendor",
    "device/subsystem_device", "device/revision",
)
_DRM_PCI_VALUE = re.compile(r"0x[0-9a-fA-F]{2,8}\Z")


def drm_sysfs_path_identity(source_path):
    """Exact SRC-19 identity and original-worker path ordering key."""
    if type(source_path) is not str or not source_path.startswith(_DRM_ROOT):
        return None
    parts = source_path[len(_DRM_ROOT):].split("/", 1)
    if len(parts) != 2:
        return None
    card, attr = parts
    if _DRM_CARD.fullmatch(card) is None or attr not in _DRM_PCI_ATTRS:
        return None
    return ("gpu.drm." + card + ".pci." + attr.split("/", 1)[1],
            (card, _DRM_PCI_ATTRS.index(attr)), attr)


def _parse_drm_sysfs(raw, *, source_path):
    identity = drm_sysfs_path_identity(source_path)
    if identity is None:
        raise SourceParseError("DRM_SOURCE_PATH_NOT_APPROVED")
    observed, value = _block_scalar_text(raw)
    if not _DRM_PCI_VALUE.fullmatch(value):
        raise SourceParseError("DRM_INVALID_PCI_ID")
    # Identifier, not a device-name lookup or inferred GPU capability.
    return ParseResult("linux-sysfs-drm-pci-id-v1", (
        ParsedDatum(identity[0], observed, value.lower(), "STRING"),
    ))



# SRC-22: existing G5-03 passive worker local net sysfs only. Exact
# link/address STATE, not a packet observation, MAC-type assertion or credential.
_NET_SYSFS_ROOT = "/sys/class/net/"
_NET_SYSFS_NAME = re.compile(r"[A-Za-z0-9_.:-]+\Z")
_NET_SYSFS_ATTRS = (
    "address", "operstate", "carrier", "mtu",
    "speed", "type", "duplex", "ifindex",
)
_NET_SIGNED = re.compile(r"-?[0-9]+\Z")


def net_sysfs_path_identity(source_path):
    """Registered per-interface SRC-22 field and worker-order key."""
    if type(source_path) is not str or not source_path.startswith(_NET_SYSFS_ROOT):
        return None
    parts = source_path[len(_NET_SYSFS_ROOT):].split("/", 1)
    if len(parts) != 2:
        return None
    name, attr = parts
    if (name.startswith(".") or _NET_SYSFS_NAME.fullmatch(name) is None
            or attr not in _NET_SYSFS_ATTRS):
        return None
    return ("network.link." + name + "." + attr,
            (name, _NET_SYSFS_ATTRS.index(attr)), attr)


def _parse_net_sysfs(raw, *, source_path):
    identity = net_sysfs_path_identity(source_path)
    if identity is None:
        raise SourceParseError("NET_SYSFS_SOURCE_PATH_NOT_APPROVED")
    observed, value = _block_scalar_text(raw)
    path, _, attr = identity
    if attr == "carrier":
        if value not in ("0", "1"):
            raise SourceParseError("NET_SYSFS_INVALID_CARRIER")
        norm, typ, unit = (value == "1"), "BOOLEAN", None
    elif attr in ("mtu", "type", "ifindex"):
        norm = _block_nonnegative_decimal(value)
        if norm > 4294967295 or (attr in ("mtu", "ifindex") and norm == 0):
            raise SourceParseError("NET_SYSFS_INVALID_NUMERIC_RANGE")
        typ = "INTEGER"
        unit = "bytes" if attr == "mtu" else None
    elif attr == "speed":
        if not value or len(value) > 20 or _NET_SIGNED.fullmatch(value) is None:
            raise SourceParseError("NET_SYSFS_INVALID_SPEED")
        number = int(value)
        if number == -1:
            norm, typ, unit = {"known": False, "reported_code": -1}, "OBJECT", None
        elif 0 <= number <= 4294967295:
            norm, typ, unit = number, "INTEGER", "Mb/s"
        else:
            raise SourceParseError("NET_SYSFS_INVALID_SPEED_RANGE")
    else:
        # Address may not be Ethernet; unknown state labels remain source text.
        norm, typ, unit = value.strip(" \t"), "STRING", None
    return ParseResult("linux-sysfs-net-link-v1", (
        ParsedDatum(path, observed, norm, typ, unit),
    ))



# SRC-24 accepted G5-03 passive worker. Only thermal_zoneN {type,temp}
# originals are read, never cooling/trip controls or thermal policy writes.
_THERMAL_SYSFS_ROOT = "/sys/class/thermal/"
_THERMAL_SYSFS_ZONE = re.compile(r"thermal_zone[0-9]+\Z")
_THERMAL_SYSFS_ATTRS = ("type", "temp")


def thermal_sysfs_path_identity(source_path):
    """SRC-24 allowed zone attribute and G5-03 original ordering key."""
    if type(source_path) is not str or not source_path.startswith(_THERMAL_SYSFS_ROOT):
        return None
    parts = source_path[len(_THERMAL_SYSFS_ROOT):].split("/", 1)
    if len(parts) != 2:
        return None
    zone, attr = parts
    if _THERMAL_SYSFS_ZONE.fullmatch(zone) is None or attr not in _THERMAL_SYSFS_ATTRS:
        return None
    return ("thermal.sysfs." + zone + "." + attr,
            (zone, _THERMAL_SYSFS_ATTRS.index(attr)), attr)


def _parse_thermal_sysfs(raw, *, source_path):
    identity = thermal_sysfs_path_identity(source_path)
    if identity is None:
        raise SourceParseError("THERMAL_SYSFS_SOURCE_PATH_NOT_APPROVED")
    observed, value = _block_scalar_text(raw)
    attr = identity[2]
    if attr == "temp":
        # Linux thermal_zone temp is in millidegrees Celsius. Do NOT
        # divide by 1000 or infer an operating limit or thermal failure.
        norm = _cpu_sysfs_integer(value, signed=True)
        typ, unit = "INTEGER", "millidegrees Celsius"
    else:
        norm, typ, unit = value.strip(" \t"), "STRING", None
    return ParseResult("linux-sysfs-thermal-zone-v1", (
        ParsedDatum(identity[0], observed, norm, typ, unit),
    ))



# SRC-25: hwmon chip/channel observations. Devices and filenames are sorted
# lexically by the accepted G5-03 worker. Do not infer hardware-specific units
# from attr names; some temp*_input drivers represent non-temperature values.
_HWMON_ROOT = "/sys/class/hwmon/"
_HWMON_DEVICE = re.compile(r"hwmon[0-9]+\Z")
_HWMON_ATTR = re.compile(r"(?:(?:temp|fan|in|power)[0-9]+_(?:input|label)|name)\Z")
_HWMON_SIGNED = re.compile(r"-?[0-9]{1,19}\Z")


def hwmon_sysfs_path_identity(source_path):
    if type(source_path) is not str or not source_path.startswith(_HWMON_ROOT):
        return None
    fields = source_path[len(_HWMON_ROOT):].split("/", 1)
    if len(fields) != 2 or not _HWMON_DEVICE.fullmatch(fields[0]):
        return None
    chip, attr = fields
    if not _HWMON_ATTR.fullmatch(attr):
        return None
    return ("thermal.hwmon." + chip + "." + attr, (chip, attr), attr)


def _parse_hwmon_sysfs(raw, *, source_path):
    identity = hwmon_sysfs_path_identity(source_path)
    if identity is None:
        raise SourceParseError("HWMON_SOURCE_PATH_NOT_APPROVED")
    observed, value = _block_scalar_text(raw)
    attr = identity[2]
    if attr == "name" or attr.endswith("_label"):
        norm, typ = value.strip(" \t"), "STRING"
    else:
        if not _HWMON_SIGNED.fullmatch(value):
            raise SourceParseError("HWMON_INVALID_RAW_DECIMAL")
        norm = int(value)
        if not -(1 << 63) <= norm < (1 << 63):
            raise SourceParseError("HWMON_INTEGER_OUT_OF_RANGE")
        typ = "INTEGER"
    # Preserve the unconverted driver-reported value; unit inference requires
    # chip/channel evidence not present in SRC-25's bounded source contract.
    return ParseResult("linux-sysfs-hwmon-raw-v1", (
        ParsedDatum(identity[0], observed, norm, typ),
    ))



# SRC-26 original G5-03 passive power-supply captures. In particular,
# serial_number is PRIVATE; source acquisition does not grant public release.
_POWER_SYSFS_ROOT = "/sys/class/power_supply/"
_POWER_SYSFS_DEVICE = re.compile(r"[A-Za-z0-9_.:-]+\Z")
_POWER_SYSFS_ATTRS = (
    "type", "status", "capacity", "voltage_now", "current_now",
    "power_now", "energy_now", "energy_full", "energy_full_design",
    "charge_now", "charge_full", "charge_full_design", "manufacturer",
    "model_name", "serial_number", "technology", "cycle_count",
)
_POWER_SYSFS_TEXT = frozenset((
    "type", "status", "manufacturer", "model_name", "serial_number", "technology",
))


def power_sysfs_path_identity(source_path):
    if type(source_path) is not str or not source_path.startswith(_POWER_SYSFS_ROOT):
        return None
    parts = source_path[len(_POWER_SYSFS_ROOT):].split("/", 1)
    if len(parts) != 2:
        return None
    name, attr = parts
    if (name.startswith(".") or _POWER_SYSFS_DEVICE.fullmatch(name) is None
            or attr not in _POWER_SYSFS_ATTRS):
        return None
    return ("power.supply." + name + "." + attr,
            (name, _POWER_SYSFS_ATTRS.index(attr)), attr)


def _parse_power_sysfs(raw, *, source_path):
    identity = power_sysfs_path_identity(source_path)
    if identity is None:
        raise SourceParseError("POWER_SYSFS_SOURCE_PATH_NOT_APPROVED")
    observed, value = _block_scalar_text(raw)
    attr = identity[2]
    if attr in _POWER_SYSFS_TEXT:
        normalized, kind = value.strip(" \t"), "STRING"
    else:
        if _HWMON_SIGNED.fullmatch(value) is None:
            raise SourceParseError("POWER_SYSFS_INVALID_RAW_DECIMAL")
        normalized = int(value)
        if not -(1 << 63) <= normalized < (1 << 63):
            raise SourceParseError("POWER_SYSFS_INTEGER_OUT_OF_RANGE")
        kind = "INTEGER"
    # Keep native raw integer, without inferring battery health or units.
    return ParseResult("linux-sysfs-power-raw-v1", (
        ParsedDatum(identity[0], observed, normalized, kind),
    ))



# SRC-05 lscpu: D1 original command stream, not a source path. Locale-specific
# labels are kept as strings; no numeric CPU claim without field assurance.
def _parse_lscpu_stdout(raw):
    lines = _text(raw).splitlines()
    if not lines or len(lines) > MAX_FIELDS:
        raise SourceParseError("LSCPU_MISSING_OR_EXCESSIVE_ROWS")
    fields = []
    for line in lines:
        if not line.strip():
            continue
        if ":" not in line:
            raise SourceParseError("LSCPU_NON_KEYVALUE_LINE")
        label, value = line.split(":", 1)
        label, value = label.strip(), value.strip()
        if (not label or len(label) > 256 or len(value) > 8192
                or "\x00" in line or "\r" in line):
            raise SourceParseError("LSCPU_UNBOUNDED_OR_INVALID_ROW")
        fields.append({"label": label, "value": value})
    if not fields:
        raise SourceParseError("LSCPU_NO_DATA_ROWS")
    return ParseResult("linux-lscpu-opaque-rows-v1", (
        ParsedDatum("cpu.lscpu.rows", "LSCPU_KEY_VALUE_ROWS", fields, "ARRAY"),
    ))



# SRC-11 lsblk: fixed G5-03 D1 --json --bytes plan. Keep the tree and
# private MODEL/SERIAL as recorded; no host disk probing or size aggregation.
_LSBLK_RECORD_FIELDS = frozenset((
    "name", "kname", "type", "size", "ro", "rm", "model", "serial", "tran",
))
_LSBLK_DEPTH_LIMIT = 16


def _lsblk_unique_object(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise SourceParseError("LSBLK_DUPLICATE_JSON_KEY")
        data[key] = value
    return data


def _lsblk_reject_constant(value):
    raise SourceParseError("LSBLK_NONFINITE_JSON_CONSTANT")


def _parse_lsblk_stdout(raw):
    try:
        data = json.loads(_text(raw), object_pairs_hook=_lsblk_unique_object,
                          parse_constant=_lsblk_reject_constant)
    except SourceParseError:
        raise
    except (ValueError, RecursionError) as exc:
        raise SourceParseError("LSBLK_INVALID_JSON") from exc
    if type(data) is not dict or set(data) != {"blockdevices"}:
        raise SourceParseError("LSBLK_UNEXPECTED_JSON_ROOT")
    devices = data["blockdevices"]
    if type(devices) is not list or len(devices) > MAX_FIELDS:
        raise SourceParseError("LSBLK_INVALID_DEVICE_ARRAY")
    total = [0]

    def validate(node, depth):
        if depth > _LSBLK_DEPTH_LIMIT or type(node) is not dict:
            raise SourceParseError("LSBLK_INVALID_DEVICE_DEPTH_OR_TYPE")
        total[0] += 1
        if total[0] > MAX_FIELDS:
            raise SourceParseError("LSBLK_EXCESSIVE_NODES")
        if not set(node).issubset(_LSBLK_RECORD_FIELDS | {"children"}):
            raise SourceParseError("LSBLK_UNAUTHORIZED_DEVICE_KEY")
        # NAME is explicitly selected and required for device identity;
        # no assumption that the remaining selected columns are populated.
        if type(node.get("name")) is not str or not node["name"]:
            raise SourceParseError("LSBLK_MISSING_DEVICE_NAME")
        result = {}
        for key, value in node.items():
            if key == "children":
                if type(value) is not list or len(value) > MAX_FIELDS:
                    raise SourceParseError("LSBLK_INVALID_CHILDREN")
                result[key] = [validate(child, depth + 1) for child in value]
            elif value is None:
                result[key] = None
            elif type(value) is str:
                if (len(value) > 8192 or "\x00" in value or
                        "\n" in value or "\r" in value):
                    raise SourceParseError("LSBLK_INVALID_STRING_FIELD")
                result[key] = value
            elif type(value) is bool:
                if key not in ("ro", "rm"):
                    raise SourceParseError("LSBLK_INVALID_BOOLEAN_FIELD")
                result[key] = value
            elif type(value) is int:
                if (key not in ("size", "ro", "rm") or value < 0 or
                        value > 18446744073709551615 or
                        (key in ("ro", "rm") and value not in (0, 1))):
                    raise SourceParseError("LSBLK_INVALID_INTEGER_FIELD")
                result[key] = value
            else:
                raise SourceParseError("LSBLK_UNSUPPORTED_JSON_VALUE")
        return result

    normalized = [validate(node, 1) for node in devices]
    return ParseResult("linux-lsblk-bounded-json-v1", (
        ParsedDatum("storage.lsblk.blockdevices",
                    "LSBLK_DEVICE_HIERARCHY", normalized, "ARRAY"),
    ))


# SRC-13 O1: parser dispatch is by a VERIFIED fixed command, never by
# untrusted output text. The private canonical writer supplies provenance.
def _parse_src13_stdout(raw, *, source_command, source_target):
    try:
        rows = parse_src13(raw, source_command=source_command,
                           source_target=source_target)
    except SRC13ParseError as exc:
        raise SourceParseError(str(exc)) from exc
    return ParseResult("linux-src13-health-verified-stdout-v1", tuple(
        ParsedDatum(path, observed, normalized, kind, unit)
        for path, observed, normalized, kind, unit in rows))


# SRC-14: a single fixed G5-02/03 D0 worker file; identity is validated
# by the private canonical producer before any original bytes are parsed.
def _parse_mountinfo_file(raw):
    try:
        records = parse_mountinfo(raw)
    except MountinfoParseError as exc:
        raise SourceParseError(str(exc)) from exc
    return ParseResult("linux-mountinfo-proc-bounded-v1", (
        ParsedDatum("storage.mountinfo.records", "MOUNTINFO_KERNEL_ROWS",
                    list(records), "ARRAY"),
    ))



# SRC-15 fixed G5-03 D1 local-only FS_STAT serialized statvfs worker result.
# Verified private receipt mount and stream attribution is required upstream.
def _parse_fsstat_stdout(raw, *, source_path):
    try:
        observed = parse_fs_stat_stdout(raw, source_path=source_path)
    except FSStatParseError as exc:
        raise SourceParseError(str(exc)) from exc
    return ParseResult("linux-fs-stat-worker-json-v1", (
        ParsedDatum("storage.fs_stat.snapshot", observed, observed, "OBJECT"),
    ))


# Intentional bounded list. Unsupported source families are not normalized
# by interpreting raw bytes as arbitrary meaningful inventory fields.
PARSERS = {
    "SRC-15": _parse_fsstat_stdout,
    "SRC-14": _parse_mountinfo_file,
    "SRC-13": _parse_src13_stdout,
    "SRC-11": _parse_lsblk_stdout,
    "SRC-05": _parse_lscpu_stdout,
    "SRC-26": _parse_power_sysfs,
    "SRC-25": _parse_hwmon_sysfs,
    "SRC-24": _parse_thermal_sysfs,
    "SRC-22": _parse_net_sysfs,
    "SRC-19": _parse_drm_sysfs,
    "SRC-17": _parse_optical_sysfs,
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


def normalize_sealed_source(source_id, raw, *, source_path=None,
                            source_stream=None, source_command=None,
                            source_target=None):
    """Normalize sealed source bytes only with their approved attribution."""
    parser = PARSERS.get(source_id)
    if parser is None:
        return None
    if source_id == "SRC-14":
        if (source_path != "/proc/self/mountinfo"
                or source_stream is not None
                or source_command is not None or source_target is not None):
            raise SourceParseError("SRC14_UNVERIFIED_FIXED_FILE")
        return parser(raw)
    if source_id == "SRC-13":
        if (source_path is not None or source_stream != "stdout"
                or source_command not in ("smartctl", "nvme")
                or type(source_target) is not str):
            raise SourceParseError("O1_UNVERIFIED_DATA_STREAM")
        return parser(raw, source_command=source_command,
                      source_target=source_target)
    if source_command is not None or source_target is not None:
        raise SourceParseError("SOURCE_COMMAND_NOT_APPLICABLE")
    if source_id == "SRC-15":
        if source_stream != "stdout" or type(source_path) is not str:
            raise SourceParseError("FSSTAT_UNVERIFIED_DATA_STREAM")
        return parser(raw, source_path=source_path)
    if source_id in ("SRC-05", "SRC-11"):
        if source_path is not None or source_stream != "stdout":
            raise SourceParseError("D1_UNVERIFIED_DATA_STREAM")
        return parser(raw)
    if source_stream is not None:
        raise SourceParseError("SOURCE_STREAM_NOT_APPLICABLE")
    if source_id in ("SRC-04", "SRC-07", "SRC-12", "SRC-17", "SRC-19", "SRC-22", "SRC-24", "SRC-25", "SRC-26"):
        return parser(raw, source_path=source_path)
    if source_path is not None:
        raise SourceParseError("SOURCE_PATH_NOT_APPLICABLE")
    return parser(raw)
