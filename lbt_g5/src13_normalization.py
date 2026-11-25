"""Pure conservative parsing of already-sealed SRC-13 O1 stdout.

No IO, runtime command execution, device state inference or health classification.
Only exact device/tool attributed streams may call parse_src13. The original
bytes remain authoritative, separately sealed evidence.
"""
import re

MAX_SRC13_BYTES = 1024 * 1024
MAX_SRC13_LINES = 512
MAX_VALUE_CHARS = 512
MAX_SRC13_FIELDS = 24


class SRC13ParseError(ValueError):
    """Unsupported or inconsistent SRC-13 stdout, retained as raw evidence."""


_SMART_FIELDS = {
    "Device Model": "device_model",
    "Model Number": "model_number",
    "Vendor": "vendor",
    "Product": "product",
    "Serial Number": "serial_number",
    "Firmware Version": "firmware_version",
    # Direct report text only. No normalized drive-health decision.
    "SMART overall-health self-assessment test result": "reported_assessment",
    "SMART Health Status": "reported_assessment",
}
_NVME_FIELDS = {
    "critical_warning": "warning_bits",
    "temperature": "temperature",
    "available_spare": "available_spare",
    "available_spare_threshold": "available_spare_threshold",
    "percentage_used": "percentage_used",
    "power_cycles": "power_cycles",
    "power_on_hours": "power_on_hours",
    "unsafe_shutdowns": "unsafe_shutdowns",
    "media_errors": "media_errors",
    "data_units_read": "data_units_read",
    "data_units_written": "data_units_written",
}
_PERCENT_KEYS = frozenset(("available_spare", "available_spare_threshold", "percentage_used"))
_COUNT_KEYS = frozenset(("power_cycles", "power_on_hours", "unsafe_shutdowns", "media_errors",
                         "data_units_read", "data_units_written"))
_DECIMAL_COUNT = re.compile(r"(?:[0-9]+|[1-9][0-9]{0,2}(?:,[0-9]{3})+)")
_NVME_HEADER = re.compile(r"Smart Log for NVME device:\s*(\S+)(?:\s+namespace-id:[0-9A-Fa-f]+)?\s*")
_CELSIUS = re.compile(r"(-?[0-9]{1,3})\s*(?:°\s*)?C(?:\s*\([^\r\n]{1,80}\))?")


def _count(raw, *, maximum=(1 << 128) - 1):
    if not _DECIMAL_COUNT.fullmatch(raw) or len(raw) > 60:
        raise SRC13ParseError("SRC13_NONNUMERIC_COUNTER")
    number = int(raw.replace(",", ""))
    if number > maximum:
        raise SRC13ParseError("SRC13_COUNTER_OUT_OF_RANGE")
    return number


def _nvme_value(key, value):
    if key == "critical_warning":
        if re.fullmatch(r"0[xX][0-9A-Fa-f]{1,2}", value):
            number = int(value, 16)
        else:
            number = _count(value, maximum=255)
        return number, "INTEGER", None
    if key in _PERCENT_KEYS:
        if not re.fullmatch(r"[0-9]{1,3}%", value):
            raise SRC13ParseError("SRC13_UNSUPPORTED_PERCENT_FORMAT")
        return _count(value[:-1], maximum=255), "INTEGER", "%"
    if key in _COUNT_KEYS:
        unit = ("h" if key == "power_on_hours" else
                "NVME_DATA_UNITS" if key.startswith("data_units_") else None)
        return _count(value), "INTEGER", unit
    if key == "temperature":
        match = _CELSIUS.fullmatch(value)
        if match:
            temp = int(match.group(1))
            if -273 <= temp <= 255:
                return temp, "INTEGER", "C"
        # A Fahrenheit/Kelvin/unknown renderer must not be guessed in Celsius.
        return value, "STRING", None
    raise SRC13ParseError("SRC13_UNREGISTERED_NVME_KEY")


def parse_src13(raw, *, source_command, source_target):
    """Return bounded (datum_path, observed, normalized, type, unit) rows.

    The caller must first verify that source_command is the *approved* plan's
    tool, that source_target is the *authorized* target for the same source run,
    and that raw came from a hash-checked callNNNN-stdout original.
    """
    if (source_command not in ("smartctl", "nvme")
            or type(source_target) is not str):
        raise SRC13ParseError("SRC13_UNVERIFIED_COMMAND")
    if source_command == "smartctl":
        if not re.fullmatch(r"/dev/sd[a-z]+", source_target):
            raise SRC13ParseError("SRC13_SMARTCTL_UNVERIFIED_TARGET")
    elif not re.fullmatch(r"/dev/nvme[0-9]+(?:n[0-9]+)?", source_target):
        raise SRC13ParseError("SRC13_NVME_UNVERIFIED_TARGET")
    if type(raw) is not bytes or len(raw) > MAX_SRC13_BYTES:
        raise SRC13ParseError("SRC13_INPUT_TYPE_OR_BOUND")
    try:
        content = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SRC13ParseError("SRC13_NON_UTF8") from exc
    lines = content.split("\n")
    if len(lines) > MAX_SRC13_LINES:
        raise SRC13ParseError("SRC13_EXCESSIVE_ROWS")
    if any("\x00" in row or "\r" in row for row in lines):
        raise SRC13ParseError("SRC13_CONTROL_BYTES")
    seen = set()
    values = []
    header_seen = False
    for row in lines:
        line = row.strip()
        if not line:
            continue
        if len(line) > 2048:
            raise SRC13ParseError("SRC13_EXCESSIVE_LINE")
        if source_command == "nvme" and line.startswith("Smart Log for NVME device:"):
            header = _NVME_HEADER.fullmatch(line)
            if (header_seen or header is None or header.group(1) not in
                    (source_target, source_target.rsplit("/", 1)[-1])):
                raise SRC13ParseError("SRC13_NVME_HEADER_TARGET_MISMATCH")
            header_seen = True
            continue
        if ":" not in line:
            continue
        label, value = (x.strip() for x in line.split(":", 1))
        key = (_SMART_FIELDS.get(label) if source_command == "smartctl" else
               _NVME_FIELDS.get(label))
        if key is None:
            continue
        if (not value or len(value) > MAX_VALUE_CHARS or key in seen):
            raise SRC13ParseError("SRC13_EMPTY_EXCESSIVE_OR_DUPLICATE_FIELD")
        seen.add(key)
        if source_command == "smartctl":
            datum = ("storage.device_health.smartctl." + key,
                     value, value, "STRING", None)
        else:
            normalized, kind, unit = _nvme_value(label, value)
            datum = ("storage.device_health.nvme." + key,
                     value, normalized, kind, unit)
        values.append(datum)
        if len(values) > MAX_SRC13_FIELDS:
            raise SRC13ParseError("SRC13_EXCESSIVE_FIELDS")
    if source_command == "nvme" and not header_seen:
        raise SRC13ParseError("SRC13_NVME_HEADER_MISSING")
    if not values:
        raise SRC13ParseError("SRC13_NO_SUPPORTED_DATA")
    return tuple(values)
