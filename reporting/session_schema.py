"""IC-03 canonical system.json v2 contract and default-safe evidence mapper.

This module performs no collection, file I/O, or Phase 1 schema migration.
All persisted fields undergo a deliberate allowlist and structural validation.
"""
from datetime import datetime, timezone
import ipaddress
import json
import math
import re

from discovery.core import CollectionStatus
from discovery.registry import EXPECTED_COLLECTOR_IDS

SCHEMA_VERSION = "2.0.0"
IC02_VERSION = "1.0"
STATUS_VALUES = frozenset(s.value for s in CollectionStatus)
OUTCOMES = frozenset(("COMPLETE", "PARTIAL", "FAILED", "INTERRUPTED"))
STATUS_KEYS = tuple(s.value for s in CollectionStatus)
_ID = re.compile(r"session_[A-Za-z0-9_-]{1,100}\Z")
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_. -]{0,100}\Z")
_MAC = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}(?![A-Fa-f0-9])")
_UUID = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}(?![0-9a-fA-F])")
_WINDOWS = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]")
_ABSOLUTE = re.compile(r"(?<![A-Za-z0-9_])/(?:home|users|tmp|var|run/user|media|mnt|root|private|etc/passwd)(?:/|\b)", re.I)
_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_SENSITIVE_KEYS = frozenset((
    "serial", "serial_number", "serial_id", "machine_id", "host_id",
    "hostname", "host_name", "username", "user", "uid", "gid",
    "ip", "ip_address", "ipv4", "ipv6", "mac", "mac_address",
    "address", "uuid", "dmi_uuid", "mountpoint", "sysfs_device_path",
    "password", "secret", "token", "private_key", "home_directory",
))
# Known read-only Phase 2 data envelopes. Unrecognized fields require a
# separately reviewed schema change; they are NOT persisted opportunistically.
_DATA_FIELDS = {
    "system": frozenset(("os", "kernel", "architecture", "id", "version_id",
                         "pretty_name", "version_codename", "efi_boot",
                         "bios_vendor", "bios_version", "bios_date",
                         "board_vendor", "product_name")),
    "cpu": frozenset(("architecture", "vendor", "model", "implementer",
                      "hardware", "instruction_sets", "logical_processors_visible",
                      "online_cpu_list", "possible_cpu_list", "package_id_cpu0",
                      "core_id_cpu0")),
    "memory": frozenset(("metrics", "swap_devices", "pressure")),
    "storage": frozenset(("devices", "partitions")),
    "optical": frozenset(("drives",)),
    "gpu": frozenset(("devices",)),
    "vaapi": frozenset(("profiles", "functional_test", "va_api_version",
                        "advertisement_only")),
    "network": frozenset(("interfaces",)),
    "thermal": frozenset(("sensors",)),
    "power": frozenset(("supplies",)),
}
_HOST_FIELDS = frozenset(("system", "architecture", "kernel", "distribution"))


class SessionSchemaError(ValueError):
    """Unknown schema, inconsistent session data or unsafe persisted value."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SessionSchemaError(message)


def _json_copy(value):
    """Reject invalid JSON types, NaN, infinity, cycles and invalid keys."""
    try:
        return json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SessionSchemaError("source data is not strict JSON") from exc


def _timestamp(value):
    _require(isinstance(value, str) and value.endswith("Z"), "UTC timestamp required")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SessionSchemaError("invalid UTC timestamp") from exc
    _require(parsed.utcoffset().total_seconds() == 0, "timestamp not UTC")
    return parsed


def _is_private(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 4096:
        return True
    if any(ord(char) < 32 and char not in "\t\n" for char in value):
        return True
    if _MAC.search(value) or _UUID.search(value) or _WINDOWS.search(value):
        return True
    if _ABSOLUTE.search(value):
        return True
    for candidate in _IP.findall(value):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True
    # Prevent accidental inclusion of raw Linux paths embedded in prose;
    # known collector source paths are handled separately below.
    if re.search(r"(?<!\w)/(?:sys|proc|etc|dev)/", value):
        return True
    return False


def _text(value):
    _require(isinstance(value, str), "text field must be a string")
    return "[REDACTED]" if _is_private(value) else value


def _sanitize_data(value, *, key=None):
    if key is not None and key.lower().replace("-", "_") in _SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        result = {}
        for name, child in value.items():
            _require(isinstance(name, str) and _KEY.fullmatch(name) is not None,
                     "invalid hardware data field name")
            normalized = name.lower().replace("-", "_")
            if normalized in _SENSITIVE_KEYS:
                # Omit sensitive keys completely; do not leak serial identifiers
                # through key names or their values.
                continue
            result[name] = _sanitize_data(child, key=normalized)
        return result
    if isinstance(value, list):
        return [_sanitize_data(child) for child in value]
    if isinstance(value, str):
        return _text(value)
    _require(value is None or type(value) in (int, float, bool),
             "unsupported hardware data field type")
    if type(value) is float:
        _require(math.isfinite(value), "nonfinite hardware value")
    return value


def _source_path(path: str) -> str:
    _require(isinstance(path, str), "source path must be text")
    # Accept only exact expected Linux virtual/OS filesystems.
    # In particular, '/tmp/test123/sys/...' is NOT treated as real sysfs.
    for prefix, tag in (("/sys/", "sysfs:"), ("/proc/", "procfs:"),
                        ("/etc/", "etc:")):
        if path.startswith(prefix):
            tail = path[len(prefix):]
            if re.fullmatch(r"[A-Za-z0-9_.@:+/-]{1,256}", tail) and all(
                segment not in ("", ".", "..") for segment in tail.split("/")
            ):
                return tag + tail
    return "[REDACTED]"


def _sources(sources):
    _require(isinstance(sources, list), "collector sources must be an array")
    result = []
    for item in sources:
        _require(isinstance(item, dict), "source must be an object")
        _require(set(item).issubset({"path", "tool", "status", "exit_code", "reason"}),
                 "unexpected source fields")
        _require("status" in item and item["status"] in STATUS_VALUES,
                 "invalid source status")
        entry = {"status": item["status"]}
        if "path" in item:
            entry["path"] = _source_path(item["path"])
        if "tool" in item:
            _require(item["tool"] == "vainfo", "unknown provenance tool")
            entry["tool"] = item["tool"]
        if "exit_code" in item:
            _require(item["exit_code"] is None or type(item["exit_code"]) is int,
                     "invalid source exit code")
            entry["exit_code"] = item["exit_code"]
        if "reason" in item:
            entry["reason"] = _text(item["reason"])
        result.append(entry)
    return result


def _sanitize_collector(cid, entry):
    _require(isinstance(entry, dict), "collector record must be an object")
    _require(set(entry) == {"collector_id", "status", "data", "sources", "reason"},
             "collector record requires five canonical fields")
    _require(entry["collector_id"] == cid and cid in EXPECTED_COLLECTOR_IDS,
             "unrecognized collector ID")
    _require(isinstance(entry["status"], str) and entry["status"] in STATUS_VALUES,
             "invalid collection status")
    _require(isinstance(entry["data"], dict), "collector data must be an object")
    _require(set(entry["data"]).issubset(_DATA_FIELDS[cid]),
             "unreviewed hardware data fields")
    return {
        "collector_id": cid, "status": entry["status"],
        "data": _sanitize_data(entry["data"]),
        "sources": _sources(entry["sources"]),
        "reason": _text(entry["reason"]),
    }


def _check_discovery(inv):
    _require(isinstance(inv, dict), "discovery must be an object")
    fields = {"contract_version", "scope", "started_utc", "completed_utc",
              "requested_collector_ids", "execution_order", "collectors",
              "timings", "summary", "errors"}
    _require(set(inv) == fields, "discovery fields do not match schema")
    _require(inv["contract_version"] == IC02_VERSION, "unsupported IC-02 version")
    _require(inv["scope"] in ("full", "selected"), "invalid discovery scope")
    _require(_timestamp(inv["started_utc"]) <= _timestamp(inv["completed_utc"]),
             "discovery timestamps out of order")
    requested, order = inv["requested_collector_ids"], inv["execution_order"]
    _require(isinstance(requested, list) and isinstance(order, list) and bool(order),
             "collector ID arrays required")
    _require(all(isinstance(cid, str) and cid in EXPECTED_COLLECTOR_IDS
                 for cid in requested + order), "unknown collector ID")
    _require(len(set(requested)) == len(requested) == len(order)
             and set(requested) == set(order), "collector IDs differ or duplicate")
    _require(order == [cid for cid in EXPECTED_COLLECTOR_IDS if cid in requested],
             "collector execution order must match IC-01")
    if inv["scope"] == "full":
        _require(order == list(EXPECTED_COLLECTOR_IDS),
                 "full discovery must select all collectors")
    _require(isinstance(inv["collectors"], dict) and
             set(inv["collectors"]).issubset(set(order)), "invalid collector mapping")
    sequence = [cid for cid in order if cid in inv["collectors"]]
    _require(list(inv["collectors"]) == sequence, "collector records out of sequence")
    for cid, entry in inv["collectors"].items():
        _sanitize_collector(cid, entry)
    timings = inv["timings"]
    _require(isinstance(timings, dict) and set(timings).issubset(set(order)),
             "invalid collector timing keys")
    for cid, item in timings.items():
        _require(isinstance(item, dict) and set(item) == {"elapsed_ms"} and
                 type(item["elapsed_ms"]) in (int, float) and
                 math.isfinite(item["elapsed_ms"]) and item["elapsed_ms"] >= 0,
                 "invalid elapsed milliseconds")
    summary = inv["summary"]
    _require(isinstance(summary, dict) and
             set(summary) == {"outcome", "minimum_inventory_met", "selected",
                              "attempted", "executed", "status_counts"},
             "invalid summary fields")
    _require(summary["outcome"] in OUTCOMES and
             type(summary["minimum_inventory_met"]) is bool,
             "invalid outcome or minimum flag")
    _require(all(type(summary[k]) is int and summary[k] >= 0
                 for k in ("selected", "attempted", "executed")), "invalid counters")
    _require(summary["selected"] == len(order) and
             summary["executed"] == len(inv["collectors"]) and
             len(timings) == summary["attempted"] and
             summary["attempted"] <= len(order), "inconsistent attempted counts")
    _require(set(summary["status_counts"]) == set(STATUS_KEYS) and
             all(type(x) is int and x >= 0 for x in summary["status_counts"].values()),
             "invalid status counts")
    actual = {key: 0 for key in STATUS_KEYS}
    for entry in inv["collectors"].values():
        actual[entry["status"]] += 1
    _require(summary["status_counts"] == actual, "collector status counts disagree")
    _require(isinstance(inv["errors"], list), "errors must be an array")
    for item in inv["errors"]:
        _require(isinstance(item, dict) and set(item) == {"collector_id", "kind"}
                 and item["collector_id"] in order and
                 item["kind"] in ("COLLECTOR_FAILURE", "DISPATCH_FAILURE",
                                  "INVALID_RESULT", "ACCESS_DENIED", "INTERRUPTED"),
                 "invalid orchestration error")
    if summary["outcome"] == "INTERRUPTED":
        _require(summary["attempted"] == summary["executed"] + 1 and
                 list(timings) == order[:summary["attempted"]] and
                 list(inv["collectors"]) == order[:summary["executed"]],
                 "interrupted session has invalid prefix")
        _require(any(e["kind"] == "INTERRUPTED" for e in inv["errors"]),
                 "interruption marker missing")
    else:
        _require(summary["attempted"] == len(order) and
                 summary["executed"] == len(order) and
                 list(timings) == order, "normal session lacks collector results")
        _require(not any(e["kind"] == "INTERRUPTED" for e in inv["errors"]),
                 "unexpected interruption marker")
    baseline = any(inv["collectors"].get(cid, {}).get("status") == "COMPLETE"
                   for cid in ("cpu", "memory", "storage"))
    if inv["scope"] == "full":
        minimum = (inv["collectors"].get("system", {}).get("status") == "COMPLETE"
                   and baseline)
    else:
        minimum = any(e["status"] in ("COMPLETE", "UNAVAILABLE", "UNSUPPORTED",
                                     "TOOL_MISSING") for e in inv["collectors"].values())
    _require(summary["minimum_inventory_met"] == minimum,
             "minimum inventory claim inconsistent")
    if summary["outcome"] != "INTERRUPTED":
        expected = ("FAILED" if not minimum else
                    "PARTIAL" if any(e["status"] in ("FAILED", "PERMISSION_DENIED")
                                     for e in inv["collectors"].values())
                    else "COMPLETE")
        _require(summary["outcome"] == expected, "orchestration outcome inconsistent")


def build_system_document(session_id: str, inventory: dict, *,
                          host: dict, session_started_utc: str) -> dict:
    """Create a default-safe defensive copy from the IC-02 memory structure."""
    _require(isinstance(session_id, str) and _ID.fullmatch(session_id),
             "invalid session ID")
    _timestamp(session_started_utc)
    raw = _json_copy(inventory)
    _require(isinstance(raw, dict), "inventory must be a mapping")
    _require(set(raw) == {
        "contract_version", "scope", "started_utc", "completed_utc",
        "requested_collector_ids", "execution_order", "results",
        "timings", "summary", "errors"}, "IC-02 inventory envelope inconsistent")
    discovery = {key: value for key, value in raw.items() if key != "results"}
    discovery["collectors"] = raw["results"]
    _check_discovery(discovery)
    _require(isinstance(host, dict) and "system" in host and
             set(host).issubset(_HOST_FIELDS), "invalid host fields")
    safe_host = {key: _text(value) for key, value in host.items()}
    _require(safe_host["system"] == "Linux", "IC-03 supports Linux only")
    safe_collectors = {
        cid: _sanitize_collector(cid, entry)
        for cid, entry in discovery["collectors"].items()
    }
    discovery["collectors"] = safe_collectors
    document = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "started_utc": session_started_utc,
        "host": safe_host,
        "discovery": discovery,
    }
    validate_system_document(document)
    return document


def validate_system_document(document: dict, session_id: str | None = None) -> None:
    """Check all canonical invariants and reject unsanitized/unapproved data."""
    doc = _json_copy(document)
    _require(isinstance(doc, dict) and
             set(doc) == {"schema_version", "session_id", "started_utc",
                          "host", "discovery"}, "invalid system document envelope")
    _require(doc["schema_version"] == SCHEMA_VERSION, "unsupported schema version")
    _require(isinstance(doc["session_id"], str) and _ID.fullmatch(doc["session_id"]),
             "invalid session ID")
    if session_id is not None:
        _require(doc["session_id"] == session_id, "session directory identity mismatch")
    _timestamp(doc["started_utc"])
    host = doc["host"]
    _require(isinstance(host, dict) and "system" in host and
             set(host).issubset(_HOST_FIELDS) and host["system"] == "Linux",
             "invalid host fields")
    _require(all(isinstance(v, str) and not _is_private(v) for v in host.values()),
             "host contains private fields")
    _check_discovery(doc["discovery"])
    for cid, entry in doc["discovery"]["collectors"].items():
        _require(_sanitize_collector(cid, entry) == entry,
                 "collector contains unapproved or private evidence")
