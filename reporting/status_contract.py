"""IC-04: typed status boundaries and a pure benchmark-result contract.

Importing this module performs no discovery, benchmarking, disk I/O or
software validation. There is no session-recovery or resume interface.
"""
from enum import Enum
import ipaddress
import json
import math
import re

from discovery.core import CollectionStatus
from validation.results import ValidationStatus


class BenchmarkExecutionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"


class WorkloadSuitability(str, Enum):
    GOOD = "GOOD"
    MARGINAL = "MARGINAL"
    POOR = "POOR"
    NOT_TESTED = "NOT_TESTED"


class AssessmentConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class BenchmarkContractError(ValueError):
    """A benchmark result violated its typed, evidence or privacy contract."""


_TEST_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\Z")
_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}\Z")
_UNIT = re.compile(r"[A-Za-z0-9%/_.-]{1,32}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_LOG = re.compile(r"logs/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_MAC = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}(?![A-Fa-f0-9])")
_UUID = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}(?![A-Fa-f0-9])")
_IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_PRIVATE_PATH = re.compile(
    r"(?<![A-Za-z0-9_])/(?:home|root|tmp|media|mnt|run/user|private|var/home|Users)(?:/|\b)",
    re.I,
)
_WINDOWS_PATH = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]")
_SENSITIVE_FIELDS = frozenset((
    "hostname", "host_name", "username", "user", "uid", "gid", "home",
    "home_dir", "home_directory", "mac", "mac_address", "ip", "ip_address",
    "ipv4", "ipv6", "serial", "serial_number", "uuid", "machine_id",
    "password", "secret", "token", "private_key", "mountpoint",
    "checkpoint", "checkpoint_path", "resume", "resume_at", "resume_cursor",
    "resumed_from", "recovery_state",
))
_REQUIRED_FIELDS = frozenset((
    "test_id", "execution_status", "parameters", "metrics", "reason", "evidence",
))
_OPTIONAL_FIELDS = frozenset(("tool", "fixture_id", "log_ref"))


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise BenchmarkContractError(reason)


def _safe_text(value: object, *, optional: bool = False, maximum: int = 250) -> str:
    _require(isinstance(value, str), "expected text value")
    if not value:
        _require(optional, "required text value absent")
        return value
    _require(len(value) <= maximum and all(ord(c) >= 32 for c in value),
             "unsafe or oversized text")
    _require(not _PRIVATE_PATH.search(value) and not _WINDOWS_PATH.search(value)
             and not _MAC.search(value) and not _UUID.search(value),
             "sensitive diagnostic text is prohibited")
    for candidate in _IPV4.findall(value):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        raise BenchmarkContractError("network address in diagnostic text")
    return value


def _safe_json(value, *, depth: int = 0):
    """Defensive JSON copy and safe, bounded structural validation."""
    _require(depth <= 12, "nested metadata is too deep")
    if isinstance(value, dict):
        _require(len(value) <= 128, "too many metadata fields")
        copied = {}
        for name, item in value.items():
            _require(isinstance(name, str) and bool(_FIELD.fullmatch(name)),
                     "unknown metadata key grammar")
            _require(name.lower() not in _SENSITIVE_FIELDS,
                     "private or resume metadata field is prohibited")
            copied[name] = _safe_json(item, depth=depth + 1)
        return copied
    if isinstance(value, list):
        _require(len(value) <= 256, "oversized metadata array")
        return [_safe_json(x, depth=depth + 1) for x in value]
    if isinstance(value, str):
        return _safe_text(value, optional=True, maximum=4096)
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        _require(math.isfinite(value), "nonfinite numeric metadata")
        return value
    raise BenchmarkContractError("unsupported metadata type")


def _parameters(parameters) -> dict:
    _require(isinstance(parameters, dict), "parameters must be an object")
    return _safe_json(parameters)


def _metrics(metrics) -> dict:
    _require(isinstance(metrics, dict), "metrics must be an object")
    _require(len(metrics) <= 128, "too many measured metrics")
    copy = {}
    for name, item in metrics.items():
        _require(isinstance(name, str) and bool(_FIELD.fullmatch(name)),
                 "invalid metric name")
        _require(isinstance(item, dict) and set(item) == {"value", "unit"},
                 "metric must specify numeric value and unit")
        value, unit = item["value"], item["unit"]
        _require(type(value) in (int, float) and math.isfinite(value),
                 "measured metric must be finite numeric evidence")
        _require(isinstance(unit, str) and bool(_UNIT.fullmatch(unit)),
                 "invalid or absent measured unit")
        copy[name] = {"value": value, "unit": unit}
    return copy


def _evidence(evidence) -> list[str]:
    _require(isinstance(evidence, list), "evidence must be an array")
    _require(len(evidence) <= 128, "too much evidence")
    _require(all(isinstance(item, str) and bool(_TOKEN.fullmatch(item))
                 and ".." not in item for item in evidence),
             "evidence must contain safe, structured identifiers")
    _require(len(set(evidence)) == len(evidence), "duplicate evidence identifier")
    return list(evidence)


def _tool(tool):
    if tool is None:
        return None
    _require(isinstance(tool, dict) and set(tool) == {"name", "version"},
             "tool metadata requires name and version")
    _require(all(isinstance(tool[name], str)
                 and bool(_TOKEN.fullmatch(tool[name]))
                 for name in ("name", "version")), "invalid tool provenance")
    return dict(tool)


def normalize_benchmark_result(
    test_id: str,
    execution_status: BenchmarkExecutionStatus,
    *,
    parameters: dict,
    metrics: dict,
    reason: str = "",
    evidence: list[str] | None = None,
    tool: dict | None = None,
    fixture_id: str | None = None,
    log_ref: str | None = None,
) -> dict:
    """Normalize one observed benchmark attempt; never run or resume it.

    A COMPLETE claim requires measured metric(s), an explicit evidence ID,
    observed configuration and tool provenance. This validates declarations;
    it cannot independently prove that a future runner measured the value.
    """
    _require(isinstance(test_id, str) and bool(_TEST_ID.fullmatch(test_id)),
             "invalid benchmark test ID")
    _require(isinstance(execution_status, BenchmarkExecutionStatus),
             "execution status must belong to benchmark domain")
    cfg = _parameters(parameters)
    measured = _metrics(metrics)
    refs = _evidence([] if evidence is None else evidence)
    note = _safe_text(reason, optional=True)
    provenance = _tool(tool)
    if fixture_id is not None:
        _require(isinstance(fixture_id, str) and bool(_TOKEN.fullmatch(fixture_id)),
                 "fixture ID must be a safe identifier")
    if log_ref is not None:
        _require(isinstance(log_ref, str) and bool(_LOG.fullmatch(log_ref))
                 and ".." not in log_ref, "diagnostic log reference is unsafe")
    if execution_status is BenchmarkExecutionStatus.COMPLETE:
        _require(bool(measured) and bool(cfg) and bool(refs)
                 and provenance is not None,
                 "COMPLETE requires observed metrics, configuration, evidence and tool")
        _require(not note, "successful measurement cannot carry an error reason")
    else:
        _require(bool(note), "non-COMPLETE benchmark requires safe reason")
        _require(not measured, "incomplete benchmark cannot claim final metrics")
    record = {
        "test_id": test_id,
        "execution_status": execution_status.value,
        "parameters": cfg,
        "metrics": measured,
        "reason": note,
        "evidence": refs,
    }
    if provenance is not None:
        record["tool"] = provenance
    if fixture_id is not None:
        record["fixture_id"] = fixture_id
    if log_ref is not None:
        record["log_ref"] = log_ref
    # Make the strict JSON boundary explicit rather than just trusting the
    # original object. Serialization never reads files or runs tools.
    try:
        return json.loads(json.dumps(record, allow_nan=False))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise BenchmarkContractError("benchmark record not strict JSON") from exc


def validate_benchmark_record(record: dict) -> None:
    """Validate a previously serialized benchmark-domain record.

    The calling reader establishes the benchmark domain via the record schema;
    raw text statuses from collector/validation objects are never auto-coerced.
    """
    _require(isinstance(record, dict)
             and _REQUIRED_FIELDS.issubset(record)
             and set(record).issubset(_REQUIRED_FIELDS | _OPTIONAL_FIELDS),
             "unrecognized benchmark record schema")
    label = record["execution_status"]
    _require(isinstance(label, str) and label in {
        item.value for item in BenchmarkExecutionStatus
    }, "invalid benchmark execution label")
    typed = BenchmarkExecutionStatus(label)
    normalized = normalize_benchmark_result(
        record["test_id"], typed,
        parameters=record["parameters"], metrics=record["metrics"],
        reason=record["reason"], evidence=record["evidence"],
        tool=record.get("tool"), fixture_id=record.get("fixture_id"),
        log_ref=record.get("log_ref"),
    )
    _require(normalized == record, "benchmark record failed canonical validation")
