"""G5-04 strict private status-record contract; no source reads or publication.

This forward G4-02/G4-06 vocabulary retains the 40 historical combinations
and adds only the separately owner-approved publication field-withholding pair.
The common 14-field envelope is distinct from the canonical schema version.
"""
from datetime import datetime, timezone
import re

CANONICAL_SCHEMA_VERSION = "1.0.0"
STATUS_SCHEMA_VERSION = "1.0"
STATUS_FIELDS = (
    "schema_version", "record_id", "domain", "component_id", "subject_id",
    "status", "reason_code", "detail", "started_utc", "completed_utc",
    "elapsed_ms", "evidence_refs", "limit_record_ids", "source_attempt_ids",
)
# Exactly 41 controlled (domain, status, reason) combinations.
STATUS_PAIRS = frozenset((
    ("acquisition", "COMPLETE", "OK"),
    ("acquisition", "PARTIAL", "CAPTURE_LIMIT"),
    ("acquisition", "PARTIAL", "SOURCE_INCOMPLETE"),
    ("acquisition", "PARTIAL", "PARSE_FAILED"),
    ("acquisition", "PARTIAL", "EVIDENCE_INCOMPLETE"),
    ("acquisition", "PARTIAL", "DEPENDENCY_MISSING"),
    ("acquisition", "UNAVAILABLE", "SOURCE_ABSENT"),
    ("acquisition", "UNSUPPORTED", "CAPABILITY_UNSUPPORTED"),
    ("acquisition", "PERMISSION_DENIED", "ACCESS_DENIED"),
    ("acquisition", "TOOL_MISSING", "EXECUTABLE_NOT_FOUND"),
    ("acquisition", "FAILED", "ACQUISITION_ERROR"),
    ("acquisition", "FAILED", "EVIDENCE_PERSIST_FAILED"),
    ("acquisition", "FAILED", "NORMALIZATION_FAILED"),
    ("acquisition", "NOT_APPLICABLE", "NO_RELEVANT_DEVICE"),
    ("acquisition", "UNAUTHORIZED", "OPERATOR_AUTH_REQUIRED"),
    ("acquisition", "INTERRUPTED", "EXECUTION_INTERRUPTED"),
    ("acquisition", "FAILED", "TIME_BUDGET_EXCEEDED"),
    ("orchestration", "COMPLETE", "ALL_REQUIRED_COMPLETE"),
    ("orchestration", "PARTIAL", "MINIMUM_WITH_GAPS"),
    ("orchestration", "FAILED", "NO_VALID_MINIMUM"),
    ("orchestration", "FAILED", "SESSION_PERSIST_FAILED"),
    ("orchestration", "INTERRUPTED", "RUN_INTERRUPTED"),
    ("benchmark", "COMPLETE", "MEASUREMENT_RECORDED"),
    ("benchmark", "SKIPPED", "NOT_REQUESTED"),
    ("benchmark", "SKIPPED", "OPERATOR_EXCLUDED"),
    ("benchmark", "UNAVAILABLE", "PREREQUISITE_MISSING"),
    ("benchmark", "FAILED", "EXECUTION_ERROR"),
    ("benchmark", "FAILED", "INVALID_MEASUREMENT"),
    ("benchmark", "INTERRUPTED", "EXECUTION_INTERRUPTED"),
    ("validation", "PASS", "ASSERTIONS_PASSED"),
    ("validation", "FAIL", "ASSERTION_FAILED"),
    ("validation", "FAIL", "TEST_EXECUTION_ERROR"),
    ("validation", "SKIP", "SELECTED_OUT"),
    ("validation", "BLOCKED", "PREREQUISITE_BLOCKED"),
    ("validation", "NOT_APPLICABLE", "OUT_OF_SCOPE"),
    ("publication", "GENERATED", "OUTPUT_WRITTEN"),
    ("publication", "BLOCKED", "POLICY_INVALID"),
    ("publication", "BLOCKED", "CURRENT_SESSION_INVALID"),
    ("publication", "FAILED", "RENDER_ERROR"),
    ("publication", "FAILED", "OUTPUT_PERSIST_FAILED"),
    ("publication", "BLOCKED", "UNCLASSIFIED_PUBLIC_FIELD"),
))


class CanonicalContractError(ValueError):
    """Malformed or unapproved private canonical/status record."""


def _utc_timestamp(value):
    if value is None:
        return None
    if type(value) is not str or not value.endswith("Z"):
        raise CanonicalContractError("UTC timestamp must end with Z")
    try:
        d = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CanonicalContractError("invalid UTC timestamp") from exc
    if d.tzinfo is None or d.utcoffset().total_seconds() != 0:
        raise CanonicalContractError("timestamp not UTC")
    return d


def _ids(values, field):
    if type(values) is not list or any(
        type(v) is not str or not v or len(v) > 256 for v in values
    ) or len(values) != len(set(values)):
        raise CanonicalContractError("invalid or duplicate " + field)


def validate_status_record(record, *, evidence_ids=None, attempt_ids=None,
                           limit_ids=None):
    """Validate exact envelope, approved domain pair, types and references.

    If reference universes are supplied, every pointer must resolve. No
    assumption about actual collection follows from a valid status envelope.
    """
    if type(record) is not dict or set(record) != set(STATUS_FIELDS):
        raise CanonicalContractError("status envelope must contain exactly 14 fields")
    if record["schema_version"] != STATUS_SCHEMA_VERSION:
        raise CanonicalContractError("unsupported status schema version")
    for field in ("record_id", "component_id", "subject_id"):
        v = record[field]
        if type(v) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", v):
            raise CanonicalContractError("invalid " + field)
    if (record["domain"], record["status"], record["reason_code"]) not in STATUS_PAIRS:
        raise CanonicalContractError("unapproved domain/status/reason pair")
    if type(record["detail"]) is not str or len(record["detail"]) > 1024:
        raise CanonicalContractError("unbounded or invalid status detail")
    start = _utc_timestamp(record["started_utc"])
    end = _utc_timestamp(record["completed_utc"])
    if end is not None and (start is None or end < start):
        raise CanonicalContractError("invalid status timestamp ordering")
    elapsed = record["elapsed_ms"]
    if elapsed is not None and (type(elapsed) is not int or elapsed < 0 or start is None):
        raise CanonicalContractError("invalid elapsed milliseconds")
    for key, universe in (
        ("evidence_refs", evidence_ids),
        ("source_attempt_ids", attempt_ids),
        ("limit_record_ids", limit_ids),
    ):
        _ids(record[key], key)
        if universe is not None and not set(record[key]).issubset(set(universe)):
            raise CanonicalContractError("dangling " + key)
    return record


def new_status(*, record_id, domain, component_id, subject_id, status,
               reason_code, detail="", started_utc=None, completed_utc=None,
               elapsed_ms=None, evidence_refs=(), limit_record_ids=(),
               source_attempt_ids=()):
    item = dict(schema_version=STATUS_SCHEMA_VERSION,
                record_id=record_id, domain=domain, component_id=component_id,
                subject_id=subject_id, status=status, reason_code=reason_code,
                detail=detail, started_utc=started_utc, completed_utc=completed_utc,
                elapsed_ms=elapsed_ms, evidence_refs=list(evidence_refs),
                limit_record_ids=list(limit_record_ids),
                source_attempt_ids=list(source_attempt_ids))
    return validate_status_record(item)
