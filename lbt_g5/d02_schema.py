"""Closed-world private D-02 v1.0.0 *shape* contract, approved CP-01 §6.

Authority: CP-01 D-01..D-05 approved Nov 2, 2026. Exact source ODT
SHA256: 6d836d28af086a0fec7df2ca0949faf9447f9cee29cfabb8751344bd5104c98b.
This is a pure, bounded schema shape/type validator. It does not acquire data,
change the source protocol, check cross-file digests, claim provenance, or
establish session completeness. Those gates remain separate.
"""
from datetime import datetime
import math
import re

from .canonical_contract import (
    CANONICAL_SCHEMA_VERSION, STATUS_SCHEMA_VERSION,
    STATUS_PAIRS, STATUS_FIELDS, CanonicalContractError,
)

def _fields(source):
    """Parse the exact annex notation into ordered field -> type strings."""
    parts = [part.strip() for part in source.split(",")]
    return dict(part.split(":", 1) for part in parts)

D02_FILES = {
    "system.json": _fields(
        "schema_version:str,run_id:str,header:SessionHeader,"
        "observations:list[CanonicalObservation],capture_limits:list[CaptureLimit],"
        "limitations:list[str]"),
    "source_attempts.json": _fields(
        "schema_version:str,run_id:str,attempts:list[SourceAttempt]"),
    "status_records.json": _fields(
        "schema_version:str,run_id:str,status_records:list[StatusRecord]"),
    "session_manifest.json": _fields(
        "schema_version:str,manifest_version:str,run_id:str,completion_state:enum,"
        "integrity_verified:bool,minimum_usable:bool,finalized_utc:utc?,counts:Counts,"
        "files:map[FileDigest],evidence:map[EvidenceArtifact],"
        "source_receipts:map[ReceiptDigest],observation_ids:list[str],"
        "source_attempt_ids:list[str],status_record_ids:list[str],"
        "limit_record_ids:list[str],limitations:list[str]"),
}

D02_ENTITIES = {
    "SessionHeader": _fields(
        "started_utc:utc?,completed_utc:utc?,platform_scope:str,requested_mode:str,"
        "lifecycle_state:enum,collector_ids:list[str],created_by_version:str?"),
    "SourceAttempt": _fields(
        "attempt_id:str,source_id:str,collector_id:str,operation_id:str,"
        "authorization_class:enum,authorization_decision:enum,operator_consent:map?,"
        "invocation:map,safety_bounds:list[str],started_utc:utc?,"
        "completed_utc:utc?,elapsed_ms:int?,tool_version:str?,exit_code:int?,"
        "errno:str?,capture_bytes:int>=0,evidence_ids:list[str],"
        "status_record_id:str,limit_record_ids:list[str],receipt_private_path:str,"
        "receipt_sha256:hash64,receipt_byte_count:int>=0,errors:list[str],"
        "unavailable_fields:list[str]"),
    "EvidenceArtifact": _fields(
        "evidence_id:str,source_attempt_id:str,representation:enum,"
        "restricted_relative_path:str,sha256:hash64,byte_count:int>=0,"
        "sealed_utc:utc?,completeness:enum,encoding:str?,limit_record_ids:list[str],"
        "limit_applied:bool,omitted_at_least:int>=0"),
    "CanonicalObservation": _fields(
        "observation_id:str,collector_id:str,datum_path:str,instance_key:str?,"
        "ordinal:int>=0,observed_value:JSON-typed-or-bytes-reference,"
        "normalized_value:JSON-typed?,value_type:enum,unit:str?,"
        "evidence_refs:list[str] (1..N),source_attempt_ids:list[str] (1..N),"
        "transformation_ids:list[str],acquired_utc:utc?,"
        "capture_limit_ids:list[str],status_record_id:str,"
        "parser_findings:list[str],limitations:list[str]"),
    "CaptureLimit": _fields(
        "limit_id:str,source_attempt_id:str,approved_rule_id:str,threshold:number,"
        "unit:str,observed_extent:number?,missing_extent:number?,"
        "affected_scope:str,reason:str"),
    "StatusRecord": _fields(
        "schema_version:str,record_id:str,domain:enum,component_id:str,"
        "subject_id:str,status:enum,reason_code:enum,detail:str,"
        "started_utc:utc?,completed_utc:utc?,elapsed_ms:int?,"
        "evidence_refs:list[str],limit_record_ids:list[str],"
        "source_attempt_ids:list[str]"),
    "Counts": _fields(
        "attempts:int>=0,sources:int>=0,observations:int>=0,"
        "evidence_artifacts:int>=0,original_bytes:int>=0,"
        "statuses:int>=0,capture_limits:int>=0"),
    "FileDigest": _fields("sha256:hash64,byte_count:int>=0"),
    "ReceiptDigest": _fields(
        "sha256:hash64,byte_count:int>=0,attempt_id:str,"
        "restricted_relative_path:str"),
}

_ENUMS = {
    ("SessionHeader","lifecycle_state"): frozenset((
        "ALLOCATED", "ACQUIRING", "CANONICAL_PENDING", "COMMITTED",
        "INCOMPLETE", "INTERRUPTED", "FAILED")),
    ("SourceAttempt","authorization_class"): frozenset(("D0","D1","O1")),
    ("SourceAttempt","authorization_decision"): frozenset((
        "ALLOW","DENY","NOT_APPLICABLE")),
    ("EvidenceArtifact","representation"): frozenset((
        "FILE_BYTES","STDOUT","STDERR","API_SNAPSHOT")),
    ("EvidenceArtifact","completeness"): frozenset(("COMPLETE","INCOMPLETE")),
    ("CanonicalObservation","value_type"): frozenset((
        "STRING","INTEGER","NUMBER","BOOLEAN","OBJECT","ARRAY","BYTES_REF","NULL")),
    ("session_manifest.json","completion_state"): frozenset((
        "COMPLETE","PARTIAL","INCOMPLETE","INTERRUPTED","FAILED")),
}

def _valid_json(value):
    """JSON values including unknown acquired datum payloads, but not NaN/Inf."""
    if value is None or type(value) in (str, bool, int):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return all(_valid_json(v) for v in value)
    if type(value) is dict:
        return all(type(k) is str and _valid_json(v) for k,v in value.items())
    return False

def _utc(value):
    if type(value) is not str:
        return False
    if not (value.endswith("Z") or value.endswith("+00:00")):
        return False
    try:
        parsed = datetime.fromisoformat(
            value[:-1]+"+00:00" if value.endswith("Z") else value)
        return (parsed.tzinfo is not None
                and parsed.utcoffset().total_seconds()==0)
    except (ValueError, OverflowError):
        return False

def _validate(name, obj, fields):
    if type(obj) is not dict or set(obj) != set(fields):
        raise CanonicalContractError("D-02 closed-world field mismatch: " + name)
    for field, spec in fields.items():
        _value(name, field, spec, obj[field])
    return obj

def _value(owner, field, spec, value):
    if spec.endswith("?"):
        if value is None:
            return
        spec = spec[:-1]
    if spec.endswith(" (1..N)"):
        required = True
        spec = spec[:-len(" (1..N)")]
    else:
        required = False
    valid = False
    if spec == "str":
        valid = type(value) is str and bool(value)
    elif spec == "utc":
        valid = _utc(value)
    elif spec == "int":
        valid = type(value) is int
    elif spec == "int>=0":
        valid = type(value) is int and value>=0
    elif spec == "bool":
        valid = type(value) is bool
    elif spec == "number":
        valid = type(value) in (int,float) and math.isfinite(value)
    elif spec == "hash64":
        valid = type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    elif spec == "enum":
        allowed = _ENUMS.get((owner,field))
        if allowed is None and owner=="StatusRecord" and field in (
                "domain","status","reason_code"):
            valid = type(value) is str and bool(value)
        else:
            valid = allowed is not None and type(value) is str and value in allowed
    elif spec in ("JSON-typed","JSON-typed-or-bytes-reference"):
        valid = _valid_json(value)
    elif spec == "map":
        valid = type(value) is dict and _valid_json(value)
    elif spec.startswith("list[") and spec.endswith("]"):
        item_spec=spec[5:-1]
        valid = type(value) is list and (not required or len(value)>0)
        if valid:
            for child in value:
                if item_spec in D02_ENTITIES:
                    validate_d02_entity(item_spec,child)
                else:
                    _value(owner,field,item_spec,child)
    elif spec.startswith("map[") and spec.endswith("]"):
        item_spec=spec[4:-1]
        valid = type(value) is dict and all(
            type(k) is str and bool(k) for k in value)
        if valid:
            for child in value.values():
                validate_d02_entity(item_spec,child)
    elif spec in D02_ENTITIES:
        validate_d02_entity(spec,value)
        valid=True
    if not valid:
        raise CanonicalContractError(
            "D-02 field type/enum invalid: " + owner + "." + field)

def validate_d02_entity(name, record):
    """Validate one exact approved entity, including status vocabulary."""
    definition=D02_ENTITIES.get(name)
    if definition is None:
        raise CanonicalContractError("unknown D-02 entity")
    _validate(name,record,definition)
    if name=="StatusRecord":
        if record["schema_version"]!=STATUS_SCHEMA_VERSION or (
            record["domain"],record["status"],record["reason_code"]) not in STATUS_PAIRS:
            raise CanonicalContractError("D-02 invalid 1.0 status record or 41-pair key")
        if set(record)!=set(STATUS_FIELDS):
            raise CanonicalContractError("D-02 status-record field mismatch")
    return record

def validate_d02_file(filename,record):
    """Validate exact file/entity shape and types; cross-file refs are separate."""
    fields=D02_FILES.get(filename)
    if fields is None:
        raise CanonicalContractError("unknown D-02 file")
    _validate(filename,record,fields)
    if record["schema_version"]!=CANONICAL_SCHEMA_VERSION:
        raise CanonicalContractError("D-02 canonical schema version mismatch")
    return record
