"""G5-04 private canonical-session materialization from ONE completed IC-02 run.

No host probing, CLI report generation, source re-execution, or privacy policy
evaluation occurs here. This deliberately conservative first normalizer
preserves each acquired artifact as a raw original observation. UTF-8 is
preserved as typed literal text when reasonably bounded; all other values use
a lossless sealed-byte reference and explicitly record the absence of parsing.
It never infers a semantic datum or benchmark result from raw inventory bytes.

The manifest is committed last. Without an independently verified manifest,
a run is not a validated canonical session, even if some private files exist.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .canonical_contract import (
    CANONICAL_SCHEMA_VERSION, CanonicalContractError,
    new_status, validate_status_record,
)
from .catalog import initial_catalog
from .normalization import (normalize_sealed_source, parser_available,
                            SourceParseError, dmi_field_from_source_path)
from .safety import initial_source_policies, valid_run_id

PRIVATE_FILES = ("system.json", "source_attempts.json", "status_records.json")
MANIFEST_NAME = "session_manifest.json"
MAX_LITERAL_TEXT = 262144  # larger text remains a byte-exact sealed reference
MAX_RECEIPT_BYTES = 256 * 1024


def _check_private_dir(path):
    st = os.lstat(path)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o077):
        raise CanonicalContractError("private directory unsafe")
    return path


def _check_run(path, run_id):
    if not valid_run_id(run_id) or path.name != run_id:
        raise CanonicalContractError("invalid acquisition run identity")
    if not path.is_absolute() or os.path.realpath(path) != str(path):
        raise CanonicalContractError("run location must be absolute and non-symlink")
    _check_private_dir(path)
    _check_private_dir(path / "private")
    _check_private_dir(path / "private" / "source_attempt_records")
    # Denied-only and zero-observation runs need not have an evidence folder.
    if os.path.lexists(path / "private" / "evidence"):
        _check_private_dir(path / "private" / "evidence")


def _read_restricted(path, ceiling):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_mode & 0o077 or st.st_size > ceiling):
            raise CanonicalContractError("unsafe or oversize private file")
        blocks = []
        remaining = ceiling + 1
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                break
            blocks.append(part)
            remaining -= len(part)
        raw = b"".join(blocks)
        if len(raw) > ceiling or len(raw) != st.st_size:
            raise CanonicalContractError("invalid private file size")
        return raw
    finally:
        os.close(fd)


def _json_load(raw):
    def strict_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CanonicalContractError("duplicate JSON field")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=strict_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              CanonicalContractError("non-finite JSON number")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanonicalContractError("malformed private JSON") from exc


def _render(obj):
    return (json.dumps(obj, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def _atomic_new_private(private, name, raw):
    if name not in PRIVATE_FILES + (MANIFEST_NAME,):
        raise CanonicalContractError("unexpected canonical filename")
    directory = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    staging = ".pending-" + secrets.token_hex(12)
    fd = None
    try:
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short canonical write")
            view = view[count:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        # EXCL hard-link publish cannot replace another committed record.
        os.link(staging, name, src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False)
        os.fsync(directory)
        os.unlink(staging, dir_fd=directory)
        os.fsync(directory)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def _artifacts(recorded):
    outcome = recorded.outcome
    if isinstance(outcome, dict):
        return tuple(outcome.get("receipts", ()))
    if hasattr(outcome, "stdout"):
        return tuple(x for x in (outcome.stdout, outcome.stderr) if x is not None)
    return tuple(getattr(outcome, "artifacts", ()) or ())



def _verified_dmi_paths(metadata, artifacts, policy):
    """Bind each sealed SRC-04 item to the *recorded* worker source-path slot.

    G5-03 stores successful worker source_paths in receipt order, while the
    evidence writer seals successful items as item0001..itemNNNN. Missing
    optional attributes do not create evidence items. Fail closed if the
    receipt cannot prove an unambiguous monotonic mapping. No host probing.
    """
    paths = metadata.get("source_paths")
    if type(paths) is not list or len(paths) != len(artifacts):
        raise CanonicalContractError("DMI path and artifact counts disagree")
    if len(paths) > policy.max_entries:
        raise CanonicalContractError("DMI source path count exceeds approved bound")
    fields = []
    for index, (path, artifact) in enumerate(zip(paths, artifacts), 1):
        if artifact.artifact != "item" + format(index, "04d"):
            raise CanonicalContractError("DMI sealed artifact ordinal mismatch")
        field = dmi_field_from_source_path(path)
        if field is None:
            raise CanonicalContractError("DMI source path not approved")
        fields.append(field)
    if fields != sorted(set(fields)):
        raise CanonicalContractError("DMI source path duplicate or ambiguous order")
    return tuple(paths)


def _status_for(receipt, artifacts, *, parser_state="NOT_RUN"):
    """A status needs actual factual source and parser evidence.

    A captured source without a parser cannot be finalized as acquisition
    COMPLETE, PARTIAL/PARSE_FAILED or SOURCE_INCOMPLETE. Fail closed.
    """
    if parser_state not in ("NOT_RUN", "OK", "FAILED"):
        raise CanonicalContractError("invalid parser disposition")
    state, reason = receipt["outcome"], receipt["reason"]
    if state == "CAPTURED":
        if reason != "BYTES_PRESERVED":
            raise CanonicalContractError("captured source has unapproved reason")
        if not artifacts or parser_state == "NOT_RUN":
            raise CanonicalContractError("captured source has no supported parser result")
        if parser_state == "FAILED":
            return "PARTIAL", "PARSE_FAILED"
        return "COMPLETE", "OK"
    if state == "PARTIAL":
        if receipt["capture_limited"] or reason in ("CAPTURE_LIMIT", "TIME_BUDGET_EXCEEDED"):
            return "PARTIAL", "CAPTURE_LIMIT"
        if reason == "EVIDENCE_PERSIST_FAILED":
            return "PARTIAL", "EVIDENCE_INCOMPLETE"
        if reason == "SOURCE_INCOMPLETE":
            return "PARTIAL", "SOURCE_INCOMPLETE"
        raise CanonicalContractError("unclassified partial-source reason")
    if state == "DENIED" and reason == "OPERATOR_AUTH_REQUIRED":
        return "UNAUTHORIZED", "OPERATOR_AUTH_REQUIRED"
    if state == "DENIED" and reason == "ACCESS_DENIED":
        return "PERMISSION_DENIED", "ACCESS_DENIED"
    if state == "UNAVAILABLE":
        if reason in ("TOOL_MISSING", "EXECUTABLE_NOT_FOUND",
                      "PYTHON3_NOT_FOUND"):
            return "TOOL_MISSING", "EXECUTABLE_NOT_FOUND"
        if reason in ("NO_RELEVANT_DEVICE", "NOT_APPLICABLE"):
            return "NOT_APPLICABLE", "NO_RELEVANT_DEVICE"
        if reason == "SOURCE_ABSENT":
            return "UNAVAILABLE", "SOURCE_ABSENT"
        raise CanonicalContractError("unclassified unavailable-source reason")
    if state == "FAILED":
        if reason == "EVIDENCE_PERSIST_FAILED":
            return "FAILED", "EVIDENCE_PERSIST_FAILED"
        if reason == "TIME_BUDGET_EXCEEDED":
            return "FAILED", "TIME_BUDGET_EXCEEDED"
        if reason == "ACQUISITION_ERROR":
            return "FAILED", "ACQUISITION_ERROR"
    # Unknown source transport reasons do not prove a failure category.
    raise CanonicalContractError("unclassified source outcome/reason; refuse final status")


def _observation(artifact, raw, attempt_id, *, status_record_id,
                 parser_findings=None, limitations=None):
    try:
        if len(raw) > MAX_LITERAL_TEXT:
            raise UnicodeDecodeError("utf-8", raw, 0, 1, "literal size bound")
        literal = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        literal = None
    return {
        "observation_id": "obs:" + artifact.evidence_id,
        "collector_id": artifact.collector_id,
        "status_record_id": status_record_id,
        "datum_path": "unclassified.source." + artifact.source_id + "." + artifact.artifact,
        "instance_key": artifact.evidence_id,
        "ordinal": 0,
        "observed_value": literal if literal is not None else {"sealed_bytes_ref": artifact.evidence_id},
        "normalized_value": None,
        "value_type": "STRING" if literal is not None else "BYTES_REF",
        "unit": None,
        "evidence_refs": [artifact.evidence_id],
        "source_attempt_ids": [attempt_id],
        "transformation_ids": [],
        "acquired_utc": None,
        "capture_limit_ids": [],
        "parser_findings": list(parser_findings if parser_findings is not None
                                else ("UNPARSED_SOURCE_ARTIFACT",)),
        "limitations": list(limitations if limitations is not None
                            else ("Source-specific semantic normalization not yet implemented",)),
    }


def _semantic_observation(artifact, attempt_id, datum, index, parser_id):
    """One typed observation derived from a precisely identified sealed original."""
    return {
        "observation_id": "obs:" + artifact.evidence_id + ":sem:" + str(index),
        "collector_id": artifact.collector_id,
        "status_record_id": "st:" + attempt_id,
        "datum_path": datum.datum_path,
        "instance_key": artifact.evidence_id,
        "ordinal": index,
        "observed_value": datum.observed_value,
        "normalized_value": datum.normalized_value,
        "value_type": datum.value_type,
        "unit": datum.unit,
        "evidence_refs": [artifact.evidence_id],
        "source_attempt_ids": [attempt_id],
        "transformation_ids": [parser_id],
        "acquired_utc": None,
        "capture_limit_ids": [],
        "parser_findings": ["SOURCE_PARSER_SUCCEEDED"],
        "limitations": [],
    }


def build_canonical(run_directory, engine_run):
    """Commit private G5-04 records from a completed G5-03 EngineRun.

    Returns a restricted manifest after verifying all files and same-run
    provenance. Never calls an adapter, executable, or legacy collector.
    """
    folder = Path(run_directory)
    run_id = engine_run.run_id
    _check_run(folder, run_id)
    if engine_run.canonical_status_pending is not True:
        raise CanonicalContractError("unexpected engine canonical state")
    if (folder / "private" / MANIFEST_NAME).exists():
        raise FileExistsError("canonical session already finalized")
    private = folder / "private"
    policies = {p.source_id: p for p in initial_source_policies()}
    attempted = set()
    evidence = {}
    observations = []
    attempts = []
    statuses = []
    limits = []
    all_attempt_ids = set()
    source_ids = set()
    all_original_bytes = 0
    semantic_field_count = 0
    all_attempts = [item for collector in engine_run.collectors
                    for item in collector.source_attempts]
    for item in all_attempts:
        receipt_path = item.receipt_private_path
        if (type(receipt_path) is not str or not re.fullmatch(
                r"private/source_attempt_records/SRC-[0-9]{2,}-[0-9]{2,}\.json",
                receipt_path)):
            raise CanonicalContractError("invalid receipt location")
        receipt_raw = _read_restricted(folder / receipt_path, MAX_RECEIPT_BYTES)
        metadata = _json_load(receipt_raw)
        source_id = metadata.get("source_id")
        policy = policies.get(source_id)
        attempt_id = metadata.get("attempt_id")
        if (policy is None or metadata.get("run_id") != run_id
                or metadata.get("collector_id") != policy.collector_id
                or metadata.get("operation_id") != policy.operation_id
                or metadata.get("authorization_class") != policy.authorization_class
                or receipt_path != "private/source_attempt_records/" + attempt_id + ".json"
                or attempt_id in attempted):
            raise CanonicalContractError("invalid/duplicate source receipt")
        attempted.add(attempt_id)
        all_attempt_ids.add(attempt_id)
        source_ids.add(source_id)
        artifacts = _artifacts(item)
        if metadata.get("evidence_ids") != [x.evidence_id for x in artifacts]:
            raise CanonicalContractError("receipt and engine evidence disagree")
        if metadata.get("acquired_bytes") != sum(x.byte_count for x in artifacts):
            raise CanonicalContractError("receipt byte count mismatch")
        dmi_paths = (_verified_dmi_paths(metadata, artifacts, policy)
                     if source_id == "SRC-04" else ())
        linked = []
        parser_executions = 0
        parser_failures = []
        for artifact_index, artifact in enumerate(artifacts, 1):
            eid = artifact.evidence_id
            if (eid in evidence or artifact.run_id != run_id
                    or artifact.source_id != source_id
                    or artifact.collector_id != policy.collector_id
                    or artifact.attempt != attempt_id.rsplit("-", 1)[-1]
                    or eid != (run_id + "_" + policy.collector_id + "_" +
                               source_id + "_" + artifact.attempt + ":" +
                               artifact.artifact)
                    or artifact.private_relative_path != "private/evidence/" + eid
                    or not re.fullmatch(r"[a-f0-9]{64}", artifact.sha256)
                    or type(artifact.byte_count) is not int
                    or artifact.byte_count < 0 or artifact.byte_count > policy.max_bytes):
                raise CanonicalContractError("invalid/duplicate sealed artifact reference")
            raw = _read_restricted(folder / artifact.private_relative_path,
                                   artifact.byte_count)
            if (len(raw) != artifact.byte_count or
                    hashlib.sha256(raw).hexdigest() != artifact.sha256):
                raise CanonicalContractError("original evidence integrity failure")
            all_original_bytes += artifact.byte_count
            evidence[eid] = {
                "evidence_id": eid, "source_attempt_id": attempt_id,
                "private_relative_path": artifact.private_relative_path,
                "sha256": artifact.sha256, "byte_count": artifact.byte_count,
                "complete": artifact.complete,
                "limit_applied": artifact.limit_applied,
                "omitted_at_least": artifact.omitted_at_least,
            }
            # Invoke a registered parser ONLY on already sealed, hash-checked bytes.
            # Unknown families remain original evidence, but their captured data
            # cannot masquerade as a finalized canonical acquisition status.
            parsed = None
            error = None
            if metadata["outcome"] in ("CAPTURED", "PARTIAL") and parser_available(source_id):
                parser_executions += 1
                try:
                    parsed = normalize_sealed_source(
                        source_id, raw,
                        source_path=(dmi_paths[artifact_index - 1]
                                     if source_id == "SRC-04" else None))
                except SourceParseError as exc:
                    error = str(exc)[:128]
                    parser_failures.append(error)
            if parsed is not None:
                observations.append(_observation(
                    artifact, raw, attempt_id, status_record_id="st:" + attempt_id,
                    parser_findings=("ORIGINAL_PRESERVED", "SOURCE_PARSER_SUCCEEDED"),
                    limitations=()))
                for index, datum in enumerate(parsed.values):
                    observations.append(_semantic_observation(
                        artifact, attempt_id, datum, index, parsed.parser_id))
                    semantic_field_count += 1
            else:
                observations.append(_observation(
                    artifact, raw, attempt_id, status_record_id="st:" + attempt_id,
                    parser_findings=(("PARSER_FAILED:" + error,) if error else
                                     ("PARSER_NOT_AVAILABLE",)),
                    limitations=(("SOURCE_PARSER_ERROR:" + error,) if error else
                                 ("Semantic parser not implemented for source",))))
            linked.append(eid)
        if parser_executions:
            parser_state = "FAILED" if parser_failures else "OK"
        else:
            parser_state = "NOT_RUN"
        status, reason = _status_for(metadata, artifacts, parser_state=parser_state)
        status_id = "st:" + attempt_id
        if (metadata.get("capture_limited") or any(x.limit_applied for x in artifacts)):
            limit_id = "limit:" + attempt_id
            limits.append({
                "limit_id": limit_id, "source_attempt_id": attempt_id,
                "approved_rule_id": "G4-07:" + source_id,
                "threshold": policy.max_bytes, "unit": "bytes",
                "observed_extent": metadata["acquired_bytes"],
                "missing_extent": metadata.get("missing_extent_known_at_least"),
                "affected_scope": source_id,
                "reason": metadata["reason"],
            })
        else:
            limit_id = None
        statuses.append(new_status(
            record_id=status_id, domain="acquisition",
            component_id=policy.collector_id, subject_id=source_id,
            status=status, reason_code=reason,
            detail=("transport=" + str(metadata["outcome"]) +
                    "/" + str(metadata["reason"]) +
                    (("; parser_errors=" + ",".join(parser_failures))
                     if parser_failures else ("; parser=verified" if parser_executions else
                                              "; parser=not-run")))[:1024],
            evidence_refs=linked, source_attempt_ids=[attempt_id],
            limit_record_ids=([limit_id] if limit_id else [])))
        attempts.append({
            "attempt_id": attempt_id, "receipt_private_path": receipt_path,
            "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "receipt_byte_count": len(receipt_raw),
            "source_id": source_id, "collector_id": policy.collector_id,
            "source_disposition": metadata["outcome"],
            "source_reason": metadata["reason"],
            "evidence_ids": linked, "status_record_id": status_id,
            "authorization_class": policy.authorization_class,
            "capture_bytes": metadata["acquired_bytes"],
            "capture_limited": metadata.get("capture_limited", False),
            "errors": metadata.get("errors", []),
            "unavailable_fields": metadata.get("unavailable_fields", []),
        })
    if engine_run.source_attempt_count != len(attempts):
        raise CanonicalContractError("engine attempt count mismatch")
    if any(a["source_id"] not in source_ids for a in attempts):
        raise CanonicalContractError("invalid source allocation")
    orchestrated_state = "PARTIAL"
    orchestrated_reason = "MINIMUM_WITH_GAPS"
    statuses.append(new_status(
        record_id="st:session", domain="orchestration",
        component_id="SES-CANONICAL", subject_id=run_id,
        status=orchestrated_state, reason_code=orchestrated_reason,
        detail=("Raw originals validated; semantic normalization incomplete; " +
                str(len(observations)) + " raw observations; " +
                str(len(attempts)) + " source attempts")[:1024],
        evidence_refs=[], source_attempt_ids=sorted(all_attempt_ids)))
    system = {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "run_id": run_id,
        "platform_scope": "Linux-AMD64",
        "normalization_state": ("PARTIAL_SEMANTIC_NORMALIZATION"
                                if semantic_field_count else "RAW_FALLBACK_ONLY"),
        "observations": observations,
        "capture_limits": limits,
        "limitations": ["Canonical schema/integrity completion pending CP-04",
                        "Semantic source coverage is restricted to SRC-02 and SRC-08..SRC-10",
                        "Zero observations permitted; no benchmark measurements inferred"],
    }
    outputs = {
        "system.json": system,
        "source_attempts.json": {
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "run_id": run_id, "attempts": attempts,
        },
        "status_records.json": {
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "run_id": run_id, "status_records": statuses,
        },
    }
    # Validate before any file is written.
    for status in statuses:
        validate_status_record(status, evidence_ids=evidence,
                               attempt_ids=all_attempt_ids,
                               limit_ids={x["limit_id"] for x in limits})
    serialized = {name: _render(payload) for name, payload in outputs.items()}
    manifest = {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "run_id": run_id,
        "completion_state": "INCOMPLETE",
        "integrity_verified": True,
        "semantic_normalization_complete": False,
        "observation_count": len(observations),
        "attempt_count": len(attempts),
        "source_count": len(source_ids),
        "original_byte_count": all_original_bytes,
        "files": {name: {"sha256": hashlib.sha256(raw).hexdigest(),
                         "byte_count": len(raw)}
                  for name, raw in serialized.items()},
        "evidence": evidence,
        "status_record_ids": [x["record_id"] for x in statuses],
        "limitations": system["limitations"],
    }
    for name in PRIVATE_FILES:
        _atomic_new_private(private, name, serialized[name])
    _atomic_new_private(private, MANIFEST_NAME, _render(manifest))
    validate_canonical(folder)
    return manifest


def validate_canonical(run_directory):
    """Read-only verification of private files, references and sealed bytes."""
    folder = Path(run_directory)
    run_id = folder.name
    _check_run(folder, run_id)
    private = folder / "private"
    manifest = _json_load(_read_restricted(private / MANIFEST_NAME, 8 * 1024 * 1024))
    if (manifest.get("schema_version") != CANONICAL_SCHEMA_VERSION
            or manifest.get("run_id") != run_id
            or manifest.get("integrity_verified") is not True
            or set(manifest.get("files", {})) != set(PRIVATE_FILES)):
        raise CanonicalContractError("invalid session manifest")
    records = {}
    for name in PRIVATE_FILES:
        file_info = manifest["files"][name]
        raw = _read_restricted(private / name, 64 * 1024 * 1024)
        if (len(raw) != file_info.get("byte_count")
                or hashlib.sha256(raw).hexdigest() != file_info.get("sha256")):
            raise CanonicalContractError("canonical file integrity failure")
        records[name] = _json_load(raw)
        if (records[name].get("run_id") != run_id
                or records[name].get("schema_version") != CANONICAL_SCHEMA_VERSION):
            raise CanonicalContractError("canonical file identity mismatch")
    attempts = records["source_attempts.json"]["attempts"]
    statuses = records["status_records.json"]["status_records"]
    observations = records["system.json"]["observations"]
    evidence = manifest["evidence"]
    if (len(attempts) != manifest["attempt_count"]
            or len(observations) != manifest["observation_count"]
            or len({a["attempt_id"] for a in attempts}) != len(attempts)
            or len({s["record_id"] for s in statuses}) != len(statuses)):
        raise CanonicalContractError("invalid canonical entity counts")
    attempt_ids = {a["attempt_id"] for a in attempts}
    for eid, record in evidence.items():
        if (record["evidence_id"] != eid or
                record["source_attempt_id"] not in attempt_ids
                or record["private_relative_path"] != "private/evidence/" + eid):
            raise CanonicalContractError("manifest evidence binding invalid")
        raw = _read_restricted(folder / record["private_relative_path"],
                               record["byte_count"])
        if (hashlib.sha256(raw).hexdigest() != record["sha256"] or
                len(raw) != record["byte_count"]):
            raise CanonicalContractError("sealed original altered")
    limits = {x["limit_id"] for x in records["system.json"]["capture_limits"]}
    for status in statuses:
        validate_status_record(status, evidence_ids=evidence,
                               attempt_ids=attempt_ids, limit_ids=limits)
    for a in attempts:
        receipt_path = a.get("receipt_private_path")
        if receipt_path != ("private/source_attempt_records/" + a["attempt_id"] + ".json"):
            raise CanonicalContractError("attempt receipt path invalid")
        receipt_raw = _read_restricted(folder / receipt_path,
                                       a["receipt_byte_count"])
        if (len(receipt_raw) != a["receipt_byte_count"]
                or hashlib.sha256(receipt_raw).hexdigest() != a["receipt_sha256"]):
            raise CanonicalContractError("original source attempt receipt altered")
        receipt_record = _json_load(receipt_raw)
        if (receipt_record.get("run_id") != run_id
                or receipt_record.get("attempt_id") != a["attempt_id"]
                or receipt_record.get("source_id") != a["source_id"]
                or receipt_record.get("evidence_ids") != a["evidence_ids"]
                or receipt_record.get("acquired_bytes") != a["capture_bytes"]):
            raise CanonicalContractError("source receipt/canonical disagreement")
        if a["status_record_id"] not in {x["record_id"] for x in statuses}:
            raise CanonicalContractError("dangling status reference")
        if any(e not in evidence or evidence[e]["source_attempt_id"] != a["attempt_id"]
               for e in a["evidence_ids"]):
            raise CanonicalContractError("attempt evidence provenance failure")
    for observation in observations:
        if (not observation["evidence_refs"]
                or not observation["source_attempt_ids"]
                or any(e not in evidence for e in observation["evidence_refs"])
                or any(a not in attempt_ids for a in observation["source_attempt_ids"])
                or any(evidence[e]["source_attempt_id"] not in
                       observation["source_attempt_ids"] for e in observation["evidence_refs"])):
            raise CanonicalContractError("observation provenance failure")
    return manifest
