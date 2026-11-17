"""G5-04 RP-03.2: read-only PRIVATE consumer of an approved D-02 session.

This is an internal, unmasked inventory view, NOT a publication, an HTML
report, a new wire schema, a benchmark claim, or a replacement for the
approved privacy.yaml / outputs.yaml publication boundary. Normalized
facts may themselves contain sensitive host values: do not serialize this
view into public outputs without the separately approved policy.

Only an already acquired, sealed and validated G5-03 EngineRun can supply
facts. The consumer performs no probes, privileged commands or collections.
"""
import hashlib
from pathlib import Path

from .canonical_contract import CanonicalContractError
from .canonical_session import (
    PRIVATE_FILES, _json_load, _read_restricted, validate_canonical,
)


def read_private_inventory(run_directory):
    """Return factual typed values and outcomes from a validated private run.

    A minimum-usable or fully captured source is NOT a successfully finished
    benchmark. Preserve the exact production session lifecycle/status states.
    Raw original payloads stay in sealed private evidence; raw observations,
    evidence IDs, source commands and filesystem paths are not added to this
    intermediary view.
    """
    folder = Path(run_directory)
    manifest = validate_canonical(folder)
    records = {}
    for name in PRIVATE_FILES:
        raw = _read_restricted(folder / "private" / name, 64 * 1024 * 1024)
        digest = manifest["files"][name]
        if (len(raw) != digest["byte_count"]
                or hashlib.sha256(raw).hexdigest() != digest["sha256"]):
            raise CanonicalContractError("private canonical file changed during read")
        records[name] = _json_load(raw)

    system = records["system.json"]
    attempts = records["source_attempts.json"]["attempts"]
    statuses = records["status_records.json"]["status_records"]
    by_status = {s["record_id"]: s for s in statuses}
    by_attempt = {a["attempt_id"]: a for a in attempts}
    session_rows = [s for s in statuses
                    if s["domain"] == "orchestration"
                    and s["subject_id"] == manifest["run_id"]]
    if len(session_rows) != 1:
        raise CanonicalContractError("missing or ambiguous orchestration outcome")
    session = session_rows[0]

    facts = []
    per_source_semantics = {a["attempt_id"]: 0 for a in attempts}
    original_rows = 0
    for row in system["observations"]:
        if not row["transformation_ids"]:
            original_rows += 1
            continue
        # The first contributor is the primary source/attempt for a typed
        # datum; additional originals remain in the D-02 private record.
        primary = row["source_attempt_ids"][0]
        attempt = by_attempt[primary]
        status = by_status[row["status_record_id"]]
        if status["domain"] != "acquisition":
            raise CanonicalContractError("typed observation has no acquisition outcome")
        per_source_semantics[primary] += 1
        facts.append({
            "source_id": attempt["source_id"],
            # Preserve D-02's verified co-contributor source identities
            # without exposing attempt/evidence IDs or restricted paths.
            "supporting_source_ids": [
                by_attempt[aid]["source_id"]
                for aid in row["source_attempt_ids"][1:]
            ],
            "datum_path": row["datum_path"],
            "ordinal": row["ordinal"],
            "observed_value": row["observed_value"],
            "normalized_value": row["normalized_value"],
            "value_type": row["value_type"],
            "unit": row["unit"],
            "acquisition_status": status["status"],
            "acquisition_reason": status["reason_code"],
        })

    sources = []
    for attempt in attempts:
        status = by_status[attempt["status_record_id"]]
        # Retain factual source availability and process disposition for
        # D1/O1 consumers. These are existing approved D-02 private fields,
        # not new producer schema or authorization claims.
        sources.append({
            "source_id": attempt["source_id"],
            "authorization_class": attempt["authorization_class"],
            "authorization_decision": attempt["authorization_decision"],
            "status": status["status"],
            "reason_code": status["reason_code"],
            "semantic_fact_count": per_source_semantics[attempt["attempt_id"]],
            "capture_bytes": attempt["capture_bytes"],
            "exit_code": attempt["exit_code"],
            "unavailable_fields": list(attempt["unavailable_fields"]),
        })

    return {
        "run_id": manifest["run_id"],
        "requested_mode": system["header"]["requested_mode"],
        "lifecycle_state": system["header"]["lifecycle_state"],
        "completion_state": manifest["completion_state"],
        "minimum_usable": manifest["minimum_usable"],
        "orchestration_status": session["status"],
        "orchestration_reason": session["reason_code"],
        "source_outcomes": sources,
        "facts": facts,
        "raw_original_observation_rows": original_rows,
        "sealed_original_artifact_count": manifest["counts"]["evidence_artifacts"],
        "limitations": list(system["limitations"]),
    }
