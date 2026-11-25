"""RP-03.3 owner-approved factual selected-acquisition lifecycle reconciliation.

Pure in-memory runtime witness + existing D-02 acquisition statuses. Does not
run a source, change source authorization, add production fields or infer a
benchmark. The small D-02 orchestration detail carries only intended source
attempt IDs/terminal marker, never raw evidence paths or private receipts.
"""
from datetime import datetime
import re

from .catalog import initial_catalog
from .canonical_contract import CanonicalContractError
from .engine import SessionExecution
from .safety import initial_source_policies

MARKER = "LBT_SESSION_V1;terminal="
_ATTEMPT = re.compile(r"SRC-[0-9]{2,}-[0-9]{2,}$")


def _source_plan(selected_collectors, selected_sources, planned):
    """Verify the approved catalog/ordinal shape of a witnessed source plan."""
    if type(selected_collectors) is not tuple or len(set(selected_collectors)) != len(selected_collectors):
        raise CanonicalContractError("invalid witnessed collector selection")
    _, catalog = initial_catalog()
    order = tuple(dict.fromkeys(x.collector_id for x in catalog))
    if tuple(cid for cid in order if cid in selected_collectors) != selected_collectors:
        raise CanonicalContractError("witnessed collector order not approved")
    expected_sources = tuple(x.source_id for x in catalog if x.collector_id in selected_collectors)
    if type(selected_sources) is not tuple or selected_sources != expected_sources:
        raise CanonicalContractError("witnessed source selection diverges from approved catalog")
    if type(planned) is not tuple or any(type(x) is not str or _ATTEMPT.fullmatch(x) is None for x in planned):
        raise CanonicalContractError("malformed planned attempt identities")
    policies = {p.source_id: p for p in initial_source_policies()}
    cursor = 0
    for sid in expected_sources:
        if policies[sid].authorization_class == "O1":
            count = 0
            while cursor + count < len(planned) and planned[cursor + count].startswith(sid + "-"):
                count += 1
            if not 1 <= count <= policies[sid].max_entries:
                raise CanonicalContractError("out-of-scope O1 planned attempt count")
        else:
            count = 2 if sid == "SRC-23" else 1
        expected = tuple("%s-%02d" % (sid, i + 1) for i in range(count))
        if planned[cursor:cursor+count] != expected:
            raise CanonicalContractError("missing or out-of-order source plan")
        cursor += count
    if cursor != len(planned):
        raise CanonicalContractError("extra planned attempts outside selected scope")


def _clock(start, end, duration):
    if (type(start) is not str or type(end) is not str
            or not start.endswith("Z") or not end.endswith("Z")
            or type(duration) is not int or duration < 0):
        raise CanonicalContractError("invalid factual session clock")
    try:
        a = datetime.fromisoformat(start[:-1] + "+00:00")
        b = datetime.fromisoformat(end[:-1] + "+00:00")
        if b < a:
            raise ValueError("reversed session clock")
    except (ValueError, OverflowError) as exc:
        raise CanonicalContractError("invalid factual session UTC chronology") from exc


def _outcome(terminal, plan, actual, status_pairs):
    if terminal not in ("FINISHED", "INTERRUPTED"):
        raise CanonicalContractError("unrecognized runtime terminal event")
    if actual != plan[:len(actual)]:
        raise CanonicalContractError("actual source attempts do not match selected execution prefix")
    if terminal == "INTERRUPTED":
        if len(actual) >= len(plan):
            raise CanonicalContractError("interrupted session had no outstanding planned attempt")
        return "INTERRUPTED", "INTERRUPTED", "INTERRUPTED", "RUN_INTERRUPTED"
    if actual != plan:
        raise CanonicalContractError("finished session omitted selected source attempts")
    if plan and all(x == ("COMPLETE", "OK") for x in status_pairs):
        return "COMMITTED", "COMPLETE", "COMPLETE", "ALL_REQUIRED_COMPLETE"
    return "INCOMPLETE", "PARTIAL", "PARTIAL", "MINIMUM_WITH_GAPS"


def reconcile_execution(execution, run_id, collector_ids, actual_ids, statuses):
    """Produce factual lifecycle fields or None for historical no-witness runs.

    `statuses` are already D-02 validated acquisition statuses in the
    *same order* as source_attempts. A finished traversal is not proof
    of successful acquisition, and an empty plan is not COMPLETE.
    """
    if execution is None:
        return None
    if not isinstance(execution, SessionExecution):
        raise CanonicalContractError("unsupported runtime execution witness")
    if (type(run_id) is not str or type(collector_ids) is not tuple
            or type(actual_ids) is not tuple
            or type(statuses) is not tuple
            or len(actual_ids) != len(statuses)
            or not all(type(x) is tuple and len(x)==2 for x in statuses)
            or type(execution.terminal_state) is not str):
        raise CanonicalContractError("invalid runtime reconciliation inputs")
    if collector_ids != execution.selected_collector_ids[:len(collector_ids)]:
        raise CanonicalContractError("actual collector order does not match run plan")
    _source_plan(execution.selected_collector_ids,
                 execution.selected_source_ids,
                 execution.planned_attempt_ids)
    _clock(execution.started_utc, execution.completed_utc, execution.elapsed_ms)
    lifecycle, completion, orchestration, reason = _outcome(
        execution.terminal_state, execution.planned_attempt_ids, actual_ids, statuses)
    detail = (MARKER + execution.terminal_state + ";planned="
              + ",".join(execution.planned_attempt_ids))
    if len(detail) > 1024:
        raise CanonicalContractError("approved D-02 orchestration detail exceeded")
    return {
        "lifecycle": lifecycle,
        "completion": completion,
        "orchestration": orchestration,
        "reason": reason,
        "detail": detail,
        "started_utc": execution.started_utc,
        "completed_utc": execution.completed_utc,
        "elapsed_ms": execution.elapsed_ms,
        "selected_collectors": execution.selected_collector_ids,
    }


def validate_persisted_lifecycle(header, manifest, session, attempts, statuses):
    """Independently reconcile the durable D-02 lifecycle against source rows.

    Only records carrying the bounded v1 terminal+plan marker may establish a
    witnessed COMPLETE / PARTIAL / INTERRUPTED outcome. Historical no-witness
    sessions remain INCOMPLETE. Statuses/attempts were already shape-checked.
    """
    selected = tuple(header["collector_ids"])
    actual = tuple(a["attempt_id"] for a in attempts)
    pair_by_id = {s["record_id"]: (s["status"], s["reason_code"])
                  for s in statuses if s["domain"] == "acquisition"}
    pairs = tuple(pair_by_id[a["status_record_id"]] for a in attempts)
    detail = session["detail"]
    if not detail.startswith(MARKER):
        if (session["status"], session["reason_code"],
                header["lifecycle_state"], manifest["completion_state"]) != (
                "PARTIAL", "MINIMUM_WITH_GAPS", "INCOMPLETE", "INCOMPLETE"):
            raise CanonicalContractError("non-witnessed session must remain INCOMPLETE")
        return
    event, sep, plan_csv = detail[len(MARKER):].partition(";planned=")
    if not sep or event not in ("FINISHED", "INTERRUPTED"):
        raise CanonicalContractError("invalid persisted session event")
    plan = tuple(plan_csv.split(",")) if plan_csv else ()
    selected_sources = tuple(x.source_id for x in initial_catalog()[1]
                             if x.collector_id in selected)
    _source_plan(selected, selected_sources, plan)
    lc, cs, os, rc = _outcome(event, plan, actual, pairs)
    if (header["lifecycle_state"] != lc
            or manifest["completion_state"] != cs
            or (session["status"], session["reason_code"]) != (os, rc)
            or session["source_attempt_ids"] != list(actual)
            or header["started_utc"] != session["started_utc"]
            or header["completed_utc"] != session["completed_utc"]
            or header["started_utc"] is None
            or header["completed_utc"] is None
            or session["elapsed_ms"] is None
            or manifest["finalized_utc"] is None):
        raise CanonicalContractError("durable witnessed session lifecycle contradicts source outcomes")
    _clock(header["started_utc"], header["completed_utc"], session["elapsed_ms"])
    try:
        if datetime.fromisoformat(manifest["finalized_utc"].replace("Z","+00:00")) < (
                datetime.fromisoformat(header["completed_utc"].replace("Z","+00:00"))):
            raise CanonicalContractError("session finalized before actual execution ended")
    except (TypeError, ValueError) as exc:
        raise CanonicalContractError("invalid witnessed finalization timestamp") from exc
