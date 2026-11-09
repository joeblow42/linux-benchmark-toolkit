"""G5-02 one-source boundary: dispatch, preserve, journal without a second engine.

This is a reusable operation for G5-03's future single IC-02 orchestrator,
NOT a production launcher. Every returned attempt has an immutable private
receipt, including denials and missing tools. Canonical/IC-04 statuses are G5-04.
"""
from dataclasses import dataclass
import time
from .records import utc_now
from .safety import SourceRequest, initial_source_policies
from .passive import acquire_passive
from .runtime import execute_source_command
from .additional import acquire_additional
from .o1_execution import execute_optional
from .records import build_attempt,commit_attempt

@dataclass(frozen=True)
class RecordedOutcome:
    outcome: object
    receipt_private_path: str
    authorization_provenance: dict | None = None
    source_timing: dict | None = None

def capture_and_record(request:SourceRequest,attempt,writer,slots,calls,
                       *,subcall=0,source14_evidence=None,
                       privileged_session=None,o1_inventory_binding=None)->RecordedOutcome:
    policies={p.source_id:p for p in initial_source_policies()}
    policy=policies.get(request.source_id)
    if policy is None:
        raise ValueError("unregistered source cannot create an approved attempt")
    # Witness G5-03 adapter entry/exit on the existing single source path.
    source_started_utc=utc_now()
    source_started_ns=time.monotonic_ns()
    if policy.authorization_class=="D0":
        outcome=acquire_passive(request,attempt,writer,slots,calls)
    elif request.source_id in ("SRC-05","SRC-11","SRC-20","SRC-23"):
        outcome=execute_source_command(request,subcall,attempt,writer,slots,calls)
    elif request.source_id in ("SRC-15","SRC-28"):
        outcome=acquire_additional(request,attempt,writer,slots,calls,
                                   source14_evidence=source14_evidence)
    elif policy.authorization_class=="O1":
        outcome=execute_optional(request,attempt,subcall,writer,slots,calls,
                                 privileged_session=privileged_session)
    else:
        raise ValueError("approved source has no bounded adapter")

    source_completed_ns=time.monotonic_ns()
    source_completed_utc=utc_now()
    if isinstance(outcome,dict):
        items=tuple(outcome.get("receipts",()))
        state=outcome["disposition"]
        reason=outcome["reason"]
        diagnostic=()
        source_paths=()
        invocation=request.operation_id
        missing=outcome.get("missing_extent_known_at_least")
        exit_code=outcome.get("exit_code")
        elapsed_seconds=outcome.get("elapsed_seconds")
        timed_out=bool(outcome.get("timed_out",False))
        capture_limited=bool(outcome.get("capture_limited",False))
    else:
        items=tuple(getattr(outcome,"artifacts",()) or ())
        if hasattr(outcome,"stdout"):
            items=tuple(x for x in (outcome.stdout,outcome.stderr) if x is not None)
        state=outcome.disposition
        reason=outcome.reason
        diagnostic=tuple(getattr(outcome,"errors",()) or ())
        source_paths=tuple(getattr(outcome,"source_paths",()) or
                           getattr(outcome,"targets",()) or ())
        argv=getattr(outcome,"argv",None)
        invocation=" ".join(argv) if argv else request.operation_id
        missing=getattr(outcome,"missing_extent_known_at_least",None)
        exit_code=getattr(outcome,"exit_code",None)
        elapsed_seconds=getattr(outcome,"elapsed_seconds",None)
        timed_out=bool(getattr(outcome,"timed_out",False))
        capture_limited=bool(getattr(outcome,"capture_limited",False) or getattr(outcome,"limited",False))
    decision="DENY" if state=="DENIED" else "ALLOW"
    # Denied/unavailable preflight does not prove that source execution began.
    source_timing = (dict(started_utc=source_started_utc,
                          completed_utc=source_completed_utc,
                          elapsed_ms=max(0,(source_completed_ns-source_started_ns)//1000000))
                     if decision=="ALLOW" and state in ("CAPTURED","PARTIAL","FAILED")
                     else None)
    if len(source_paths)!=len(items):
        source_paths=()
    # The engine, not an external request, supplies the witnessed D0 binding.
    # A successful O1 executor supplies the checked plan identity. Both are
    # necessary; an ALLOW-looking receipt alone cannot assert operator consent.
    provenance=None
    if (policy.authorization_class=="O1" and isinstance(outcome,dict)
            and outcome.get("preflight_approved") is True
            and type(o1_inventory_binding) is dict
            and request.consent is not None and request.target in request.trusted_targets
            and state in ("CAPTURED","PARTIAL") and items):
        consent=request.consent
        provenance=dict(
            run_id=request.run_id,source_id=request.source_id,
            operation_id=request.operation_id,target=request.target,
            consent_run_id=consent.run_id,consent_source_id=consent.source_id,
            consent_operation_id=consent.operation_id,consent_target=consent.target,
            consent_issued_utc=consent.issued_utc.isoformat().replace("+00:00","Z"),
            impact_acknowledged=consent.impact_acknowledged,
            inventory_source_id=o1_inventory_binding.get("source_id"),
            inventory_source_path=o1_inventory_binding.get("source_path"),
            inventory_evidence_id=o1_inventory_binding.get("evidence_id"),
            approved_argv=list(outcome.get("approved_argv",())))
        invocation=" ".join(provenance["approved_argv"])
    record=build_attempt(request.run_id,request.source_id,attempt,
        decision,state,reason,evidence=items,
        bytes_count=sum(x.byte_count for x in items),
        missing=missing,errors=diagnostic,
        invocation=invocation,target=request.target,
        source_paths=source_paths,
        unavailable_fields=tuple(getattr(outcome,"unavailable_fields",()) or ()),
        exit_code=exit_code,elapsed_seconds=elapsed_seconds,
        timed_out=timed_out,capture_limited=capture_limited,
        authorization_provenance=provenance,
        execution_provenance=(getattr(outcome,"execution_provenance",None)
                              if request.source_id=="SRC-28" else None),
        source_timing=source_timing,
        limit_witness=(outcome.get("limit_witness") if isinstance(outcome,dict)
                       else getattr(outcome,"limit_witness",None)))
    location=commit_attempt(writer.run_directory,record)
    return RecordedOutcome(outcome,location,provenance,source_timing)
