"""G5-02 one-source boundary: dispatch, preserve, journal without a second engine.

This is a reusable operation for G5-03's future single IC-02 orchestrator,
NOT a production launcher. Every returned attempt has an immutable private
receipt, including denials and missing tools. Canonical/IC-04 statuses are G5-04.
"""
from dataclasses import dataclass
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

def capture_and_record(request:SourceRequest,attempt,writer,slots,calls,
                       *,subcall=0,source14_evidence=None)->RecordedOutcome:
    policies={p.source_id:p for p in initial_source_policies()}
    policy=policies.get(request.source_id)
    if policy is None:
        raise ValueError("unregistered source cannot create an approved attempt")
    if policy.authorization_class=="D0":
        outcome=acquire_passive(request,attempt,writer,slots,calls)
    elif request.source_id in ("SRC-05","SRC-11","SRC-20","SRC-23"):
        outcome=execute_source_command(request,subcall,attempt,writer,slots,calls)
    elif request.source_id in ("SRC-15","SRC-28"):
        outcome=acquire_additional(request,attempt,writer,slots,calls,
                                   source14_evidence=source14_evidence)
    elif policy.authorization_class=="O1":
        outcome=execute_optional(request,attempt,subcall,writer,slots,calls)
    else:
        raise ValueError("approved source has no bounded adapter")

    if isinstance(outcome,dict):
        items=tuple(outcome.get("receipts",()))
        state=outcome["disposition"]
        reason=outcome["reason"]
        diagnostic=()
        source_paths=()
        invocation=request.operation_id
        missing=None
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
    decision="DENY" if state=="DENIED" else "ALLOW"
    if len(source_paths)!=len(items):
        source_paths=()
    record=build_attempt(request.run_id,request.source_id,attempt,
        decision,state,reason,evidence=items,
        bytes_count=sum(x.byte_count for x in items),
        missing=missing,errors=diagnostic,
        invocation=invocation,target=request.target,
        source_paths=source_paths)
    location=commit_attempt(writer.run_directory,record)
    return RecordedOutcome(outcome,location)
