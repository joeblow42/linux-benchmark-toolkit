"""G5-02 local-only D1: statvfs bounded worker and dpkg installed metadata."""
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import time
from .safety import SourceRequest,decide_source,initial_source_policies
from .runtime import (_capture_child,_resolve_executable,ProbeSlots,
                      SourceCallBudget,ProbeCapacityError)
from .evidence import EvidenceWriter,ArtifactReceipt
from .local_space import eligible_mounts
MIB=1024*1024
_LOCAL_WORKER=os.path.realpath(os.path.join(os.path.dirname(__file__),"local_space.py"))
_DPKG_ARGV=("dpkg-query","-W","-f=$"+"{Package}\\t$"+"{Version}\\n")

@dataclass(frozen=True)
class AdditionalOutcome:
    source_id: str
    disposition: str
    reason: str
    artifacts: tuple[ArtifactReceipt,...]
    targets: tuple[str,...]
    errors: tuple[str,...]
    elapsed_seconds: float
    limited: bool
    exit_code: int | None = None
    execution_provenance: dict | None = None
    timed_out: bool = False
    limit_witness: dict | None = None
    # Private v0.6 measured D1 limits; no public/canonical field change.
    limit_witnesses: tuple[dict,...] = ()

def acquire_additional(request:SourceRequest,attempt:str,writer:EvidenceWriter,
                       slots:ProbeSlots,calls:SourceCallBudget,
                       *,source14_evidence:bytes|None=None)->AdditionalOutcome:
    # Only SRC-28 is authorized to add the 0.3 private execution witness.
    # No execution witness is minted on a missing executable or failed spawn.
    executed_code = None
    execution_witness = None
    observed_timeout = False
    single_limit_witness = None
    transport_limit_witnesses = ()
    def out(disposition,reason,artifacts=(),targets=(),errors=(),elapsed=0.,limited=False):
        return AdditionalOutcome(request.source_id,disposition,reason,tuple(artifacts),
                                 tuple(targets),tuple(errors),elapsed,limited,
                                 executed_code if request.source_id == "SRC-28" else None,
                                 execution_witness if request.source_id == "SRC-28" else None,
                                 observed_timeout,single_limit_witness,
                                 transport_limit_witnesses)
    policy={p.source_id:p for p in initial_source_policies()}.get(request.source_id)
    decision=decide_source(request,
        remaining_seconds=writer.meter.time_remaining(),
        remaining_bytes=writer.meter.max_bytes-writer.meter.bytes_reserved)
    if not decision.allowed:return out("DENIED",decision.reason)
    if request.source_id not in ("SRC-15","SRC-28"):
        return out("DENIED","NO_SAFE_ADAPTER")
    if writer.run_id!=request.run_id:return out("DENIED","RUN_ID_MISMATCH")
    if request.source_id=="SRC-15":
        if type(source14_evidence) is not bytes:
            return out("DENIED","SOURCE14_EVIDENCE_REQUIRED")
        mounts=eligible_mounts(source14_evidence.decode("utf-8","replace"))
        if not mounts:return out("NOT_APPLICABLE","NO_CONFIRMED_LOCAL_MOUNT")
        plans=tuple((p,("python3","-I",_LOCAL_WORKER,p)) for p in mounts[:policy.max_entries])
        limited=len(mounts)>policy.max_entries
    else:
        plans=(("installed-packages",_DPKG_ARGV),)
        limited=False
    receipts=[]
    targets=[]
    errors=[]
    start=time.monotonic()
    # A single source-level wall deadline must span *all* mounts, including
    # process setup and evidence persistence; the call counter tracks only
    # completed subcall durations and is insufficient as an absolute clock.
    deadline=start+policy.max_seconds
    try:
        with slots.hold("D1"):
            for i,(label,argv) in enumerate(plans):
                remaining_wall=deadline-time.monotonic()
                remaining_calls=calls.remaining(request.run_id,request.source_id)
                if remaining_wall<=0 or remaining_calls<=0:
                    limited=True;errors.append("TIME_BUDGET_EXCEEDED");break
                if not calls.begin(request.run_id,request.source_id,i):
                    limited=True
                    errors.append("TIME_BUDGET_EXCEEDED" if
                                  calls.remaining(request.run_id,request.source_id)<=0
                                  else "INVOCATION_LIMIT")
                    break
                callstart=time.monotonic()
                try:
                    binary=_resolve_executable(argv[0])
                    if binary is None:
                        errors.append("EXECUTABLE_NOT_FOUND");break
                    seconds=min(8.0 if request.source_id=="SRC-28" else 2.0,
                        deadline-time.monotonic(),
                        calls.remaining(request.run_id,request.source_id),
                        writer.meter.time_remaining())
                    if seconds<=0:
                        limited=True;errors.append("TIME_BUDGET_EXCEEDED");break
                    actual_argv = (binary,)+argv[1:]
                    # These clock readings bracket the real transport operation.
                    # The transport's elapsed_seconds is independently monotonic.
                    cmd_started_utc = (datetime.now(timezone.utc)
                        .isoformat(timespec="milliseconds").replace("+00:00","Z")) \
                        if request.source_id == "SRC-28" else None
                    transport=_capture_child(actual_argv,
                        8*MIB if request.source_id=="SRC-28" else 1*MIB,
                        1*MIB if request.source_id=="SRC-28" else 128*1024,
                        seconds,8*MIB if request.source_id=="SRC-28" else 2*MIB)
                    observed_timeout = observed_timeout or transport.timed_out
                    if request.source_id == "SRC-28":
                        cmd_completed_utc = (datetime.now(timezone.utc)
                            .isoformat(timespec="milliseconds").replace("+00:00","Z"))
                        executed_code = transport.returncode
                        execution_witness = dict(
                            argv_executed=list(actual_argv),
                            exit_code=transport.returncode,
                            started_utc=cmd_started_utc,
                            completed_utc=cmd_completed_utc,
                            elapsed_seconds=transport.elapsed_seconds)
                    for name,data,stream_limit in (
                        ("stdout",transport.stdout,8*MIB if request.source_id=="SRC-28" else 1*MIB),
                        ("stderr",transport.stderr,1*MIB if request.source_id=="SRC-28" else 128*1024)):
                        if not data:continue
                        seal=writer.seal_chunks(policy,attempt,f"call{i+1:04d}-{name}",
                                               (data,),per_stream_limit=stream_limit)
                        if seal.failure:
                            errors.append("EVIDENCE_PERSIST_FAILED");break
                        receipts.append(seal.receipt)
                        targets.append(label+":"+name)
                        if seal.receipt.limit_applied:limited=True
                    if errors:break
                    # F-04: SRC-28's single approved process has one actual
                    # applied transport deadline. A competing stream/writer
                    # limit prevents declaring a single dominant dimension.
                    # Never recast a timeout as an inferred byte threshold.
                    if (request.source_id=="SRC-28" and transport.timed_out
                            and not transport.exceeded_limit
                            and transport.stdout_omitted_at_least==0
                            and transport.stderr_omitted_at_least==0
                            and not limited
                            and not any(r.limit_applied for r in receipts)):
                        single_limit_witness={
                            "unit":"seconds","threshold":seconds,
                            "observed_extent":transport.elapsed_seconds,
                            "missing_extent":None,
                            "affected_scope":"SRC-28:call0001:transport",
                            "reason":"TIME_BUDGET_EXCEEDED",
                        }
                    if request.source_id=="SRC-28":
                        # F-04: only independently witnessed, ACTUAL applied
                        # process caps; never derive thresholds from the source
                        # policy maximum or choose a guessed dominant event.
                        events=[]
                        stdout_missing=transport.stdout_omitted_at_least
                        stderr_missing=transport.stderr_omitted_at_least
                        combined_len=len(transport.stdout)+len(transport.stderr)
                        if transport.exceeded_limit:
                            # Combined cap has priority where both an individual
                            # stdout cap and combined cap are exactly 8 MiB.
                            # This names a real applied bound, not a claim
                            # about which internal branch caused the stop.
                            if (combined_len==8*MIB and
                                    type(stdout_missing) is int and
                                    type(stderr_missing) is int and
                                    stdout_missing>=0 and stderr_missing>=0 and
                                    stdout_missing+stderr_missing>0):
                                events.append({
                                    "unit":"bytes","threshold":8*MIB,
                                    "observed_extent":combined_len,
                                    "missing_extent":stdout_missing+stderr_missing,
                                    "affected_scope":"SRC-28:call0001:transport",
                                    "reason":"CAPTURE_LIMIT"})
                            elif (type(stderr_missing) is int and stderr_missing>0
                                    and stdout_missing==0
                                    and len(transport.stderr)==1*MIB):
                                events.append({
                                    "unit":"bytes","threshold":1*MIB,
                                    "observed_extent":len(transport.stderr),
                                    "missing_extent":stderr_missing,
                                    "affected_scope":"SRC-28:call0001:stderr",
                                    "reason":"CAPTURE_LIMIT"})
                        elif stdout_missing or stderr_missing:
                            # Inconsistent transport facts: no promotion.
                            events=[]
                        if (transport.timed_out and
                                not any(r.limit_applied for r in receipts)):
                            events.append({
                                "unit":"seconds","threshold":seconds,
                                "observed_extent":transport.elapsed_seconds,
                                "missing_extent":None,
                                "affected_scope":"SRC-28:call0001:transport",
                                "reason":"TIME_BUDGET_EXCEEDED"})
                        if (any(r.limit_applied for r in receipts) or
                                (transport.exceeded_limit and not any(
                                    ev["unit"]=="bytes" for ev in events)) or
                                (not transport.exceeded_limit and (
                                    stdout_missing or stderr_missing))):
                            # Unwitnessed competing source/writer/transport
                            # limit makes the whole event nonpromotable.
                            events=[]
                        if events and (transport.exceeded_limit or
                                      len(events)>1):
                            transport_limit_witnesses=tuple(events)
                            single_limit_witness=None
                    if request.source_id=="SRC-15":
                        # Source-first v0.6 D1 facts. The existing source loop
                        # stops on the FIRST limited subcall; do not resume
                        # later mounts or infer an overall 15s source event.
                        events=[]
                        missing_out=transport.stdout_omitted_at_least
                        missing_err=transport.stderr_omitted_at_least
                        if transport.exceeded_limit:
                            for name,raw,omitted,effective in (
                                    ("stdout",transport.stdout,missing_out,1*MIB),
                                    ("stderr",transport.stderr,missing_err,128*1024)):
                                if (type(omitted) is int and omitted>0 and
                                        len(raw)==effective):
                                    events.append({
                                        "unit":"bytes","threshold":effective,
                                        "observed_extent":len(raw),
                                        "missing_extent":omitted,
                                        "affected_scope":("SRC-15:call"+
                                            format(i+1,"04d")+":"+name),
                                        "reason":"CAPTURE_LIMIT"})
                        if transport.timed_out:
                            events.append({
                                "unit":"seconds","threshold":seconds,
                                "observed_extent":transport.elapsed_seconds,
                                "missing_extent":None,
                                "affected_scope":("SRC-15:call"+
                                    format(i+1,"04d")+":transport"),
                                "reason":"TIME_BUDGET_EXCEEDED"})
                        # A mismatched output extent, missing overflow proof
                        # or separate unproven writer truncation blocks ALL
                        # canonical limit records for this source attempt.
                        if (any(r.limit_applied for r in receipts)
                                or (transport.exceeded_limit and
                                    not any(v["unit"]=="bytes" for v in events))
                                or (not transport.exceeded_limit and
                                    (missing_out or missing_err))
                                or (transport.exceeded_limit and
                                    ((missing_out>0 and not any(
                                        v["affected_scope"].endswith(":stdout")
                                        for v in events)) or
                                     (missing_err>0 and not any(
                                        v["affected_scope"].endswith(":stderr")
                                        for v in events))))):
                            events=[]
                        if events:
                            transport_limit_witnesses=tuple(events)
                    if transport.returncode:errors.append("COMMAND_EXIT_NONZERO")
                    if (transport.exceeded_limit or
                            transport.stdout_omitted_at_least>0 or
                            transport.stderr_omitted_at_least>0):
                        # Even a contradictory transport overflow claim is
                        # an incomplete source, never a CAPTURED/OK success.
                        # Without an independently witnessed cap, canonical
                        # creation must still fail closed.
                        limited=True;errors.append("CAPTURE_LIMIT")
                    if transport.timed_out:
                        limited=True;errors.append("TIME_BUDGET_EXCEEDED")
                    if transport.returncode or transport.timed_out or transport.exceeded_limit:
                        break
                except OSError as exc:
                    errors.append(type(exc).__name__);break
                finally:
                    calls.end(request.run_id,request.source_id,time.monotonic()-callstart)
    except ProbeCapacityError:
        return out("DENIED","CONCURRENCY_LIMIT")
    elapsed=time.monotonic()-start
    if receipts and not errors and not limited:
        return out("CAPTURED","BYTES_PRESERVED",receipts,targets,errors,elapsed)
    if receipts:
        reason=("TIME_BUDGET_EXCEEDED" if "TIME_BUDGET_EXCEEDED" in errors
                else "CAPTURE_LIMIT" if limited else "SOURCE_INCOMPLETE")
        return out("PARTIAL",reason,receipts,targets,errors,elapsed,limited)
    if "EXECUTABLE_NOT_FOUND" in errors:
        return out("UNAVAILABLE","EXECUTABLE_NOT_FOUND",errors=errors,elapsed=elapsed)
    return out("FAILED","ACQUISITION_ERROR",errors=errors,elapsed=elapsed,limited=limited)
