"""G5-02 bounded passive acquisition, with byte-identical original artifacts.

D0 sources are isolated into a hard-deadline worker; the worker is given
ONLY a registered source ID and approved numeric ceilings. All source path
selection is fixed inside that worker. Its JSON/base64 output is transport,
not original evidence; the decoded bytes are sealed separately per field.
No runtime source is invoked on import.
"""
from dataclasses import dataclass
import base64
import binascii
import json
import os
import time

from .evidence import EvidenceWriter, ArtifactReceipt
from .runtime import (_capture_child, _resolve_executable,
                      ProbeSlots, SourceCallBudget, ProbeCapacityError)
from .safety import SourceRequest, decide_source, initial_source_policies

_WORKER = os.path.join(os.path.dirname(os.path.realpath(__file__)),"passive_worker.py")

@dataclass(frozen=True)
class PassiveOutcome:
    source_id: str
    disposition: str
    reason: str
    artifacts: tuple[ArtifactReceipt,...]
    source_paths: tuple[str,...]
    errors: tuple[str,...]
    acquired_count: int
    acquired_bytes: int
    elapsed_seconds: float
    limited: bool
    missing_extent_known_at_least: int | None
    worker_finished: bool
    unavailable_fields: tuple[str,...] = ()
    # Only a witnessed process timeout may populate this D0 time-bound fact.
    timed_out: bool = False
    limit_witness: dict | None = None
    limit_witnesses: tuple[dict,...] = ()

def _transport_decode(payload: bytes, policy, *, with_events=False):
    records=[]
    errors=[]
    unavailable=[]
    end=None
    total=0
    attempted_records=0
    for line in payload.splitlines():
        if not line: continue
        try:
            msg=json.loads(line)
        except (ValueError,UnicodeDecodeError):
            errors.append("INCOMPLETE_TRANSPORT_RECORD")
            break
        if not isinstance(msg,dict):
            errors.append("INVALID_TRANSPORT_RECORD");break
        if msg.get("end") is True:
            end=msg;break
        attempted_records+=1
        if msg.get("unavailable") is True:
            path=str(msg.get("path","UNKNOWN"))[:180]
            code=str(msg.get("error","UNAVAILABLE"))[:50]
            errno_value=msg.get("errno")
            errno_tag=("["+str(errno_value)+"]") if type(errno_value) is int else ""
            unavailable.append(code+errno_tag+":"+path)
            continue
        if "error" in msg:
            error_type=str(msg.get("error","READ_FAILED"))[:64]
            source_path=str(msg.get("path","UNSPECIFIED"))[:110]
            errno_value=msg.get("errno")
            errno_tag=("["+str(errno_value)+"]") if type(errno_value) is int else ""
            errors.append((error_type+errno_tag+":"+source_path)[:120])
            continue
        if "bytes_b64" not in msg or not isinstance(msg.get("path"),str):
            errors.append("MALFORMED_SOURCE_RECORD");break
        try:
            raw=base64.b64decode(msg["bytes_b64"],validate=True)
        except (binascii.Error,TypeError):
            errors.append("INVALID_BASE64_SOURCE");break
        if len(records)>=policy.max_entries or total+len(raw)>policy.max_bytes:
            errors.append("SOURCE_LIMIT_REACHED");break
        total+=len(raw)
        record=(msg["path"],raw,bool(msg.get("limited")))
        # Preserve the original five-result/three-item decoder contract for
        # all older callers. Only the G5-03 adapter consumes v0.6 metadata.
        records.append(record+(msg.get("limit_events",()),) if with_events else record)
    # Restricted worker transport is not source-original evidence.
    if with_events:
        return records,errors,end,total,unavailable,attempted_records
    return records,errors,end,total,unavailable

def acquire_passive(request: SourceRequest, attempt: str, writer: EvidenceWriter,
                    slots: ProbeSlots, calls: SourceCallBudget) -> PassiveOutcome:
    pol={p.source_id:p for p in initial_source_policies()}.get(request.source_id)
    paths=[]
    unavailable=[]
    def done(disposition,reason,receipts=(),errors=(),elapsed=0.0,
             limited=False,missing=None,complete=False,
             timed_out=False,limit_witness=None,limit_witnesses=()):
        bounded_errors=tuple(errors[:63])+(("ADDITIONAL_ERRORS_OMITTED",) if len(errors)>63 else ())
        return PassiveOutcome(request.source_id,disposition,reason,tuple(receipts),
                              tuple(paths),bounded_errors,len(receipts),
                              sum(r.byte_count for r in receipts),elapsed,
                              limited,missing,complete,
                              tuple(unavailable[:63])+(("ADDITIONAL_OPTIONAL_FIELDS_OMITTED",) if len(unavailable)>63 else ()),
                              timed_out,limit_witness,tuple(limit_witnesses))
    decision=decide_source(request,remaining_seconds=writer.meter.time_remaining(),
        remaining_bytes=writer.meter.max_bytes-writer.meter.bytes_reserved)
    if not decision.allowed: return done("DENIED",decision.reason)
    if pol is None or pol.authorization_class!="D0":
        return done("DENIED","NOT_A_PASSIVE_SOURCE")
    if request.run_id != writer.run_id: return done("DENIED","RUN_ID_MISMATCH")
    if not os.path.isfile(_WORKER):
        return done("UNAVAILABLE","WORKER_NOT_FOUND")
    if not calls.begin(request.run_id,request.source_id,0):
        return done("DENIED","SOURCE_ALREADY_ATTEMPTED")
    started=time.monotonic()
    try:
        with slots.hold("D0"):
            python=_resolve_executable("python3")
            if python is None: return done("UNAVAILABLE","PYTHON3_NOT_FOUND")
            cap=min(pol.max_seconds,calls.remaining(request.run_id,request.source_id),
                    writer.meter.time_remaining())
            if cap<=0: return done("DENIED","TIME_BUDGET_EXCEEDED")
            # Transport expands original bytes by base64 + bounded per-record metadata.
            transport_cap=min(64*1024*1024,int(pol.max_bytes*1.5)+pol.max_entries*512+4096)
            try:
                captured=_capture_child((python,"-I",_WORKER,pol.source_id,
                    str(pol.max_bytes),str(pol.max_entries)),
                    transport_cap,64*1024,cap)
            except OSError as exc:
                return done("FAILED",type(exc).__name__)
            records,errors,end,total,skipped,attempted_records=_transport_decode(
                captured.stdout,pol,with_events=True)
            unavailable.extend(skipped)
            receipts=[]
            limited=(captured.exceeded_limit or captured.timed_out
                     or captured.stdout_omitted_at_least>0
                     or captured.stderr_omitted_at_least>0)
            worker_bounds=[]
            unproved_worker_limit=False
            for i,(original_path,original,record_limit,events) in enumerate(records,1):
                artifact=f"item{i:04d}"
                result=writer.seal_chunks(pol,attempt,artifact,(original,))
                if result.failure:
                    errors.append("EVIDENCE_PERSIST_FAILED")
                    break
                receipt=result.receipt
                receipts.append(receipt)
                paths.append(original_path)
                limited=limited or record_limit or receipt.limit_applied
                # Revalidate private worker metadata against immutable source
                # ceilings, original size and exactly sealed item identity.
                valid_file=(record_limit and type(events) is list
                            and len(events)==1 and type(events[0]) is dict
                            and set(events[0])=={
                                "dimension","threshold","observed_extent"}
                            and events[0]["dimension"]=="file_bytes"
                            and events[0]["threshold"]==1024*1024
                            and events[0]["observed_extent"]==len(original)
                            and len(original)==1024*1024
                            and receipt.byte_count==len(original)
                            and not receipt.limit_applied)
                if record_limit and valid_file:
                    worker_bounds.append({
                        "unit":"bytes","threshold":1024*1024,
                        "observed_extent":receipt.byte_count,
                        "missing_extent":None,
                        "affected_scope":pol.source_id+f":call0001:item{i:04d}:file",
                        "reason":"CAPTURE_LIMIT"})
                elif record_limit or events:
                    unproved_worker_limit=True
            if end and end.get("limited"):
                limited=True
                raw_events=end.get("limit_events")
                # No end record or missing/contradictory dimensional witness
                # means canonical generation must fail closed.
                if type(raw_events) is not list or not raw_events:
                    unproved_worker_limit=True
                else:
                    seen=set()
                    for event in raw_events:
                        if type(event) is not dict or set(event)!={
                                "dimension","threshold","observed_extent"}:
                            unproved_worker_limit=True
                            break
                        dim=event["dimension"]
                        if dim in seen:
                            unproved_worker_limit=True
                            break
                        seen.add(dim)
                        if dim=="source_entries":
                            valid=(type(event["threshold"]) is int
                                and type(event["observed_extent"]) is int
                                and event["threshold"]==pol.max_entries
                                and event["observed_extent"]==attempted_records
                                and attempted_records==pol.max_entries
                                and end.get("attempted")==attempted_records)
                            unit="entries";scope="source:entries"
                        elif dim=="source_bytes":
                            valid=(type(event["threshold"]) is int
                                and type(event["observed_extent"]) is int
                                and event["threshold"]==pol.max_bytes
                                and event["observed_extent"]==total
                                and total==pol.max_bytes
                                and end.get("bytes")==total)
                            unit="bytes";scope="source:bytes"
                        else:
                            valid=False;unit=None;scope=None
                        if not valid:
                            unproved_worker_limit=True
                            break
                        worker_bounds.append({
                            "unit":unit,"threshold":event["threshold"],
                            "observed_extent":event["observed_extent"],
                            "missing_extent":None,
                            "affected_scope":pol.source_id+":call0001:"+scope,
                            "reason":"CAPTURE_LIMIT"})
            elif end and end.get("limit_events"):
                unproved_worker_limit=True
            # Never promote worker facts if the envelope's counts are
            # contradictory or if a separate writer truncation cannot be
            # independently dimensioned within this bounded increment.
            if end is not None and (type(end.get("entries")) is not int
                    or end["entries"]!=len(records)
                    or type(end.get("bytes")) is not int or end["bytes"]!=total
                    or end.get("attempted") not in (None,attempted_records)):
                unproved_worker_limit=True
            complete=(end is not None and captured.returncode==0 and not captured.timed_out
                      and not captured.exceeded_limit and not errors and not limited
                      and len(records)==end.get("entries") and total==end.get("bytes"))
            if captured.returncode not in (0,None): errors.append("WORKER_EXIT_NONZERO")
            if captured.timed_out: errors.append("TIME_BUDGET_EXCEEDED")
            if captured.exceeded_limit or (not captured.exceeded_limit and (
                    captured.stdout_omitted_at_least or captured.stderr_omitted_at_least)):
                errors.append("TRANSPORT_LIMIT")
            if not end: errors.append("INCOMPLETE_WORKER_STREAM")
            # F-04: the actual _capture_child call deadline is a source event
            # witness. Never infer a source byte ceiling from policy.max_bytes.
            # One bound is representable by v0.5; ambiguous simultaneous D0
            # worker, writer and transport ceilings fail closed at canonical.
            timeout_witness = None
            if (captured.timed_out and not captured.exceeded_limit
                    and not any(record_limit for _,_,record_limit,_ in records)
                    and not any(r.limit_applied for r in receipts)
                    and not (end and end.get("limited"))
                    and "SOURCE_LIMIT_REACHED" not in errors
                    and "EVIDENCE_PERSIST_FAILED" not in errors
                    and not unproved_worker_limit):
                timeout_witness = {
                    "unit":"seconds",
                    "threshold":cap,
                    "observed_extent":captured.elapsed_seconds,
                    "missing_extent":None,
                    "affected_scope":pol.source_id+":call0001:transport",
                    "reason":"TIME_BUDGET_EXCEEDED",
                }
            # The v0.6 path is distinct from legacy v0.5 single time facts.
            # Evidence-writer or transport byte overruns remain nonpromotable
            # until individually witnessed. Do not bury an unproved dimension
            # underneath a separately valid worker/time witness.
            transport_bounds=[]
            unproved_transport=False
            # D0's actual _capture_child applies per-stream stdout/stderr caps;
            # there is NO optional combined cap for this worker. A reported
            # omitted lower bound proves overflow only if the retained stream
            # reached precisely the ceiling passed to the transport.
            stream_events=(
                ("stdout",captured.stdout,captured.stdout_omitted_at_least,
                 transport_cap),
                ("stderr",captured.stderr,captured.stderr_omitted_at_least,
                 64*1024))
            if captured.exceeded_limit:
                for name,raw,omitted,ceiling in stream_events:
                    if type(omitted) is not int or omitted<0:
                        unproved_transport=True
                    elif omitted>0:
                        if len(raw)!=ceiling:
                            unproved_transport=True
                        else:
                            transport_bounds.append({
                                "unit":"bytes","threshold":ceiling,
                                "observed_extent":len(raw),
                                "missing_extent":omitted,
                                "affected_scope":pol.source_id+":call0001:"+name,
                                "reason":"CAPTURE_LIMIT"})
                if not transport_bounds:
                    unproved_transport=True
            elif (captured.stdout_omitted_at_least or
                  captured.stderr_omitted_at_least):
                unproved_transport=True
            can_promote=(not unproved_worker_limit and not unproved_transport
                         and not any(r.limit_applied for r in receipts)
                         and "SOURCE_LIMIT_REACHED" not in errors
                         and "EVIDENCE_PERSIST_FAILED" not in errors)
            multiple=tuple(worker_bounds+transport_bounds) if can_promote else ()
            if multiple and captured.timed_out:
                multiple += ({
                    "unit":"seconds","threshold":cap,
                    "observed_extent":captured.elapsed_seconds,
                    "missing_extent":None,
                    "affected_scope":pol.source_id+":call0001:transport",
                    "reason":"TIME_BUDGET_EXCEEDED"},)
            # A single witnessed worker event uses the same list envelope as
            # simultaneous events; old v0.5 applies only to a sole time event.
            if multiple:
                timeout_witness=None
            if not receipts and errors:
                return done("FAILED","ACQUISITION_ERROR",receipts,errors,
                            captured.elapsed_seconds,limited,None,False,
                            captured.timed_out,timeout_witness,multiple)
            if not receipts:
                return done("UNAVAILABLE","SOURCE_ABSENT",receipts,errors,
                            captured.elapsed_seconds,limited,None,complete,
                            captured.timed_out,timeout_witness,multiple)
            if complete:
                return done("CAPTURED","BYTES_PRESERVED",receipts,errors,
                            captured.elapsed_seconds,False,0,True)
            return done("PARTIAL","SOURCE_INCOMPLETE" if not limited else "CAPTURE_LIMIT",
                        receipts,errors,captured.elapsed_seconds,limited,None,False,
                        captured.timed_out,timeout_witness,multiple)
    except ProbeCapacityError:
        return done("DENIED","CONCURRENCY_LIMIT")
    finally:
        calls.end(request.run_id,request.source_id,time.monotonic()-started)
