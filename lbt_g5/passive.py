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

def _transport_decode(payload: bytes, policy):
    records=[]
    errors=[]
    end=None
    total=0
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
        if "error" in msg:
            errors.append(str(msg.get("error","READ_FAILED"))[:80])
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
        records.append((raw, bool(msg.get("limited"))))
    # All records from an incomplete worker are still real and preservable.
    return records,errors,end,total

def acquire_passive(request: SourceRequest, attempt: str, writer: EvidenceWriter,
                    slots: ProbeSlots, calls: SourceCallBudget) -> PassiveOutcome:
    pol={p.source_id:p for p in initial_source_policies()}.get(request.source_id)
    def done(disposition,reason,receipts=(),errors=(),elapsed=0.0,
             limited=False,missing=None,complete=False):
        return PassiveOutcome(request.source_id,disposition,reason,tuple(receipts),
                              tuple(),tuple(errors),len(receipts),
                              sum(r.byte_count for r in receipts),elapsed,
                              limited,missing,complete)
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
            records,errors,end,total=_transport_decode(captured.stdout,pol)
            receipts=[]
            limited=captured.exceeded_limit or captured.timed_out
            for i,(original,record_limit) in enumerate(records,1):
                artifact=f"item{i:04d}"
                result=writer.seal_chunks(pol,attempt,artifact,(original,))
                if result.failure:
                    errors.append("EVIDENCE_PERSIST_FAILED")
                    break
                receipt=result.receipt
                receipts.append(receipt)
                limited=limited or record_limit or receipt.limit_applied
            complete=(end is not None and captured.returncode==0 and not captured.timed_out
                      and not captured.exceeded_limit and not errors and not limited
                      and len(records)==end.get("entries") and total==end.get("bytes"))
            if end and end.get("limited"): limited=True
            if captured.returncode not in (0,None): errors.append("WORKER_EXIT_NONZERO")
            if captured.timed_out: errors.append("TIME_BUDGET_EXCEEDED")
            if captured.exceeded_limit: errors.append("TRANSPORT_LIMIT")
            if not end: errors.append("INCOMPLETE_WORKER_STREAM")
            if not receipts and errors:
                return done("FAILED","ACQUISITION_ERROR",receipts,errors,
                            captured.elapsed_seconds,limited,None,False)
            if not receipts:
                return done("UNAVAILABLE","SOURCE_ABSENT",receipts,errors,
                            captured.elapsed_seconds,limited,None,complete)
            if complete:
                return done("CAPTURED","BYTES_PRESERVED",receipts,errors,
                            captured.elapsed_seconds,False,0,True)
            return done("PARTIAL","SOURCE_INCOMPLETE" if not limited else "CAPTURE_LIMIT",
                        receipts,errors,captured.elapsed_seconds,limited,None,False)
    except ProbeCapacityError:
        return done("DENIED","CONCURRENCY_LIMIT")
    finally:
        calls.end(request.run_id,request.source_id,time.monotonic()-started)
