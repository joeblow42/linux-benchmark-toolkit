"""O1 device execution only following exact run/target consent and device validation."""
import time
from .o1 import plan_optional
from .runtime import _resolve_executable, _capture_child, ProbeCapacityError

def execute_optional(request,attempt,subcall,writer,slots,calls,*,privileged_session=None):
    """O1 consent required. Session helper is allowed for SRC-13 only."""
    from .safety import decide_source,initial_source_policies
    policy={p.source_id:p for p in initial_source_policies()}.get(request.source_id)
    auth=decide_source(request,remaining_seconds=writer.meter.time_remaining(),
         remaining_bytes=writer.meter.max_bytes-writer.meter.bytes_reserved)
    if not auth.allowed:return {"disposition":"DENIED","reason":auth.reason,"receipts":()}
    if request.run_id!=writer.run_id:return {"disposition":"DENIED","reason":"RUN_ID_MISMATCH","receipts":()}
    try: plan=plan_optional(request)
    except PermissionError as exc:
        return {"disposition":"DENIED","reason":str(exc),"receipts":()}
    if not calls.begin(request.run_id,request.source_id,subcall):
        return {"disposition":"DENIED","reason":"SOURCE_CALL_LIMIT","receipts":()}
    start=time.monotonic()
    try:
        with slots.hold("O1"):
            binary=_resolve_executable(plan.argv[0])
            if binary is None:return {"disposition":"UNAVAILABLE","reason":"EXECUTABLE_NOT_FOUND","receipts":()}
            cap=min(plan.max_seconds,calls.remaining(request.run_id,request.source_id),
                    writer.meter.time_remaining())
            if cap<=0:return {"disposition":"DENIED","reason":"TIME_BUDGET_EXCEEDED","receipts":()}
            if privileged_session is not None and request.source_id=="SRC-13":
                from .privileged_session import PrivilegedSessionError
                try:
                    captured=privileged_session.capture(request,plan,seconds=cap)
                except PrivilegedSessionError:
                    return {"disposition":"FAILED","reason":"PRIVILEGED_HELPER_ERROR",
                            "receipts":()}
            else:
                captured=_capture_child((binary,)+plan.argv[1:],plan.max_bytes,
                    plan.max_bytes,cap,plan.max_bytes)
            receipts=[]
            writer_events=[]
            for label,raw in (("stdout",captured.stdout),("stderr",captured.stderr)):
                if not raw:continue
                seal=writer.seal_chunks(policy,attempt,
                    "call%04d-%s"%(subcall+1,label),(raw,),
                    per_stream_limit=plan.max_bytes)
                if seal.failure:
                    return {"disposition":"FAILED","reason":"EVIDENCE_PERSIST_FAILED",
                            "receipts":tuple(receipts)}
                receipts.append(seal.receipt)
                writer_events.extend(seal.limit_events)
            # RP-02.3 / Increment 39: the shared writer, not a transport
            # guess, must have actually clipped a same-run original. The
            # helper can privately reduce its cumulative transport ceiling;
            # never attribute such an event to a writer without its seal.
            limit_witnesses=()
            transport_missing=(captured.stdout_omitted_at_least+
                               captured.stderr_omitted_at_least)
            clipped=[x for x in receipts if x.limit_applied]
            if (not captured.timed_out and not captured.exceeded_limit
                    and transport_missing==0
                    and len(writer_events)==1 and len(clipped)==1
                    and writer_events[0].get("dimension")=="writer_run_bytes"):
                event=writer_events[0]
                if (type(event.get("threshold")) is int
                        and event["threshold"]==writer.meter.max_bytes
                        and event.get("observed_extent")==writer.meter.max_bytes
                        and event.get("omitted_at_least")==clipped[0].omitted_at_least
                        and clipped[0].omitted_at_least>0
                        and writer.meter.bytes_reserved==writer.meter.max_bytes):
                    limit_witnesses=({
                        "unit":"bytes",
                        "threshold":event["threshold"],
                        "observed_extent":event["observed_extent"],
                        "missing_extent":event["omitted_at_least"],
                        "affected_scope":request.source_id+
                            ":call%04d:run:writer"%(subcall+1),
                        "reason":"CAPTURE_LIMIT"},)
            limited=captured.exceeded_limit or captured.timed_out or any(
                    r.limit_applied for r in receipts)
            if limited:reason="TIME_BUDGET_EXCEEDED" if captured.timed_out else "CAPTURE_LIMIT"
            elif captured.returncode:reason="ACQUISITION_ERROR"
            else:reason="BYTES_PRESERVED"
            state="PARTIAL" if receipts and (limited or captured.returncode) else (
                  "FAILED" if limited or captured.returncode else "CAPTURED")
            return {"disposition":state,"reason":reason,"receipts":tuple(receipts),
                    "preflight_approved":True,"approved_argv":tuple(plan.argv),
                    "exit_code":captured.returncode,
                    "elapsed_seconds":captured.elapsed_seconds,
                    "timed_out":captured.timed_out,
                    "capture_limited":captured.exceeded_limit or any(
                        receipt.limit_applied for receipt in receipts),
                    "limit_witnesses":limit_witnesses,
                    "transport_exceeded_limit":captured.exceeded_limit,
                    "transport_timed_out":captured.timed_out,
                    "transport_omitted_at_least":transport_missing,
                    "missing_extent_known_at_least":
                        captured.stdout_omitted_at_least+
                        captured.stderr_omitted_at_least+
                        sum(receipt.omitted_at_least for receipt in receipts)}
    except ProbeCapacityError:
        return {"disposition":"DENIED","reason":"CONCURRENCY_LIMIT","receipts":()}
    finally:
        calls.end(request.run_id,request.source_id,time.monotonic()-start)
