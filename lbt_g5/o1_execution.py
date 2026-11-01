"""O1 device execution only following exact run/target consent and device validation."""
import time
from .o1 import plan_optional
from .runtime import _resolve_executable, _capture_child, ProbeCapacityError

def execute_optional(request,attempt,subcall,writer,slots,calls):
    """Never used automatically. Caller must present one-run source/target consent."""
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
            captured=_capture_child((binary,)+plan.argv[1:],plan.max_bytes,
                plan.max_bytes,cap,plan.max_bytes)
            receipts=[]
            for label,raw in (("stdout",captured.stdout),("stderr",captured.stderr)):
                if not raw:continue
                seal=writer.seal_chunks(policy,attempt,
                    "call%04d-%s"%(subcall+1,label),(raw,),
                    per_stream_limit=plan.max_bytes)
                if seal.failure:
                    return {"disposition":"FAILED","reason":"EVIDENCE_PERSIST_FAILED",
                            "receipts":tuple(receipts)}
                receipts.append(seal.receipt)
            limited=captured.exceeded_limit or captured.timed_out or any(
                    r.limit_applied for r in receipts)
            if limited:reason="TIME_BUDGET_EXCEEDED" if captured.timed_out else "CAPTURE_LIMIT"
            elif captured.returncode:reason="ACQUISITION_ERROR"
            else:reason="BYTES_PRESERVED"
            state="PARTIAL" if receipts and (limited or captured.returncode) else (
                  "FAILED" if limited or captured.returncode else "CAPTURED")
            return {"disposition":state,"reason":reason,"receipts":tuple(receipts)}
    except ProbeCapacityError:
        return {"disposition":"DENIED","reason":"CONCURRENCY_LIMIT","receipts":()}
    finally:
        calls.end(request.run_id,request.source_id,time.monotonic()-start)
