"""G5-02 local-only D1: statvfs bounded worker and dpkg installed metadata."""
from dataclasses import dataclass
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

def acquire_additional(request:SourceRequest,attempt:str,writer:EvidenceWriter,
                       slots:ProbeSlots,calls:SourceCallBudget,
                       *,source14_evidence:bytes|None=None)->AdditionalOutcome:
    def out(disposition,reason,artifacts=(),targets=(),errors=(),elapsed=0.,limited=False):
        return AdditionalOutcome(request.source_id,disposition,reason,tuple(artifacts),
                                 tuple(targets),tuple(errors),elapsed,limited)
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
    try:
        with slots.hold("D1"):
            for i,(label,argv) in enumerate(plans):
                if not calls.begin(request.run_id,request.source_id,i):
                    limited=True;errors.append("INVOCATION_LIMIT");break
                callstart=time.monotonic()
                try:
                    binary=_resolve_executable(argv[0])
                    if binary is None:
                        errors.append("EXECUTABLE_NOT_FOUND");break
                    seconds=min(8.0 if request.source_id=="SRC-28" else 2.0,
                        calls.remaining(request.run_id,request.source_id),
                        writer.meter.time_remaining())
                    if seconds<=0:
                        limited=True;errors.append("TIME_BUDGET_EXCEEDED");break
                    transport=_capture_child((binary,)+argv[1:],
                        8*MIB if request.source_id=="SRC-28" else 1*MIB,
                        1*MIB if request.source_id=="SRC-28" else 128*1024,
                        seconds,8*MIB if request.source_id=="SRC-28" else 2*MIB)
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
                    if transport.returncode:errors.append("COMMAND_EXIT_NONZERO")
                    if transport.exceeded_limit:
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
        return out("PARTIAL","CAPTURE_LIMIT" if limited else "SOURCE_INCOMPLETE",
                   receipts,targets,errors,elapsed,limited)
    if "EXECUTABLE_NOT_FOUND" in errors:
        return out("UNAVAILABLE","EXECUTABLE_NOT_FOUND",errors=errors,elapsed=elapsed)
    return out("FAILED","ACQUISITION_ERROR",errors=errors,elapsed=elapsed,limited=limited)
