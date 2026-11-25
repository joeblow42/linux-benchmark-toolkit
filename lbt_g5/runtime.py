"""G5-02: fixed D1 local command plans and bounded original-byte capture.

This module has NO import-time effects and is NOT connected to the legacy
launcher. Only fixed vetted D1 command templates can be dispatched. O1, mount
statvfs and offline package DB operations remain unavailable pending dedicated
safe adapters. Status values here describe transport, not IC-04 status pairs.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import os
import selectors
import signal
import stat
import subprocess
import threading
import time

from .safety import (SourceRequest, decide_source, initial_source_policies,
                     MAX_ORDINARY_PROBES, MAX_O1_PROBES)
from .evidence import EvidenceWriter, ArtifactReceipt

_MIB = 1024 * 1024
# Fixed, read-only, local metadata. Never receive argv supplied by an operator.
# In particular LSBLK only requests sysfs/udev attributes, not filesystem probing.
_APPROVED_COMMANDS = {
    "SRC-05": (("lscpu",),),
    "SRC-11": (("lsblk", "--bytes", "--json", "--output",
                "NAME,KNAME,TYPE,SIZE,RO,RM,MODEL,SERIAL,TRAN"),),
    "SRC-20": (("lspci", "-nn"),),
    "SRC-23": (("ip", "-j", "addr", "show"),
               ("ip", "-j", "route", "show")),
}
# G4-07: command stdout/stderr 12/4 MiB for 05, 11, 20; 23 has 16 MiB
# across two calls, each 5 seconds. Per-call cap 8 MiB for SRC-23.
_STREAM_LIMITS = {"SRC-05": (12*_MIB,4*_MIB),
                  "SRC-11": (12*_MIB,4*_MIB),
                  "SRC-20": (12*_MIB,4*_MIB),
                  "SRC-23": (8*_MIB,8*_MIB)}
_TRUSTED_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")


@dataclass(frozen=True)
class CommandPlan:
    source_id: str
    operation_id: str
    subcall: int
    argv: tuple[str, ...]
    stdout_limit: int
    stderr_limit: int
    max_seconds: float


@dataclass(frozen=True)
class TransportCapture:
    stdout: bytes
    stderr: bytes
    returncode: int | None
    elapsed_seconds: float
    timed_out: bool
    exceeded_limit: bool
    stdout_omitted_at_least: int
    stderr_omitted_at_least: int


@dataclass(frozen=True)
class SourceCommandOutcome:
    # Internal transport category only; not an approved status/reason pair.
    disposition: str
    reason: str
    source_id: str
    argv: tuple[str,...] | None
    stdout: ArtifactReceipt | None
    stderr: ArtifactReceipt | None
    exit_code: int | None
    elapsed_seconds: float
    timed_out: bool
    capture_limited: bool
    missing_extent_known_at_least: int
    limit_witness: dict | None = None


def command_plan(source_id: str, subcall: int = 0) -> CommandPlan:
    """Return a fixed, catalog-checked plan or refuse; never source execution."""
    policy = {p.source_id:p for p in initial_source_policies()}.get(source_id)
    plans = _APPROVED_COMMANDS.get(source_id)
    if policy is None or policy.authorization_class != "D1" or plans is None:
        raise ValueError("source has no approved executable command adapter")
    if type(subcall) is not int or not 0 <= subcall < len(plans):
        raise ValueError("subcall outside registered source scope")
    stdout_cap, stderr_cap = _STREAM_LIMITS[source_id]
    seconds = min(policy.max_seconds, policy.per_target_seconds or policy.max_seconds)
    return CommandPlan(source_id,policy.operation_id,subcall,plans[subcall],
                       stdout_cap,stderr_cap,float(seconds))


def _resolve_executable(binary: str) -> str | None:
    """Restrict resolution to trusted system-owned, non-writable executables."""
    if not binary or "/" in binary:
        return None
    for dirname in _TRUSTED_DIRS:
        candidate = os.path.realpath(os.path.join(dirname,binary))
        if not any(candidate.startswith(os.path.realpath(root).rstrip("/")+"/")
                   for root in _TRUSTED_DIRS):
            continue
        try:
            s = os.stat(candidate)
        except OSError:
            continue
        if (stat.S_ISREG(s.st_mode) and s.st_uid == 0
                and not (s.st_mode & 0o022) and os.access(candidate,os.X_OK)):
            return candidate
    return None


class ProbeCapacityError(RuntimeError):
    """A routine capacity refusal, not an internal programming defect."""


class ProbeSlots:
    """Nonblocking run-wide source concurrency; O1 excludes other probes."""
    def __init__(self):
        self._lock = threading.Lock()
        self._ordinary = 0
        self._o1 = 0

    @contextmanager
    def hold(self, cls: str):
        if cls not in ("D0","D1","O1"):
            raise ValueError("unknown/prohibited acquisition class")
        with self._lock:
            if cls == "O1":
                allowed = self._o1 < MAX_O1_PROBES and self._ordinary == 0
                if allowed: self._o1 += 1
            else:
                allowed = self._ordinary < MAX_ORDINARY_PROBES and self._o1 == 0
                if allowed: self._ordinary += 1
        if not allowed:
            raise ProbeCapacityError("concurrency ceiling reached")
        try:
            yield
        finally:
            with self._lock:
                if cls == "O1": self._o1 -= 1
                else: self._ordinary -= 1


class SourceCallBudget:
    """Reserve subcalls and cumulative execution seconds per (run, source)."""
    def __init__(self):
        self._lock = threading.Lock()
        self._records = {}

    def begin(self, run_id: str, source_id: str, subcall: int) -> bool:
        policy = {p.source_id:p for p in initial_source_policies()}.get(source_id)
        if policy is None: return False
        key = (run_id,source_id)
        with self._lock:
            used, elapsed, subcalls = self._records.get(key,(0,0.0,set()))
            if (used >= policy.max_entries or subcall in subcalls
                    or elapsed >= policy.max_seconds):
                return False
            self._records[key] = (used+1, elapsed, subcalls | {subcall})
            return True

    def end(self, run_id: str, source_id: str, elapsed: float) -> None:
        key = (run_id,source_id)
        with self._lock:
            used, old, subcalls = self._records[key]
            self._records[key] = (used,old+max(0.0,elapsed),subcalls)

    def remaining(self, run_id: str, source_id: str) -> float:
        policy = {p.source_id:p for p in initial_source_policies()}.get(source_id)
        if policy is None: return 0.0
        with self._lock:
            _, elapsed, _ = self._records.get((run_id,source_id),(0,0.0,set()))
        return max(0.0,policy.max_seconds-elapsed)


def _terminate_group(proc: subprocess.Popen) -> None:
    if proc.poll() is not None: return
    try:
        os.killpg(proc.pid,signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        proc.kill()


def _capture_child(argv: tuple[str,...], stdout_cap: int, stderr_cap: int,
                   deadline_seconds: float, combined_cap: int | None = None) -> TransportCapture:
    """Bounded process worker. For synthetic fixture tests only, argv is injectable.

    Production dispatch exclusively supplies argv from command_plan(), after
    controlled binary resolution. A finite wall deadline is applied to the
    process group, and both pipes are drained without unbounded communicate().
    """
    if deadline_seconds <= 0 or stdout_cap < 0 or stderr_cap < 0 or (combined_cap is not None and combined_cap < 0):
        raise ValueError("invalid command safety limit")
    now = time.monotonic()
    proc = subprocess.Popen(argv,stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
        close_fds=True,cwd="/",env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"})
    buffers = {"stdout":bytearray(), "stderr":bytearray()}
    caps = {"stdout":stdout_cap,"stderr":stderr_cap}
    overflow = {"stdout":0,"stderr":0}
    timed_out = False
    over_limit = False
    sel = selectors.DefaultSelector()
    try:
        for label, pipe in (("stdout",proc.stdout),("stderr",proc.stderr)):
            os.set_blocking(pipe.fileno(),False)
            sel.register(pipe,selectors.EVENT_READ,label)
        while sel.get_map():
            remaining=deadline_seconds-(time.monotonic()-now)
            if remaining <= 0:
                timed_out=True
                _terminate_group(proc)
                break
            for key,_ in sel.select(timeout=min(remaining,0.10)):
                label=key.data
                try: chunk=os.read(key.fileobj.fileno(),65536)
                except BlockingIOError: continue
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                available=max(0,caps[label]-len(buffers[label]))
                if combined_cap is not None:
                    available=min(available,max(0,combined_cap-sum(map(len,buffers.values()))))
                take=min(available,len(chunk))
                buffers[label].extend(chunk[:take])
                if take<len(chunk):
                    overflow[label] += len(chunk)-take
                    over_limit=True
                    _terminate_group(proc)
                    break
            if over_limit: break
        if proc.poll() is None:
            remaining=deadline_seconds-(time.monotonic()-now)
            if remaining <= 0: timed_out=True
            if timed_out or over_limit: _terminate_group(proc)
        try: proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            _terminate_group(proc)
            proc.wait(timeout=0.5)
    finally:
        sel.close()
        for pipe in (proc.stdout,proc.stderr):
            if pipe is not None: pipe.close()
        if proc.poll() is None:
            _terminate_group(proc)
            proc.wait(timeout=1)
    return TransportCapture(bytes(buffers["stdout"]),bytes(buffers["stderr"]),
                            proc.returncode,time.monotonic()-now,timed_out,
                            over_limit,overflow["stdout"],overflow["stderr"])


def execute_source_command(request: SourceRequest, subcall: int,
                           attempt: str, writer: EvidenceWriter,
                           slots: ProbeSlots, calls: SourceCallBudget) -> SourceCommandOutcome:
    """Run only fixed D1 templates, capture bounded bytes, then seal originals.

    The callable never permits O1; explicit source-specific O1 implementations
    must be designed separately. No caller-provided argv or executor injection.
    """
    denied=decide_source(request,remaining_seconds=writer.meter.time_remaining(),
            remaining_bytes=writer.meter.max_bytes-writer.meter.bytes_reserved)
    def result(disposition,reason,argv=None,out=None,err=None,code=None,
               elapsed=0.0,timed_out=False,limited=False,missing=0,
               limit_witness=None):
        return SourceCommandOutcome(disposition,reason,request.source_id,argv,
                                    out,err,code,elapsed,timed_out,limited,missing,
                                    limit_witness)
    if not denied.allowed:
        return result("DENIED",denied.reason)
    if writer.run_id != request.run_id:
        return result("DENIED","RUN_ID_MISMATCH")
    try: plan=command_plan(request.source_id,subcall)
    except ValueError:
        return result("DENIED","NO_SAFE_ADAPTER")
    if not calls.begin(request.run_id,request.source_id,subcall):
        return result("DENIED","SOURCE_CALL_BUDGET_OR_DUPLICATE")
    start=time.monotonic()
    try:
        with slots.hold(denied.source.authorization_class):
            tool=_resolve_executable(plan.argv[0])
            if tool is None:
                return result("UNAVAILABLE","EXECUTABLE_NOT_FOUND",plan.argv)
            limit=min(plan.max_seconds,calls.remaining(request.run_id,request.source_id),
                      writer.meter.time_remaining())
            if limit <= 0:
                return result("DENIED","TIME_BUDGET_EXCEEDED",plan.argv)
            try:
                captured=_capture_child((tool,)+plan.argv[1:],plan.stdout_limit,
                                        plan.stderr_limit,limit,
                                        8*_MIB if request.source_id == "SRC-23" else None)
            except OSError as exc:
                return result("FAILED",type(exc).__name__,plan.argv)
            receipts=[]
            for name,data in (("stdout",captured.stdout),("stderr",captured.stderr)):
                if not data:
                    receipts.append(None)
                    continue
                seal=writer.seal_chunks(denied.source,attempt,f"call{subcall+1:04d}-{name}",[data])
                if seal.failure is not None:
                    return result("FAILED","EVIDENCE_PERSIST_FAILED",plan.argv,
                                  receipts[0] if receipts else None,None,captured.returncode,
                                  captured.elapsed_seconds,captured.timed_out,
                                  captured.exceeded_limit)
                receipts.append(seal.receipt)
            writer_truncated=any(receipt is not None and receipt.limit_applied for receipt in receipts)
            incomplete=captured.timed_out or captured.exceeded_limit or writer_truncated
            outcome="PARTIAL" if incomplete and any(receipts) else \
                    "FAILED" if incomplete else "CAPTURED"
            reason=("TIME_BUDGET_EXCEEDED" if captured.timed_out else
                    "CAPTURE_LIMIT" if captured.exceeded_limit or writer_truncated else
                    "EXIT_NONZERO" if captured.returncode else "BYTES_PRESERVED")
            if not incomplete and captured.returncode:
                outcome="PARTIAL" if any(receipts) else "FAILED"
            # Only actual applied deadlines/capture caps prove the dimension.
            bound=None
            scope=f"{request.source_id}:call{subcall+1:04d}:"
            if captured.timed_out:
                bound=dict(unit="seconds",threshold=float(limit),
                           observed_extent=float(captured.elapsed_seconds),
                           missing_extent=None,affected_scope=scope+"transport",
                           reason="TIME_BUDGET_EXCEEDED")
            elif captured.exceeded_limit:
                if captured.stdout_omitted_at_least>0:
                    stream="stdout"
                    threshold=plan.stdout_limit
                    retained=len(captured.stdout)
                    omitted=captured.stdout_omitted_at_least
                elif captured.stderr_omitted_at_least>0:
                    stream="stderr"
                    threshold=plan.stderr_limit
                    retained=len(captured.stderr)
                    omitted=captured.stderr_omitted_at_least
                else:
                    stream="transport"
                    threshold=(8*_MIB if request.source_id=="SRC-23"
                               else plan.stdout_limit+plan.stderr_limit)
                    retained=len(captured.stdout)+len(captured.stderr)
                    omitted=None
                bound=dict(unit="bytes",threshold=threshold,
                           observed_extent=retained,missing_extent=omitted,
                           affected_scope=scope+stream,reason="CAPTURE_LIMIT")
            return result(outcome,reason,plan.argv,receipts[0],receipts[1],
                          captured.returncode,captured.elapsed_seconds,
                          captured.timed_out,captured.exceeded_limit or writer_truncated,
                          (captured.stdout_omitted_at_least+captured.stderr_omitted_at_least
                           +sum(receipt.omitted_at_least for receipt in receipts if receipt is not None)),
                          bound)
    except ProbeCapacityError:
        return result("DENIED","CONCURRENCY_LIMIT")
    finally:
        calls.end(request.run_id,request.source_id,time.monotonic()-start)
