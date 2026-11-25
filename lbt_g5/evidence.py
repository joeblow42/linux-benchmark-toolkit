"""G5-02: private first-preserved original evidence, never overwritten.

Only callers holding a validated source authorization should feed this writer.
No source reads, subprocesses or collection occur in this module. Incomplete
staging artifacts are private and are NEVER advertised as sealed originals.
"""
from dataclasses import dataclass, field
import hashlib
import os
import re
import secrets
import stat
import threading
import time
from .safety import RUN_BYTES, RUN_SECONDS, SourcePolicy, valid_run_id, initial_source_policies

@dataclass(frozen=True)
class ArtifactReceipt:
    evidence_id: str
    run_id: str
    collector_id: str
    source_id: str
    attempt: str
    artifact: str
    private_relative_path: str
    sha256: str
    byte_count: int
    complete: bool
    limit_applied: bool
    omitted_at_least: int

@dataclass(frozen=True)
class EvidenceFailure:
    status: str
    reason: str
    diagnostic: str
    captured_bytes: int

@dataclass(frozen=True)
class SealResult:
    receipt: ArtifactReceipt | None
    failure: EvidenceFailure | None
    # Private in-memory operational facts; not part of sealed original receipt.
    limit_events: list[dict] = field(default_factory=list)

@dataclass
class RunMeter:
    """Monotonic run budget; conservative reservation survives write failure."""
    max_bytes: int = RUN_BYTES
    max_seconds: float = RUN_SECONDS
    started: float = field(default_factory=time.monotonic)
    bytes_reserved: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        if not (0 < self.max_bytes <= RUN_BYTES and 0 < self.max_seconds <= RUN_SECONDS):
            raise ValueError("run budget exceeds G4-07 ceiling")

    def reserve(self, wanted: int) -> int:
        if wanted < 0:
            raise ValueError("negative reservation")
        with self._lock:
            if time.monotonic() - self.started >= self.max_seconds:
                return 0
            count = min(wanted, max(0, self.max_bytes - self.bytes_reserved))
            self.bytes_reserved += count
            return count

    def time_remaining(self) -> float:
        return max(0.0, self.max_seconds - (time.monotonic()-self.started))

def evidence_identifier(run_id: str, policy: SourcePolicy, attempt: str, artifact: str) -> str:
    if not valid_run_id(run_id) or re.fullmatch(r"[0-9]{2,}",attempt) is None:
        raise ValueError("invalid run ID or attempt")
    if re.fullmatch(r"[a-z][a-z0-9-]*",artifact) is None:
        raise ValueError("invalid artifact discriminator")
    return f"{run_id}_{policy.collector_id}_{policy.source_id}_{attempt}:{artifact}"

def _private_dir(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=parent_fd)
    mode = os.fstat(fd)
    if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.geteuid() or mode.st_mode & 0o077:
        os.close(fd)
        raise PermissionError("private evidence directory has unsafe ownership or permissions")
    return fd

class EvidenceWriter:
    def __init__(self, run_directory: str, run_id: str, meter: RunMeter | None = None):
        if not valid_run_id(run_id) or os.path.basename(os.path.abspath(run_directory)) != run_id:
            raise ValueError("run directory identity mismatch")
        if os.path.realpath(run_directory) != os.path.abspath(run_directory):
            raise ValueError("symlink in run directory path")
        self.run_id = run_id
        self.run_directory = run_directory
        self.meter = meter if meter is not None else RunMeter()
        self._source_lock = threading.Lock()
        self._source_reserved: dict[tuple[str,str],int] = {}

    def seal_chunks(self, policy: SourcePolicy, attempt: str, artifact: str,
                    chunks, *, per_stream_limit: int | None = None) -> SealResult:
        """Seal bytes from an ALREADY authorized stream; stop before overrunning quota.

        This does not impose a hard deadline on a blocking iterator; executable
        collectors must use G4-07 bounded worker/process controls in G5-03.
        """
        identifier = evidence_identifier(self.run_id,policy,attempt,artifact)
        approved = {p.source_id:p for p in initial_source_policies()}.get(policy.source_id)
        if approved != policy:
            raise ValueError("unapproved source policy or altered ceiling")
        fixed_stream = (12*1024*1024 if artifact=="stdout" else 4*1024*1024) \
            if policy.source_id in ("SRC-05","SRC-11","SRC-20") and artifact in ("stdout","stderr") else policy.max_bytes
        if per_stream_limit is not None and per_stream_limit > fixed_stream:
            raise ValueError("stream cap exceeds approved ceiling")
        if per_stream_limit is not None and (per_stream_limit < 0 or per_stream_limit > policy.max_bytes):
            raise ValueError("stream limit outside approved source ceiling")
        limit = fixed_stream if per_stream_limit is None else per_stream_limit
        written = 0
        truncated = False
        omitted_at_least = 0
        writer_events = []
        run_fd = private_fd = evidence_fd = out_fd = None
        staging = identifier + ".partial-" + secrets.token_hex(8)
        try:
            run_fd = os.open(self.run_directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            private_fd = _private_dir(run_fd,"private")
            evidence_fd = _private_dir(private_fd,"evidence")
            out_fd = os.open(staging,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=evidence_fd)
            h = hashlib.sha256()
            for block in chunks:
                if type(block) is not bytes:
                    raise TypeError("source chunks must be bytes")
                if not block:
                    continue
                available = max(0, limit-written)
                with self._source_lock:
                    key = (policy.source_id,)
                    remaining_source = max(
                        0,policy.max_bytes-self._source_reserved.get(key,0))
                    # Bounded reservation is still enforced by RunMeter.
                    # A before/after witness cannot infer a reason when another
                    # writer raced its reservation or the timer expired.
                    remaining_run = max(
                        0,self.meter.max_bytes-self.meter.bytes_reserved)
                    take = self.meter.reserve(min(len(block),available,remaining_source))
                    self._source_reserved[key] = self._source_reserved.get(key,0)+take
                    source_after=self._source_reserved[key]
                if take:
                    # os.write may be short. Account only bytes actually persisted.
                    view = memoryview(block)[:take]
                    offset = 0
                    while offset < take:
                        count = os.write(out_fd,view[offset:])
                        if count <= 0:
                            raise OSError("no progress writing evidence")
                        h.update(view[offset:offset+count])
                        offset += count
                    written += take
                if take < len(block):
                    truncated = True
                    omitted_at_least = len(block)-take
                    # Record EACH actually reached quota, never infer one
                    # dominant reason for tied source/stream/run bounds.
                    # Reservation races or time expiry are not byte facts.
                    expected=min(len(block),available,
                                 remaining_source,remaining_run)
                    if take==expected and self.meter.time_remaining()>0:
                        if (take==available and written==limit):
                            writer_events.append({
                                "dimension":"writer_stream_bytes",
                                "threshold":limit,"observed_extent":written,
                                "omitted_at_least":omitted_at_least})
                        if (take==remaining_source and
                                source_after==policy.max_bytes):
                            writer_events.append({
                                "dimension":"writer_source_bytes",
                                "threshold":policy.max_bytes,
                                "observed_extent":source_after,
                                "omitted_at_least":omitted_at_least})
                        if (take==remaining_run and
                                self.meter.bytes_reserved==self.meter.max_bytes):
                            writer_events.append({
                                "dimension":"writer_run_bytes",
                                "threshold":self.meter.max_bytes,
                                "observed_extent":self.meter.max_bytes,
                                "omitted_at_least":omitted_at_least})
                    break
                if self.meter.time_remaining() <= 0:
                    truncated = True
                    break
            os.fsync(out_fd)
            os.close(out_fd)
            out_fd = None
            # Hard-link publish is no-replace even if a race creates the target.
            os.link(staging,identifier,src_dir_fd=evidence_fd,dst_dir_fd=evidence_fd,follow_symlinks=False)
            os.fsync(evidence_fd)
            os.unlink(staging,dir_fd=evidence_fd)
            os.fsync(evidence_fd)
            return SealResult(ArtifactReceipt(identifier,self.run_id,
                policy.collector_id,policy.source_id,attempt,artifact,
                "private/evidence/"+identifier,h.hexdigest(),written,
                not truncated,truncated,omitted_at_least),None,writer_events)
        except OSError as exc:
            # Staging retains any acquired partial bytes privately; no fake
            # sealed evidence ID or digest is returned on failure.
            return SealResult(None,EvidenceFailure("FAILED","EVIDENCE_PERSIST_FAILED",
                    type(exc).__name__+": "+str(exc),written))
        finally:
            for fd in (out_fd,evidence_fd,private_fd,run_fd):
                if fd is not None:
                    os.close(fd)
