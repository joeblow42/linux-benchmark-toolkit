"""G5-02 append-only, restricted source-attempt receipts.

Receipts are operational records, NOT the G5-04 canonical schema or IC-04
14-field validated status envelope. That envelope is emitted at G5-04 after
normalization. Every evaluated source must receive a receipt, including refusal,
absence, partial capture and preservation failures.
"""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
import re
import secrets
import stat
from .safety import valid_run_id, initial_source_policies, RUN_SECONDS

@dataclass(frozen=True)
class AttemptReceipt:
    schema_version: str
    run_id: str
    attempt_id: str
    collector_id: str
    source_id: str
    operation_id: str
    authorization_class: str
    invocation: str
    target: str | None
    decision: str
    outcome: str
    reason: str
    acquired_bytes: int
    evidence_ids: tuple[str,...]
    missing_extent_known_at_least: int | None
    errors: tuple[str,...]
    observed_utc: str
    # Reserved for G5-04 validated status envelope. Not a status assertion.
    status_record_pending: bool = True
    source_paths: tuple[str,...] = ()
    unavailable_fields: tuple[str,...] = ()
    exit_code: int | None = None
    elapsed_seconds: float | None = None
    timed_out: bool = False
    capture_limited: bool = False
    # G5-02 optional O1 execution witness (not a G5-04 schema field).
    authorization_provenance: dict | None = None

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")

def build_attempt(run_id,source_id,attempt,decision,outcome,reason,
                  *,evidence=(),bytes_count=0,missing=None,errors=(),
                  invocation="NOT_INVOKED",target=None,source_paths=(),unavailable_fields=(),
                  exit_code=None,elapsed_seconds=None,timed_out=False,capture_limited=False,
                  authorization_provenance=None):
    policy={p.source_id:p for p in initial_source_policies()}.get(source_id)
    if not valid_run_id(run_id) or policy is None:
        raise ValueError("invalid source or run identity")
    if type(attempt) is not str or not re.fullmatch(r"[0-9]{2,}",attempt):
        raise ValueError("invalid attempt")
    ids=tuple(r.evidence_id for r in evidence)
    if any(not x.startswith(run_id+"_"+policy.collector_id+"_"+source_id+"_") for x in ids):
        raise ValueError("evidence not from this run, owner or source")
    if bytes_count<0 or bytes_count>policy.max_bytes:
        raise ValueError("invalid preserved-byte count")
    if missing is not None and missing<0:
        raise ValueError("invalid missing extent")
    if exit_code is not None and (type(exit_code) is not int or abs(exit_code)>65535):
        raise ValueError("invalid process exit code")
    if elapsed_seconds is not None and (not isinstance(elapsed_seconds,(int,float))
        or elapsed_seconds<0 or elapsed_seconds!=elapsed_seconds or elapsed_seconds>RUN_SECONDS):
        raise ValueError("invalid source elapsed duration")
    if len(unavailable_fields)>64 or len(str(unavailable_fields))>8192:
        raise ValueError("unbounded unavailable-attribute diagnostics")
    if len(errors)>64 or len(str(errors))>8192:
        raise ValueError("unbounded diagnostics")
    if authorization_provenance is not None:
        if (policy.authorization_class != "O1" or decision != "ALLOW"
                or type(authorization_provenance) is not dict
                or len(str(authorization_provenance)) > 4096):
            raise ValueError("invalid O1 operational authorization provenance")
    return AttemptReceipt("g5-02-attempt-0.2" if authorization_provenance else
                          "g5-02-attempt-0.1",run_id,
        f"{source_id}-{attempt}",policy.collector_id,source_id,
        policy.operation_id,policy.authorization_class,
        invocation,target,decision,outcome,reason,bytes_count,
        ids,missing,tuple(str(e)[:256] for e in errors),utc_now(),
        source_paths=tuple(source_paths),unavailable_fields=tuple(unavailable_fields),
        exit_code=exit_code,elapsed_seconds=elapsed_seconds,
        timed_out=bool(timed_out),capture_limited=bool(capture_limited),
        authorization_provenance=authorization_provenance)

def _safe_private_dir(parent_fd,name):
    try: os.mkdir(name,0o700,dir_fd=parent_fd)
    except FileExistsError: pass
    fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
    mode=os.fstat(fd)
    if (not stat.S_ISDIR(mode.st_mode) or mode.st_uid!=os.geteuid()
        or mode.st_mode&0o077):
        os.close(fd)
        raise PermissionError("unsafe private operational records directory")
    return fd

def commit_attempt(run_directory,receipt):
    """Durable exclusive create. Never modifies a previously committed receipt."""
    if not isinstance(receipt,AttemptReceipt):
        raise TypeError("validated AttemptReceipt required")
    if os.path.basename(os.path.abspath(run_directory))!=receipt.run_id:
        raise ValueError("run directory mismatch")
    name=receipt.attempt_id+".json"
    fields=asdict(receipt)
    if fields["authorization_provenance"] is None:
        del fields["authorization_provenance"]  # Preserve legacy 0.1 receipt envelope.
    payload=(json.dumps(fields,sort_keys=True,separators=(",",":"),
                        allow_nan=False)+"\n").encode("utf-8")
    if len(payload)>256*1024:
        raise ValueError("attempt receipt exceeds limit")
    run_fd=private_fd=attempt_fd=temp_fd=None
    staging=".staging-"+secrets.token_hex(12)
    try:
        run_fd=os.open(run_directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        private_fd=_safe_private_dir(run_fd,"private")
        attempt_fd=_safe_private_dir(private_fd,"source_attempt_records")
        temp_fd=os.open(staging,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                        0o600,dir_fd=attempt_fd)
        data=memoryview(payload)
        while data:
            count=os.write(temp_fd,data)
            if count<=0:raise OSError("short receipt write")
            data=data[count:]
        os.fsync(temp_fd)
        os.close(temp_fd);temp_fd=None
        os.link(staging,name,src_dir_fd=attempt_fd,dst_dir_fd=attempt_fd,
                follow_symlinks=False)
        os.fsync(attempt_fd)
        os.unlink(staging,dir_fd=attempt_fd)
        os.fsync(attempt_fd)
        return "private/source_attempt_records/"+name
    finally:
        for fd in (temp_fd,attempt_fd,private_fd,run_fd):
            if fd is not None:os.close(fd)
