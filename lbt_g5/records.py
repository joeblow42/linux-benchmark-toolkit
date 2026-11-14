"""G5-02 append-only, restricted source-attempt receipts.

Receipts are operational records, NOT the G5-04 canonical schema or IC-04
14-field validated status envelope. That envelope is emitted at G5-04 after
normalization. Every evaluated source must receive a receipt, including refusal,
absence, partial capture and preservation failures.
"""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import math
import os
import re
import secrets
import stat
from .safety import valid_run_id, initial_source_policies, RUN_SECONDS, RUN_BYTES

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
    # Owner Alternative A, 2026-11-08: SRC-28 private execution facts only.
    execution_provenance: dict | None = None
    # Truthful measured existing G5-03 adapter entry/exit, D-04.
    source_timing: dict | None = None
    # Effective bound facts from the worker transport, never guessed.
    limit_witness: dict | None = None
    # Owner-approved RP-02.1: multiple independently verified D0 facts.
    # Omitted from legacy v0.1-v0.5 envelopes entirely.
    limit_witnesses: tuple[dict,...] = ()

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")

def build_attempt(run_id,source_id,attempt,decision,outcome,reason,
                  *,evidence=(),bytes_count=0,missing=None,errors=(),
                  invocation="NOT_INVOKED",target=None,source_paths=(),unavailable_fields=(),
                  exit_code=None,elapsed_seconds=None,timed_out=False,capture_limited=False,
                  authorization_provenance=None,execution_provenance=None,
                  source_timing=None,limit_witness=None,limit_witnesses=()):
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
    if execution_provenance is not None:
        witness=execution_provenance
        keys={"argv_executed","exit_code","started_utc",
              "completed_utc","elapsed_seconds"}
        if (source_id != "SRC-28" or decision != "ALLOW"
                or policy.operation_id != "OFFLINE_METADATA"
                or invocation != "OFFLINE_METADATA"
                or authorization_provenance is not None
                or type(witness) is not dict or set(witness) != keys):
            raise ValueError("SRC-28 execution witness invalid scope or shape")
        argv=witness["argv_executed"]
        suffix=("-W","-f=$"+"{Package}"+r"\t$"+"{Version}"+r"\n")
        if (type(argv) not in (tuple,list) or len(argv)!=3
                or type(argv[0]) is not str
                or argv[0] not in ("/usr/bin/dpkg-query","/bin/dpkg-query",
                                   "/usr/sbin/dpkg-query","/sbin/dpkg-query")
                or tuple(argv[1:]) != suffix):
            raise ValueError("SRC-28 actual argv outside approved fixed template")
        code=witness["exit_code"]
        if (code is not None and (type(code) is not int or abs(code)>65535)
                or code != exit_code):
            raise ValueError("SRC-28 witness return-code mismatch")
        duration=witness["elapsed_seconds"]
        if (type(duration) not in (int,float) or not math.isfinite(duration)
                or duration<0 or duration>RUN_SECONDS):
            raise ValueError("SRC-28 witness invalid monotonic duration")
        try:
            start=witness["started_utc"];end=witness["completed_utc"]
            if (type(start) is not str or type(end) is not str
                    or not start.endswith("Z") or not end.endswith("Z")):
                raise ValueError("SRC-28 timestamps must be UTC")
            a=datetime.fromisoformat(start[:-1]+"+00:00")
            b=datetime.fromisoformat(end[:-1]+"+00:00")
            if b<a:
                raise ValueError("SRC-28 end precedes start")
        except (TypeError,AttributeError,ValueError) as exc:
            raise ValueError("SRC-28 actual execution clock invalid") from exc
    if source_timing is not None:
        keys={"started_utc","completed_utc","elapsed_ms"}
        if (type(source_timing) is not dict or set(source_timing)!=keys
                or decision != "ALLOW" or outcome == "DENIED"):
            raise ValueError("invalid factual acquisition timing envelope")
        start=source_timing["started_utc"];end=source_timing["completed_utc"]
        elapsed=source_timing["elapsed_ms"]
        if (type(start) is not str or type(end) is not str
                or not start.endswith("Z") or not end.endswith("Z")
                or type(elapsed) is not int or not 0<=elapsed<=RUN_SECONDS*1000):
            raise ValueError("invalid source clock type or duration")
        try:
            a=datetime.fromisoformat(start[:-1]+"+00:00")
            b=datetime.fromisoformat(end[:-1]+"+00:00")
            if a.tzinfo is None or b.tzinfo is None or b<a:
                raise ValueError("source end precedes start")
        except ValueError as exc:
            raise ValueError("invalid source UTC clock") from exc
    if limit_witness is not None:
        bound=limit_witness
        keys={"unit","threshold","observed_extent","missing_extent",
              "affected_scope","reason"}
        if (type(bound) is not dict or set(bound)!=keys
                or decision!="ALLOW" or outcome not in ("PARTIAL","FAILED")
                or bound["unit"] not in ("seconds","bytes")
                or bound["reason"] not in ("CAPTURE_LIMIT","TIME_BUDGET_EXCEEDED")
                or (bound["unit"]=="seconds")!=(bound["reason"]=="TIME_BUDGET_EXCEEDED")):
            raise ValueError("unproven capture-limit dimension")
        scope=bound["affected_scope"]
        if (type(scope) is not str or not re.fullmatch(
                re.escape(source_id)+r":call[0-9]{4}:(transport|stdout|stderr)",scope)):
            raise ValueError("capture-limit scope outside approved source")
        th=bound["threshold"];observed=bound["observed_extent"]
        if (type(th) not in (int,float) or type(observed) not in (int,float)
                or not all(math.isfinite(float(v)) for v in (th,observed))
                or th<=0 or observed<0):
            raise ValueError("invalid measured capture limit")
        bound_missing=bound["missing_extent"]
        if bound["unit"]=="seconds":
            per=policy.per_target_seconds or policy.max_seconds
            if th>per or bound_missing is not None or timed_out is not True:
                raise ValueError("unproved actual time ceiling or missing bytes")
        else:
            if (th>policy.max_bytes or type(th) is not int
                    or type(observed) is not int
                    or observed>th or type(bound_missing) not in (int,type(None))
                    or (bound_missing is not None and bound_missing<0)):
                raise ValueError("invalid observed byte ceiling or omitted extent")
    if limit_witnesses:
        # A new operational receipt version is permitted; canonical/status
        # schema keys, source safety budgets and reason vocabulary are not.
        if (limit_witness is not None or type(limit_witnesses) not in (list,tuple)
                or not 1<=len(limit_witnesses)<=64
                or (policy.authorization_class not in ("D0","O1") and
                    source_id not in ("SRC-28","SRC-15"))
                or decision!="ALLOW" or outcome not in ("PARTIAL","FAILED")
                or not (capture_limited or timed_out)):
            raise ValueError("invalid v0.6 multiple-limit source scope")
        witnessed=set()
        for bound in limit_witnesses:
            required={"unit","threshold","observed_extent",
                      "missing_extent","affected_scope","reason"}
            if type(bound) is not dict or set(bound)!=required:
                raise ValueError("invalid v0.6 limit fields")
            unit=bound["unit"];scope=bound["affected_scope"]
            reason=bound["reason"]
            th=bound["threshold"];observed=bound["observed_extent"]
            omitted=bound["missing_extent"]
            eligible_scope=(type(scope) is str and (
                (bool(re.fullmatch(re.escape(source_id)+
                    r":call(?:00(?:0[1-9]|[1-9][0-9])|0(?:1[0-1][0-9]|12[0-8])):"
                    r"(transport|stdout|stderr)",scope))
                 or scope in (
                    source_id+":call0001:source:entries",
                    source_id+":call0001:source:time",
                    source_id+":call0001:source:writer"))
                if source_id=="SRC-15" else
                scope.startswith(source_id+":call0001:")))
            if policy.authorization_class=="O1":
                # Only exact same-attempt shared writer-run proof is
                # authorized in Increment 39. Transport and helper internal
                # effective limits have not yet been independently attested.
                eligible_scope=(source_id in ("SRC-13","SRC-18","SRC-21")
                    and type(scope) is str
                    and scope==source_id+":call%04d:run:writer"%int(attempt))
            if (unit not in ("seconds","bytes","entries")
                    or type(scope) is not str
                    or not eligible_scope
                    or (unit=="seconds") != (reason=="TIME_BUDGET_EXCEEDED")
                    or reason not in ("CAPTURE_LIMIT","TIME_BUDGET_EXCEEDED")
                    or type(th) not in (int,float) or type(observed) not in (int,float)
                    or not math.isfinite(float(th)) or not math.isfinite(float(observed))
                    or th<=0 or observed<0 or (unit!="seconds" and observed>th)
                    or (unit in ("seconds","entries") and omitted is not None)
                    or (omitted is not None and
                        (type(omitted) is not int or omitted<0))):
                raise ValueError("invalid v0.6 measured limit")
            if unit=="seconds":
                if source_id=="SRC-15" and scope==source_id+":call0001:source:time":
                    # Source wall deadline is separate from per-call transport.
                    if th!=policy.max_seconds or observed<th or not timed_out:
                        raise ValueError("invalid SRC-15 cumulative deadline")
                else:
                    applied_max=(policy.per_target_seconds
                                 if source_id in ("SRC-28","SRC-15")
                                 else policy.max_seconds)
                    if (not scope.endswith(":transport")
                            or th>applied_max or not timed_out):
                        raise ValueError("invalid v0.6 process deadline")
            else:
                if (not capture_limited or type(th) is not int
                        or type(observed) is not int):
                    raise ValueError("invalid v0.6 count/byte dimension")
                if policy.authorization_class=="O1":
                    if (unit!="bytes" or type(th) is not int
                            or th>RUN_BYTES or observed!=th
                            or type(omitted) is not int or omitted<=0):
                        raise ValueError("invalid O1 writer-run original limit")
                elif source_id=="SRC-15":
                    if unit=="entries":
                        if (scope!=source_id+":call0001:source:entries" or
                                th!=policy.max_entries or observed!=th):
                            raise ValueError("invalid SRC-15 source entry ceiling")
                    elif scope==source_id+":call0001:source:writer":
                        # Writer owns the existing 2 MiB aggregate ceiling.
                        if (unit!="bytes" or th!=policy.max_bytes or
                                observed!=th or omitted is None or omitted<=0):
                            raise ValueError("invalid SRC-15 writer source quota")
                    else:
                        applied=(1*1024*1024 if scope.endswith(":stdout")
                                 else 128*1024 if scope.endswith(":stderr")
                                 else None)
                        if (unit!="bytes" or applied is None or
                                omitted is None or omitted<=0 or
                                observed!=th or th!=applied):
                            raise ValueError("invalid SRC-15 D1 per-call cap")
                elif source_id=="SRC-28":
                    if scope==source_id+":call0001:run:writer":
                        # The run-wide meter can become exhausted by earlier
                        # sealed sources. It is NOT the 32 MiB SRC-28 cap.
                        if (unit!="bytes" or th>RUN_BYTES or
                                observed!=th or omitted is None or omitted<=0):
                            raise ValueError("invalid SRC-28 run-writer quota")
                    elif (unit!="bytes" or omitted is None or omitted<=0
                            or observed!=th
                            or (scope==source_id+":call0001:stderr" and
                                th!=1024*1024)
                            or (scope==source_id+":call0001:transport" and
                                th!=8*1024*1024)
                            or scope not in (source_id+":call0001:stderr",
                                              source_id+":call0001:transport")):
                        raise ValueError("invalid SRC-28 D1 measured transport cap")
                elif unit=="entries":
                    if (scope!=source_id+":call0001:source:entries"
                            or th!=policy.max_entries):
                        raise ValueError("invalid v0.6 source entry ceiling")
                elif scope==source_id+":call0001:source:bytes":
                    if th!=policy.max_bytes:
                        raise ValueError("invalid v0.6 source byte ceiling")
                elif re.fullmatch(re.escape(source_id)+r":call0001:item[0-9]{4}:file",scope):
                    # The unchanged private worker applies the 1 MiB file cap.
                    if th!=1024*1024:
                        raise ValueError("invalid v0.6 file ceiling")
                elif scope==source_id+":call0001:stdout":
                    actual=min(64*1024*1024,
                        int(policy.max_bytes*1.5)+policy.max_entries*512+4096)
                    if (th!=actual or observed!=th or
                            omitted is None or omitted<=0):
                        raise ValueError("invalid v0.6 stdout transport overrun")
                elif scope==source_id+":call0001:stderr":
                    if (th!=64*1024 or observed!=th or
                            omitted is None or omitted<=0):
                        raise ValueError("invalid v0.6 stderr transport overrun")
                elif scope==source_id+":call0001:run:writer":
                    if (th>RUN_BYTES or observed!=th or
                            omitted is None or omitted<=0):
                        raise ValueError("invalid v0.6 writer run ceiling")
                elif scope==source_id+":call0001:source:writer":
                    if (th!=policy.max_bytes or observed!=th or
                            omitted is None or omitted<=0):
                        raise ValueError("invalid v0.6 writer source ceiling")
                elif re.fullmatch(
                        re.escape(source_id)+r":call0001:item[0-9]{4}:writer",
                        scope):
                    if (th!=policy.max_bytes or omitted is None or omitted<=0):
                        raise ValueError("invalid v0.6 writer stream ceiling")
                else:
                    raise ValueError("unapproved v0.6 byte scope")
            if (unit,scope) in witnessed:
                raise ValueError("duplicate v0.6 source limit")
            witnessed.add((unit,scope))
    return AttemptReceipt("g5-02-attempt-0.6" if limit_witnesses else
                          "g5-02-attempt-0.5" if limit_witness else
                          "g5-02-attempt-0.4" if source_timing else
                          "g5-02-attempt-0.3" if execution_provenance else
                          "g5-02-attempt-0.2" if authorization_provenance else
                          "g5-02-attempt-0.1",run_id,
        f"{source_id}-{attempt}",policy.collector_id,source_id,
        policy.operation_id,policy.authorization_class,
        invocation,target,decision,outcome,reason,bytes_count,
        ids,missing,tuple(str(e)[:256] for e in errors),utc_now(),
        source_paths=tuple(source_paths),unavailable_fields=tuple(unavailable_fields),
        exit_code=exit_code,elapsed_seconds=elapsed_seconds,
        timed_out=bool(timed_out),capture_limited=bool(capture_limited),
        authorization_provenance=authorization_provenance,
        execution_provenance=execution_provenance,
        source_timing=source_timing,
        limit_witness=limit_witness,
        limit_witnesses=tuple(limit_witnesses))

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
    if fields["execution_provenance"] is None:
        del fields["execution_provenance"]  # Other source IDs retain exact old shape.
    if fields["source_timing"] is None:
        del fields["source_timing"]  # Old schema envelopes remain byte-compatible.
    if fields["limit_witness"] is None:
        del fields["limit_witness"]
    if not fields["limit_witnesses"]:
        del fields["limit_witnesses"]
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
