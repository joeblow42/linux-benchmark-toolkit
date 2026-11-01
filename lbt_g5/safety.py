"""G5-02: executable preflight policy; imports and decisions perform no source IO.

G4-07 Rev0.1 is authoritative. An ALLOW decision is not an invocation:
G5-03 must provide trusted source adapters, exact argv templates, bounded workers,
source-specific filesystem allowlists, and status-record integration.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
import time
from .catalog import initial_catalog

MIB = 1024 * 1024
RUN_SECONDS = 180
RUN_BYTES = 512 * MIB
MAX_ORDINARY_PROBES = 2
MAX_O1_PROBES = 1

# Exact G4-07 initial source ceiling: source ID, bytes, entries/calls, seconds.
# For SRC-13/18/15/23/28 additional per-target/per-call ceilings apply.
_BOUNDS = (
    (1,1*MIB,8,2),(2,1*MIB,1,2),(3,512*1024,128,2),
    (4,4*MIB,64,3),(5,16*MIB,1,6),(6,32*MIB,1,4),
    (7,32*MIB,4096,5),(8,2*MIB,1,2),(9,2*MIB,1,2),
    (10,2*MIB,1,2),(11,16*MIB,1,6),(12,32*MIB,4096,5),
    (13,32*MIB,32,60),(14,16*MIB,1,3),(15,2*MIB,128,15),
    (16,1*MIB,1,2),(17,8*MIB,128,3),(18,8*MIB,4,20),
    (19,16*MIB,2048,4),(20,16*MIB,1,6),(21,8*MIB,1,10),
    (22,16*MIB,2048,4),(23,16*MIB,2,10),(24,8*MIB,2048,4),
    (25,16*MIB,4096,5),(26,16*MIB,2048,4),
    (27,2*MIB,128,3),(28,32*MIB,4,20),
)
# Additional ceilings from the accepted source authorization register.
_PER_TARGET = {
    "SRC-13": (8*MIB, 12), "SRC-18": (4*MIB, 8),
    "SRC-15": (2*MIB, 2), "SRC-23": (8*MIB, 5),
    "SRC-28": (8*MIB, 8),
}
# Only these exact paths are known and directly eligible for FILE collection.
# They must still pass safe no-follow open/read checks in the G5-03 adapter.
_FIXED_FILES = {
    "SRC-02": "/etc/os-release", "SRC-06": "/proc/cpuinfo",
    "SRC-08": "/proc/meminfo", "SRC-09": "/proc/swaps",
    "SRC-10": "/proc/pressure/memory",
    "SRC-14": "/proc/self/mountinfo",
    "SRC-16": "/proc/sys/dev/cdrom/info",
}

@dataclass(frozen=True)
class SourcePolicy:
    source_id: str
    collector_id: str
    operation_id: str
    authorization_class: str
    max_bytes: int
    max_entries: int
    max_seconds: int
    per_target_bytes: int | None = None
    per_target_seconds: int | None = None
    fixed_file: str | None = None

@dataclass(frozen=True)
class SourceConsent:
    run_id: str
    source_id: str
    operation_id: str
    target: str
    issued_utc: datetime
    impact_acknowledged: bool

@dataclass(frozen=True)
class SourceRequest:
    run_id: str
    source_id: str
    operation_id: str
    target: str | None = None
    consent: SourceConsent | None = None
    # Checked inventory of approved targets from a trusted upstream source.
    trusted_targets: frozenset[str] = frozenset()
    operator_disabled: bool = False
    # Caller-specified shell strings, flags and paths are never accepted.
    override_argv: tuple[str, ...] | None = None
    override_path: str | None = None

@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    disposition: str
    reason: str
    source: SourcePolicy | None

def valid_run_id(run_id: str) -> bool:
    if type(run_id) is not str or re.fullmatch(r"run-\d{13}", run_id) is None:
        return False
    try:
        d = datetime.strptime(run_id[4:], "%Y%j%H%M%S")
        return d.strftime("%Y%j%H%M%S") == run_id[4:]
    except ValueError:
        return False

def initial_source_policies() -> tuple[SourcePolicy, ...]:
    _, catalog = initial_catalog()
    by_id = {src.source_id: src for src in catalog}
    if {f"SRC-{num:02d}" for num, *_ in _BOUNDS} != set(by_id):
        raise ValueError("G4-07 ceiling registry/catalog mismatch")
    records = []
    for num, byte_limit, entries, seconds in _BOUNDS:
        sid = f"SRC-{num:02d}"
        source = by_id[sid]
        per_bytes, per_seconds = _PER_TARGET.get(sid, (None, None))
        records.append(SourcePolicy(sid,source.collector_id,source.operation_id,
                source.authorization_class,byte_limit,entries,seconds,
                per_bytes,per_seconds,_FIXED_FILES.get(sid)))
    return tuple(records)

def decide_source(request: SourceRequest, *, now_utc: datetime | None = None,
                  remaining_seconds: float = RUN_SECONDS,
                  remaining_bytes: int = RUN_BYTES) -> AuthorizationDecision:
    """Fail-closed metadata preflight, before any collector or source access.

    This API deliberately does not execute probes or assert that a target is
    locally accessible. G5-03 must verify paths, tools, commands and devices.
    """
    if not valid_run_id(request.run_id):
        return AuthorizationDecision(False,"DENY","INVALID_RUN_ID",None)
    policy = next((s for s in initial_source_policies() if s.source_id == request.source_id),None)
    if policy is None or request.operation_id != policy.operation_id:
        return AuthorizationDecision(False,"DENY","UNREGISTERED_SOURCE_OR_OPERATION",policy)
    if os.geteuid() == 0:
        return AuthorizationDecision(False,"DENY","PRIVILEGED_PROCESS",policy)
    if request.operator_disabled:
        return AuthorizationDecision(False,"DENY","OPERATOR_DISABLED",policy)
    if request.override_argv is not None or request.override_path is not None:
        return AuthorizationDecision(False,"DENY","UNTRUSTED_OVERRIDE",policy)
    if remaining_seconds <= 0 or remaining_bytes <= 0:
        return AuthorizationDecision(False,"DENY","RUN_BUDGET_EXHAUSTED",policy)
    if policy.authorization_class == "O1":
        consent = request.consent
        now = now_utc if now_utc is not None else datetime.now(timezone.utc)
        if (consent is None or consent.impact_acknowledged is not True
            or consent.run_id != request.run_id
            or consent.source_id != policy.source_id
            or consent.operation_id != policy.operation_id
            or not request.target or consent.target != request.target
            or request.target not in request.trusted_targets
            or consent.issued_utc.tzinfo is None
            or consent.issued_utc > now):
            return AuthorizationDecision(False,"DENY","OPERATOR_AUTH_REQUIRED",policy)
    elif request.consent is not None:
        return AuthorizationDecision(False,"DENY","UNNEEDED_CONSENT",policy)
    elif request.target is not None and policy.fixed_file != request.target:
        return AuthorizationDecision(False,"DENY","UNTRUSTED_TARGET",policy)
    return AuthorizationDecision(True,"ALLOW","APPROVED_PREFLIGHT_ONLY",policy)
