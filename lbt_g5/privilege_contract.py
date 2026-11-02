"""G5-03 declarative privileged-helper protocol, version 1.

This is a pure no-I/O validation boundary for an independently installed,
root-owned session-scoped helper. It does NOT invoke sudo, open a device,
elevate privilege or run a command. No caller-supplied argv is ever accepted.

A valid wire envelope is NOT sufficient to authorize source acquisition.
The unprivileged IC-02 engine must first validate per-run/source/target O1
consent, verify target via sealed D0 inventory, and respect G4-07 budgets.
The eventual helper must independently check the installed device identity.
"""
from dataclasses import dataclass
import json
import re

from .safety import valid_run_id

PROTOCOL_VERSION = "lbt-root-helper-1"
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 12 * 1024 * 1024  # framing ceiling; output still <= 8 MiB
MAX_HEALTH_BYTES = 8 * 1024 * 1024
MAX_HEALTH_SECONDS = 12.0
MAX_HEALTH_ATTEMPTS_PER_RUN = 32
_SESSION_TAG = re.compile(r"[0-9a-f]{32}")
_RUN_ID = re.compile(r"run-[0-9]{13}")
_DEVICE = re.compile(r"/dev/(?:sd[a-z]+|nvme[0-9]+(?:n[0-9]+)?)")


class PrivilegeContractError(ValueError):
    """Rejected session, device, protocol shape or replay."""


@dataclass(frozen=True)
class HealthRequest:
    run_id: str
    sequence: int
    target: str
    max_bytes: int
    max_seconds: float


def _decode_wire(raw: bytes) -> dict:
    if type(raw) is not bytes or not (0 < len(raw) <= MAX_REQUEST_BYTES):
        raise PrivilegeContractError("invalid request frame")
    if b"\x00" in raw or b"\n" in raw or b"\r" in raw:
        raise PrivilegeContractError("only one JSON frame is allowed")
    def reject_duplicate_fields(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise PrivilegeContractError("duplicate JSON field")
            obj[key] = value
        return obj
    try:
        doc = json.loads(raw.decode("utf-8"),
                         object_pairs_hook=reject_duplicate_fields)
    except (ValueError, UnicodeError) as exc:
        raise PrivilegeContractError("malformed JSON") from exc
    if type(doc) is not dict:
        raise PrivilegeContractError("object frame required")
    return doc


def _typed_fields(doc: dict, *, expected: frozenset[str]):
    if set(doc) != expected:
        raise PrivilegeContractError("unexpected or missing request field")


class HealthSessionContract:
    """Exact operation allowlist and monotonic sequence per helper session.

    This state belongs inside the privileged helper. A user-supplied request
    cannot change the expected session tag, reset sequence or counters.
    """

    def __init__(self, session_tag: str):
        if type(session_tag) is not str or not _SESSION_TAG.fullmatch(session_tag):
            raise PrivilegeContractError("invalid session identifier")
        self.session_tag = session_tag
        self._sequence = 0
        self._counts = {}

    def prepare(self, raw: bytes) -> HealthRequest:
        """Validate without mutating state; call commit only after accepted."""
        doc = _decode_wire(raw)
        _typed_fields(doc, expected=frozenset((
            "protocol", "session", "sequence", "run_id", "source_id",
            "operation_id", "target", "max_bytes", "max_seconds",
        )))
        if (doc["protocol"] != PROTOCOL_VERSION
                or type(doc["session"]) is not str
                or doc["session"] != self.session_tag
                or doc["source_id"] != "SRC-13"
                or doc["operation_id"] != "DEVICE_HEALTH"):
            raise PrivilegeContractError("unregistered privileged operation")
        run_id = doc["run_id"]
        target = doc["target"]
        seq = doc["sequence"]
        byte_limit = doc["max_bytes"]
        seconds = doc["max_seconds"]
        if (type(run_id) is not str or not _RUN_ID.fullmatch(run_id)
                or not valid_run_id(run_id)
                or type(target) is not str or not _DEVICE.fullmatch(target)
                or type(seq) is not int or seq != self._sequence+1):
            raise PrivilegeContractError("invalid run, target or sequence")
        if (type(byte_limit) is not int or not 0 < byte_limit <= MAX_HEALTH_BYTES
                or type(seconds) not in (int, float)
                or not 0 < seconds <= MAX_HEALTH_SECONDS):
            raise PrivilegeContractError("invalid or excessive operation budget")
        if self._counts.get(run_id, 0) >= MAX_HEALTH_ATTEMPTS_PER_RUN:
            raise PrivilegeContractError("run health query ceiling reached")
        return HealthRequest(run_id, seq, target, byte_limit, float(seconds))

    def commit(self, request: HealthRequest):
        """Reserve the accepted request before any privileged operation."""
        if (type(request) is not HealthRequest
                or request.sequence != self._sequence + 1
                or self._counts.get(request.run_id, 0) >= MAX_HEALTH_ATTEMPTS_PER_RUN):
            raise PrivilegeContractError("stale or unreserved request")
        self._sequence = request.sequence
        self._counts[request.run_id] = self._counts.get(request.run_id, 0)+1

    def accept(self, raw: bytes) -> HealthRequest:
        request = self.prepare(raw)
        self.commit(request)
        return request
