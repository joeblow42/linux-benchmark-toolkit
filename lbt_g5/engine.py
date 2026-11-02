"""G5-03 IC-02 single run-scoped collector orchestration (non-production entry).

The 13 current logical owners execute only their registered G5-01 source
families via the single G5-02 capture_and_record boundary. This does not
publish canonical sessions or replace the legacy launcher before parity tests.
Importing this module has no effects. The engine never installs tools,
requests sudo, or creates an alternate device/acquisition pathway.
"""
from dataclasses import dataclass, replace
import hashlib
import os
import re
import stat
import threading
from pathlib import Path
from typing import Mapping

from .catalog import initial_catalog
from .evidence import EvidenceWriter
from .receipt_dispatch import capture_and_record
from .runtime import ProbeSlots, SourceCallBudget
from .safety import SourceRequest, initial_source_policies

# Registered, bounded D1 IP introspection has exactly two independent calls.
_SUBCALLS = {"SRC-23": (0, 1)}
_BLOCK = re.compile(r"/sys/class/block/(sd[a-z]+|nvme[0-9]+n[0-9]+)/")
_OPTICAL = re.compile(r"/sys/class/block/(sr[0-9]+)/")
_DRM_CARD = re.compile(r"/sys/class/drm/(card[0-9]+)/")
_RENDER = re.compile(r"/dev/dri/renderD[0-9]+")


@dataclass(frozen=True)
class CollectorRun:
    collector_id: str
    source_attempts: tuple


@dataclass(frozen=True)
class EngineRun:
    run_id: str
    collectors: tuple
    # Operational receipts are private G5-02 attempts, NOT the G5-04 schema.
    canonical_status_pending: bool = True

    @property
    def source_attempt_count(self):
        return sum(len(c.source_attempts) for c in self.collectors)


class UnifiedCollectorEngine:
    """One run, one source dispatcher, one shared budget/concurrency boundary.

    Run directory must already exist; lifecycle/manifest naming is G5-04.
    O1 accepts per-source bounded target requests, each requiring exact-run
    consent AND a device discovered
    through this run's sealed D0 inventory. A caller cannot assert trust merely
    by populating SourceRequest.trusted_targets.
    """

    def __init__(self, run_directory: str, run_id: str, *,
                 writer=None, slots=None, calls=None):
        self.writer = writer if writer is not None else EvidenceWriter(run_directory, run_id)
        if self.writer.run_id != run_id:
            raise ValueError("writer/run identity mismatch")
        self.slots = slots if slots is not None else ProbeSlots()
        self.calls = calls if calls is not None else SourceCallBudget()
        self.run_id = run_id
        self._once_lock = threading.Lock()
        self._used = False

    @staticmethod
    def _sources_by_collector():
        collectors, sources = initial_catalog()
        by_owner = {c.collector_id: [] for c in collectors}
        for source in sources:
            by_owner[source.collector_id].append(source)
        return by_owner

    @staticmethod
    def _recorded_paths(results, source_id):
        """Only paths paired with sealed evidence from this run count."""
        matched = set()
        for result in results.get(source_id, ()):
            outcome = result.outcome
            if outcome.disposition not in ("CAPTURED", "PARTIAL"):
                continue
            for path, receipt in zip(outcome.source_paths, outcome.artifacts):
                if receipt.source_id == source_id:
                    matched.add(path)
        return matched

    def _trusted_targets(self, source_id, target, results):
        """Bind O1 targets to current-run D0 evidence, then validate sysfs."""
        if not isinstance(target, str):
            return frozenset()
        if source_id == "SRC-13":
            matched = _BLOCK
            paths = self._recorded_paths(results, "SRC-12")
        elif source_id == "SRC-18":
            matched = _OPTICAL
            paths = self._recorded_paths(results, "SRC-17")
        elif source_id == "SRC-21":
            if not _RENDER.fullmatch(target):
                return frozenset()
            paths = self._recorded_paths(results, "SRC-19")
            observed = set()
            for path in paths:
                card = _DRM_CARD.match(path)
                if card:
                    observed.add(card.group(1))
            if not observed:
                return frozenset()
            name = target.rsplit("/", 1)[-1]
            pci = Path("/sys/class/drm") / name / "device"
            try:
                if os.path.islink(target) or not stat.S_ISCHR(os.lstat(target).st_mode):
                    return frozenset()
                resolved = os.path.realpath(pci)
                for card in observed:
                    if (resolved == os.path.realpath(
                            Path("/sys/class/drm") / card / "device")
                            and os.path.exists(pci)):
                        return frozenset((target,))
            except OSError:
                pass
            return frozenset()
        else:
            return frozenset()
        names = {match.group(1) for path in paths
                 if (match := matched.match(path))}
        allowed = {"/dev/" + name for name in names}
        if source_id == "SRC-13":
            for name in names:
                controller = re.fullmatch(r"(nvme[0-9]+)n[0-9]+", name)
                if controller:
                    allowed.add("/dev/" + controller.group(1))
        if target not in allowed:
            return frozenset()
        try:
            mode = os.lstat(target).st_mode
        except OSError:
            return frozenset()
        if os.path.islink(target) or not (
                stat.S_ISBLK(mode) or
                (source_id == "SRC-13" and stat.S_ISCHR(mode))):
            return frozenset()
        if (source_id == "SRC-13" and stat.S_ISCHR(mode)
                and not os.path.exists("/sys/class/nvme/" + os.path.basename(target))):
            return frozenset()
        return frozenset((target,))

    def _mountinfo_original(self, results):
        """Consume SOURCE-14 immutable bytes, never re-read live mountinfo."""
        for result in results.get("SRC-14", ()):
            outcome = result.outcome
            if outcome.disposition != "CAPTURED":
                continue
            for path, item in zip(outcome.source_paths, outcome.artifacts):
                if path != "/proc/self/mountinfo":
                    continue
                relative = item.private_relative_path
                if not relative.startswith("private/evidence/") or "/" in relative[17:]:
                    continue
                try:
                    file_name = os.path.join(self.writer.run_directory, relative)
                    fd = os.open(file_name, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        original = b""
                        while len(original) <= item.byte_count:
                            chunk = os.read(fd, min(65536, item.byte_count + 1 - len(original)))
                            if not chunk:
                                break
                            original += chunk
                    finally:
                        os.close(fd)
                    if (len(original) == item.byte_count
                            and hashlib.sha256(original).hexdigest() == item.sha256):
                        return original
                except OSError:
                    continue
        return None

    def run(self, collector_ids=None, *, o1_requests: Mapping | None = None,
            disabled_sources=()):
        by_owner = self._sources_by_collector()
        requested = tuple(by_owner if collector_ids is None else collector_ids)
        if len(requested) != len(set(requested)) or set(requested) - set(by_owner):
            raise ValueError("unknown or duplicate collector")
        # Catalog ordering is stable, including D0 dependencies before O1.
        selected = tuple(cid for cid in by_owner if cid in requested)
        inputs = {} if o1_requests is None else dict(o1_requests)
        disabled = frozenset(disabled_sources)
        policies = {p.source_id: p for p in initial_source_policies()}
        active = {source.source_id for cid in selected for source in by_owner[cid]}
        if set(inputs) - active or disabled - active:
            raise ValueError("unselected or unknown source")
        o1 = {}
        for sid, submitted in inputs.items():
            policy = policies[sid]
            if policy.authorization_class != "O1":
                raise ValueError("non-O1 source request")
            requests = ((submitted,) if isinstance(submitted, SourceRequest)
                        else tuple(submitted) if isinstance(submitted, (list, tuple))
                        else ())
            if not requests or len(requests) > policy.max_entries:
                raise ValueError("invalid O1 request count")
            targets = set()
            for req in requests:
                if (not isinstance(req, SourceRequest)
                        or req.run_id != self.run_id
                        or req.source_id != sid
                        or req.operation_id != policy.operation_id
                        or req.override_argv is not None or req.override_path is not None
                        or not isinstance(req.target, str) or req.target in targets):
                    raise ValueError("invalid, duplicate or non-O1 source request")
                targets.add(req.target)
            o1[sid] = requests
        with self._once_lock:
            if self._used:
                raise RuntimeError("IC-02 engine is single-use per run")
            self._used = True

        receipts_by_source = {}
        collected = []
        for cid in selected:
            attempts = []
            for source in by_owner[cid]:
                sid = source.source_id
                policy = policies[sid]
                if policy.authorization_class == "O1":
                    requests = o1.get(sid, (SourceRequest(
                        self.run_id, sid, policy.operation_id),))
                else:
                    requests = (SourceRequest(self.run_id, sid, policy.operation_id,
                                             operator_disabled=sid in disabled),)
                for index, request in enumerate(requests):
                    if policy.authorization_class == "O1":
                        request = replace(request,
                            trusted_targets=self._trusted_targets(
                                sid, request.target, receipts_by_source),
                            operator_disabled=(sid in disabled or request.operator_disabled))
                    subcalls = (_SUBCALLS.get(sid, (0,))
                                if policy.authorization_class != "O1" else (index,))
                    for subcall in subcalls:
                        attempt = "%02d" % (subcall + 1)
                        source14 = (self._mountinfo_original(receipts_by_source)
                                    if sid == "SRC-15" else None)
                        recorded = capture_and_record(
                            request, attempt, self.writer, self.slots, self.calls,
                            subcall=subcall, source14_evidence=source14)
                        attempts.append(recorded)
                        receipts_by_source.setdefault(sid, []).append(recorded)
            collected.append(CollectorRun(cid, tuple(attempts)))
        return EngineRun(self.run_id, tuple(collected))
