"""RP-02 Increment 39: O1 actual run-writer events, frozen-source synthetic oracles.

No physical devices, sudo, helper installation, or external commands run.
Fixtures are AI-authored candidate assurance, not independent CP-02 acceptance.
"""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import tempfile
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter, RunMeter
from lbt_g5.o1 import OptionalSourcePlan
from lbt_g5.receipt_dispatch import RecordedOutcome, capture_and_record
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceConsent, SourceRequest, initial_source_policies, RUN_BYTES

RUN = "run-2026318180000"
RAW = b"ORIGINAL_O1_OBSERVATION\n"
POL = {p.source_id: p for p in initial_source_policies()}
SOURCES = {
    "SRC-13": ("SRC-12", "/sys/class/block/sda/size", b"3907029168\n",
               "/dev/sda", ("smartctl", "-i", "-H", "/dev/sda")),
    "SRC-18": ("SRC-17", "/sys/class/block/sr0/removable", b"1\n",
               "/dev/sr0", ("sg_get_config", "--readonly", "--current", "/dev/sr0")),
    "SRC-21": ("SRC-19", "/sys/class/drm/card0/device/vendor", b"0x8086\n",
               "/dev/dri/renderD128",
               ("vainfo", "--display", "drm", "--device", "/dev/dri/renderD128")),
}


class O1RunWriterOracles(unittest.TestCase):
    def fixture(self, source="SRC-13", *, retained=5, stale=0, raw=RAW,
                captured=None, helper=False, exclude_inventory=False):
        upstream, inv_path, inv_raw, target, argv = SOURCES[source]
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        folder = Path(tmp.name) / RUN
        folder.mkdir(mode=0o700)
        meter = RunMeter(max_bytes=len(inv_raw)+retained+stale)
        writer = EvidenceWriter(str(folder), RUN, meter)
        original_inv = writer.seal_chunks(POL[upstream], "01", "item0001",
                                          (inv_raw,)).receipt
        self.assertIsNotNone(original_inv)
        inv_receipt = build_attempt(
            RUN, upstream, "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=(original_inv,), bytes_count=original_inv.byte_count,
            invocation=POL[upstream].operation_id, source_paths=(inv_path,))
        inv_record = RecordedOutcome(
            SimpleNamespace(artifacts=(original_inv,), disposition="CAPTURED",
                            source_paths=(inv_path,)),
            commit_attempt(str(folder), inv_receipt))
        if stale:
            self.assertEqual(writer.meter.reserve(stale), stale)
        op = POL[source].operation_id
        consent = SourceConsent(RUN, source, op, target,
                                datetime.now(timezone.utc), True)
        request = SourceRequest(RUN, source, op, target=target, consent=consent,
                                trusted_targets=frozenset((target,)))
        plan = OptionalSourcePlan(
            source, op, target, argv,
            POL[source].per_target_bytes or POL[source].max_bytes,
            POL[source].per_target_seconds or POL[source].max_seconds,
            "registered O1 impact")
        if captured is None:
            captured = TransportCapture(raw, b"", 0, 0.05, False, False, 0, 0)
        binding = dict(source_id=upstream, source_path=inv_path,
                       evidence_id=original_inv.evidence_id)
        session = Mock() if helper else None
        if helper:
            session.capture.return_value = captured
        with patch("lbt_g5.o1_execution.plan_optional", return_value=plan), \
             patch("lbt_g5.o1_execution._resolve_executable",
                   return_value="/usr/bin/" + argv[0]), \
             patch("lbt_g5.o1_execution._capture_child",
                   return_value=captured) as direct:
            recorded = capture_and_record(
                request, "01", writer, ProbeSlots(), SourceCallBudget(),
                privileged_session=session, o1_inventory_binding=binding)
        if helper:
            session.capture.assert_called_once()
            direct.assert_not_called()
        else:
            direct.assert_called_once()
        attempt = json.loads((folder / recorded.receipt_private_path).read_text())
        members = (() if exclude_inventory else (inv_record,)) + (recorded,)
        run = EngineRun(RUN, (CollectorRun(POL[source].collector_id, members),))
        return folder, attempt, run, recorded, original_inv

    def test_39_01_03_o1_all_three_writer_events_and_consent_proof(self):
        for source in SOURCES:
            with self.subTest(source=source):
                folder, receipt, run, recorded, _ = self.fixture(
                    source, helper=(source == "SRC-13"))
                self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
                self.assertEqual(receipt["outcome"], "PARTIAL")
                self.assertEqual(receipt["reason"], "CAPTURE_LIMIT")
                self.assertEqual(receipt["acquired_bytes"], 5)
                self.assertEqual(receipt["limit_witnesses"], [{
                    "unit": "bytes", "threshold": len(SOURCES[source][2])+5,
                    "observed_extent": len(SOURCES[source][2])+5,
                    "missing_extent": len(RAW)-5,
                    "affected_scope": source+":call0001:run:writer",
                    "reason": "CAPTURE_LIMIT"}])
                original = recorded.outcome["receipts"][0]
                self.assertEqual((folder/original.private_relative_path).read_bytes(),
                                 RAW[:5])
                self.assertEqual(original.sha256, hashlib.sha256(RAW[:5]).hexdigest())
                self.assertEqual(recorded.authorization_provenance["consent_source_id"],
                                 source)
                build_canonical(folder, run)
                limits = json.loads((folder/"private/system.json").read_text())["capture_limits"]
                self.assertEqual(len(limits), 1)
                self.assertEqual(limits[0]["affected_scope"],
                                 source+":call0001:run:writer")
                statuses = json.loads((folder/"private/status_records.json").read_text())
                own = next(x for x in statuses["status_records"]
                           if x["subject_id"] == source)
                self.assertEqual((own["status"], own["reason_code"]),
                                 ("PARTIAL", "CAPTURE_LIMIT"))

    def test_39_04_exact_boundary_is_not_an_event(self):
        _, receipt, _, recorded, _ = self.fixture("SRC-18", raw=b"X"*5)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.4")
        self.assertNotIn("limit_witnesses", receipt)
        self.assertFalse(receipt["capture_limited"])
        self.assertTrue(all(not a.limit_applied
                            for a in recorded.outcome["receipts"]))

    def test_39_05_missing_same_run_inventory_or_memory_consent_rejected(self):
        for source in SOURCES:
            with self.subTest(source=source):
                folder, receipt, run, recorded, _ = self.fixture(
                    source, exclude_inventory=True)
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder, run)
        folder, receipt, run, recorded, _ = self.fixture("SRC-13")
        altered = replace(recorded, authorization_provenance=None)
        without_memory = EngineRun(RUN, (
            CollectorRun(POL["SRC-13"].collector_id,
                         (run.collectors[0].source_attempts[0], altered)),))
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder, without_memory)

    def test_39_06_fabricated_scope_and_threshold_refused(self):
        for source in SOURCES:
            for bad in (
                ("source:writer", 5, 5, 1),
                ("transport", 5, 5, 1),
                ("run:writer", RUN_BYTES+1, RUN_BYTES+1, 1),
                ("run:writer", 5, 5, 0),
                ("run:writer", 5, 5, None),
            ):
                scope, threshold, observed, omitted = bad
                fact = dict(unit="bytes", threshold=threshold,
                            observed_extent=observed, missing_extent=omitted,
                            affected_scope=source+":call0001:"+scope,
                            reason="CAPTURE_LIMIT")
                with self.subTest(source=source, bad=bad), self.assertRaises(ValueError):
                    build_attempt(RUN, source, "01", "ALLOW", "PARTIAL",
                                  "CAPTURE_LIMIT", capture_limited=True,
                                  limit_witnesses=(fact,))

    def test_39_07_simultaneous_transport_or_timeout_cannot_select_writer(self):
        conflicts = (
            TransportCapture(RAW, b"", 0, .05, False, True, 1, 0),
            TransportCapture(RAW, b"", None, 12.0, True, False, 0, 0),
        )
        for captured in conflicts:
            with self.subTest(captured=captured):
                folder, receipt, run, _, _ = self.fixture(
                    "SRC-13", captured=captured)
                self.assertNotIn("limit_witnesses", receipt)
                with self.assertRaisesRegex(
                        CanonicalContractError, "dimension not evidenced"):
                    build_canonical(folder, run)

    def test_39_08_unsealed_reservation_not_canonical_writer_proof(self):
        folder, receipt, run, _, _ = self.fixture("SRC-13", retained=7, stale=3)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        with self.assertRaisesRegex(
                CanonicalContractError, "run writer aggregate not evidenced"):
            build_canonical(folder, run)

    def test_39_09_helper_unknown_effective_transport_limit_not_invented(self):
        captured = TransportCapture(b"abc", b"", 0, .03, False, True, 9, 0)
        folder, receipt, run, recorded, _ = self.fixture(
            "SRC-13", raw=b"abc", retained=10, captured=captured, helper=True)
        self.assertNotIn("limit_witnesses", receipt)
        self.assertTrue(receipt["capture_limited"])
        with self.assertRaisesRegex(
                CanonicalContractError, "dimension not evidenced"):
            build_canonical(folder, run)


if __name__ == "__main__":
    unittest.main()
