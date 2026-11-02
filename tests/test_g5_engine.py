"""G5-03 contract tests: run owners, denial, provenance, single engine."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import unittest

from lbt_g5.catalog import initial_catalog
from lbt_g5.engine import UnifiedCollectorEngine
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.safety import SourceRequest, SourceConsent, initial_source_policies

RUN = "run-2026305120000"


def result(disposition="CAPTURED", paths=(), artifacts=()):
    return SimpleNamespace(
        outcome=SimpleNamespace(
            disposition=disposition,
            source_paths=tuple(paths),
            artifacts=tuple(artifacts)))


class UnifiedEngineContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / RUN
        self.folder.mkdir()
        self.engine = UnifiedCollectorEngine(str(self.folder), RUN)

    def test_all_thirteen_owners_and_twenty_eight_sources(self):
        collectors, sources = initial_catalog()
        calls = []
        def invoke(request, attempt, *args, **kwargs):
            calls.append((request.source_id, request.operation_id, attempt,
                          kwargs.get("subcall"), kwargs.get("source14_evidence")))
            return result()
        with patch("lbt_g5.engine.capture_and_record", side_effect=invoke):
            run = self.engine.run()
        self.assertEqual(len(run.collectors), 13)
        self.assertEqual({c.collector_id for c in run.collectors},
                         {c.collector_id for c in collectors})
        self.assertEqual(run.source_attempt_count, 29)  # SRC-23 has two calls.
        self.assertEqual({r[0] for r in calls}, {s.source_id for s in sources})
        self.assertEqual([r[3] for r in calls if r[0] == "SRC-23"], [0, 1])
        self.assertTrue(run.canonical_status_pending)

    def test_one_engine_one_run_no_repeat_acquisition(self):
        with patch("lbt_g5.engine.capture_and_record", return_value=result()) as capture:
            self.engine.run(("COL-OS",))
            with self.assertRaises(RuntimeError):
                self.engine.run(("COL-OS",))
        self.assertEqual(capture.call_count, 4)

    def test_reject_unknown_collector_before_execution(self):
        with patch("lbt_g5.engine.capture_and_record") as capture:
            with self.assertRaises(ValueError):
                self.engine.run(("COL-CPU", "COL-CPU"))
            with self.assertRaises(ValueError):
                self.engine.run(("COL-UNKNOWN",))
            capture.assert_not_called()

    def test_subset_is_exactly_owned(self):
        seen = []
        with patch("lbt_g5.engine.capture_and_record",
                   side_effect=lambda request, *a, **k:
                   (seen.append(request.source_id) or result())):
            run = self.engine.run(("COL-MEM",))
        self.assertEqual(seen, ["SRC-08", "SRC-09", "SRC-10"])
        self.assertEqual(run.source_attempt_count, 3)

    def test_invalid_o1_requests_rejected_before_source_access(self):
        bad = SourceRequest(RUN, "SRC-02", "OS_RELEASE", target="/dev/sda")
        with patch("lbt_g5.engine.capture_and_record") as capture:
            with self.assertRaises(ValueError):
                self.engine.run(("COL-OS",), o1_requests={"SRC-02":bad})
            capture.assert_not_called()

    def test_o1_caller_trust_never_accepted_without_run_inventory(self):
        policy = next(p for p in initial_source_policies() if p.source_id=="SRC-21")
        consent = SourceConsent(
            RUN, "SRC-21", policy.operation_id, "/dev/dri/renderD128",
            datetime.now(timezone.utc), True)
        request = SourceRequest(
            RUN, "SRC-21", policy.operation_id, target="/dev/dri/renderD128",
            consent=consent, trusted_targets=frozenset({"/dev/dri/renderD128"}))
        seen = []
        with patch("lbt_g5.engine.capture_and_record",
                   side_effect=lambda req, *a, **k:
                   (seen.append(req) or result("DENIED"))):
            self.engine.run(("COL-VAAPI",), o1_requests={"SRC-21":request})
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].trusted_targets, frozenset())
        self.assertIsNotNone(seen[0].consent)

    def test_missing_o1_consent_remains_denied(self):
        requests = []
        with patch("lbt_g5.engine.capture_and_record",
                   side_effect=lambda req, *a, **k:
                   (requests.append(req) or result("DENIED"))):
            self.engine.run(("COL-VAAPI",))
        self.assertEqual(len(requests), 1)
        self.assertIsNone(requests[0].consent)
        self.assertEqual(requests[0].trusted_targets, frozenset())

    def test_mount_stat_only_consumes_sealed_source14_original(self):
        policy = next(p for p in initial_source_policies() if p.source_id=="SRC-14")
        raw = b"42 1 0:50 / / rw - overlay /cow rw\n"
        receipt = self.engine.writer.seal_chunks(policy, "01", "item0001", (raw,)).receipt
        seen = {}
        def fake(request, *args, **kwargs):
            if request.source_id == "SRC-14":
                return result(paths=("/proc/self/mountinfo",), artifacts=(receipt,))
            if request.source_id == "SRC-15":
                seen["raw"] = kwargs["source14_evidence"]
            return result()
        with patch("lbt_g5.engine.capture_and_record", side_effect=fake):
            self.engine.run(("COL-FS",))
        self.assertEqual(seen["raw"], raw)

    def test_mount_stat_refuses_unsealed_or_tampered_source14(self):
        policy = next(p for p in initial_source_policies() if p.source_id=="SRC-14")
        raw = b"42 1 0:50 / / rw - overlay /cow rw\n"
        receipt = self.engine.writer.seal_chunks(policy, "01", "item0001", (raw,)).receipt
        (self.folder / receipt.private_relative_path).write_bytes(b"tampered")
        seen = {}
        def fake(request, *args, **kwargs):
            if request.source_id=="SRC-14":
                return result(paths=("/proc/self/mountinfo",), artifacts=(receipt,))
            if request.source_id=="SRC-15":
                seen["raw"] = kwargs["source14_evidence"]
            return result()
        with patch("lbt_g5.engine.capture_and_record", side_effect=fake):
            self.engine.run(("COL-FS",))
        self.assertIsNone(seen["raw"])

    def test_disabled_source_reaches_same_authorization_boundary(self):
        received=[]
        with patch("lbt_g5.engine.capture_and_record",
                   side_effect=lambda request, *a, **k:
                   (received.append(request) or result("DENIED"))):
            self.engine.run(("COL-CPU",), disabled_sources=("SRC-05",))
        self.assertTrue(received[0].operator_disabled)
        self.assertFalse(received[1].operator_disabled)

    def test_no_branch_for_legacy_acquisition(self):
        from lbt_g5 import engine
        self.assertIs(engine.capture_and_record.__module__ == "lbt_g5.receipt_dispatch", True)


if __name__=="__main__":
    unittest.main()
