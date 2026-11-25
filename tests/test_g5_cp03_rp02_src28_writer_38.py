"""SRC-28 D1 writer-run quota vs unreachable source quota; source-first mock oracles."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lbt_g5.canonical_session import build_canonical, CanonicalContractError
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter, RunMeter
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest, initial_source_policies, RUN_BYTES

RUN = "run-2026318183000"
SRC = "SRC-28"
RAW = b"dpkg\t1.21.22\n"
MIB = 1024 * 1024
SRC14_RAW = b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
POL = {p.source_id: p for p in initial_source_policies()}


class SRC28WriterOracles(unittest.TestCase):
    def one(self, *, max_bytes=None, prior14=False, stale_reserved=0,
            stdout=RAW, stderr=b"", exceeded=False, omitted_stdout=0,
            omitted_stderr=0):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name) / RUN
        folder.mkdir(mode=0o700)
        meter = RunMeter(max_bytes=max_bytes) if max_bytes is not None else None
        writer = EvidenceWriter(str(folder), RUN, meter)
        before = []
        if prior14:
            sealed = writer.seal_chunks(POL["SRC-14"], "01", "item0001",
                                        (SRC14_RAW,))
            self.assertIsNone(sealed.failure)
            self.assertFalse(sealed.receipt.limit_applied)
            rec = build_attempt(RUN, "SRC-14", "01", "ALLOW", "CAPTURED",
                "BYTES_PRESERVED", evidence=(sealed.receipt,),
                bytes_count=sealed.receipt.byte_count, invocation="MOUNTINFO",
                source_paths=("/proc/self/mountinfo",))
            before.append(SimpleNamespace(
                receipt_private_path=commit_attempt(str(folder), rec),
                outcome=SimpleNamespace(artifacts=(sealed.receipt,))))
        if stale_reserved:
            self.assertEqual(writer.meter.reserve(stale_reserved), stale_reserved)
        transport = TransportCapture(stdout, stderr, 0, .05, False, exceeded,
                                     omitted_stdout, omitted_stderr)
        with patch("lbt_g5.additional.decide_source",
                   return_value=SimpleNamespace(allowed=True, reason="APPROVED")):
            with patch("lbt_g5.additional._resolve_executable",
                       return_value="/usr/bin/dpkg-query"):
                with patch("lbt_g5.additional._capture_child",
                           return_value=transport) as invoked:
                    recorded = capture_and_record(
                        SourceRequest(RUN, SRC, "OFFLINE_METADATA"), "01",
                        writer, ProbeSlots(), SourceCallBudget())
        receipt = json.loads((folder / recorded.receipt_private_path).read_text())
        attempts = tuple(before) + (recorded,)
        run = EngineRun(RUN, (CollectorRun("COL-FS", tuple(before)),
                              CollectorRun(POL[SRC].collector_id,
                                           (recorded,)))) if before else EngineRun(
            RUN, (CollectorRun(POL[SRC].collector_id, (recorded,)),))
        return folder, receipt, run, invoked, recorded

    def test_38_01_real_writer_run_quota_with_original_hash(self):
        folder, receipt, run, called, recorded = self.one(max_bytes=3)
        self.assertEqual(called.call_count, 1)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        self.assertEqual(receipt["acquired_bytes"], 3)
        self.assertEqual(receipt["reason"], "CAPTURE_LIMIT")
        self.assertEqual(receipt["limit_witnesses"], [{
            "unit": "bytes", "threshold": 3, "observed_extent": 3,
            "missing_extent": len(RAW)-3,
            "affected_scope": "SRC-28:call0001:run:writer",
            "reason": "CAPTURE_LIMIT"}])
        a = recorded.outcome.artifacts[0]
        self.assertEqual(a.sha256, hashlib.sha256(RAW[:3]).hexdigest())
        self.assertEqual((folder / a.private_relative_path).read_bytes(), RAW[:3])
        build_canonical(folder, run)
        limits = json.loads((folder / "private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0]["affected_scope"],
                         "SRC-28:call0001:run:writer")

    def test_38_02_exact_run_meter_no_clipping_is_legacy(self):
        folder, receipt, run, called, _ = self.one(max_bytes=len(RAW))
        self.assertEqual(called.call_count, 1)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.4")
        self.assertNotIn("limit_witnesses", receipt)
        build_canonical(folder, run)

    def test_38_03_prior_source_sealed_bytes_prove_run_quota(self):
        cap = len(SRC14_RAW) + 3
        folder, receipt, run, _, _ = self.one(max_bytes=cap, prior14=True)
        self.assertEqual(receipt["acquired_bytes"], 3)
        self.assertEqual(receipt["limit_witnesses"][0]["threshold"], cap)
        build_canonical(folder, run)

    def test_38_04_unsealed_reservation_not_sufficient_canonical_proof(self):
        folder, receipt, run, _, _ = self.one(
            max_bytes=10, stale_reserved=4)
        self.assertEqual(receipt["limit_witnesses"][0]["threshold"], 10)
        self.assertEqual(receipt["acquired_bytes"], 6)
        with self.assertRaisesRegex(
                CanonicalContractError, "run writer aggregate not evidenced"):
            build_canonical(folder, run)

    def test_38_05_writer_and_transport_conflict_not_promoted(self):
        folder, receipt, run, _, _ = self.one(
            max_bytes=3, stderr=b"E"*MIB, exceeded=True, omitted_stderr=1)
        self.assertNotIn("limit_witnesses", receipt)
        self.assertTrue(receipt["capture_limited"])
        with self.assertRaisesRegex(
                CanonicalContractError, "dimension not evidenced"):
            build_canonical(folder, run)

    def test_38_06_reject_unreachable_source_and_invalid_run_writer(self):
        good = dict(unit="bytes", threshold=3, observed_extent=3,
                    missing_extent=8,
                    affected_scope="SRC-28:call0001:run:writer",
                    reason="CAPTURE_LIMIT")
        for bad in (dict(good, threshold=RUN_BYTES+1,
                         observed_extent=RUN_BYTES+1),
                    dict(good, observed_extent=2),
                    dict(good, missing_extent=0),
                    dict(good, missing_extent=None),
                    dict(good, affected_scope="SRC-28:call0002:run:writer"),
                    dict(good, affected_scope="SRC-28:call0001:source:writer",
                         threshold=32*MIB, observed_extent=32*MIB),
                    dict(good, affected_scope="SRC-28:call0001:source:bytes",
                         threshold=32*MIB, observed_extent=32*MIB)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                build_attempt(RUN, SRC, "01", "ALLOW", "PARTIAL", "CAPTURE_LIMIT",
                              capture_limited=True, limit_witnesses=(bad,))


if __name__ == "__main__":
    unittest.main()
