"""SRC-28 source-first D1 F-04 transport facts. Synthetic mock-only, CP-02 open."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lbt_g5.evidence import EvidenceWriter
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest, initial_source_policies
from lbt_g5.canonical_session import build_canonical, CanonicalContractError
from lbt_g5.records import build_attempt

RUN="run-2026318140030"
SRC="SRC-28"
RAW=b"dpkg\t1.21.22\n"
ERR_CAP=1024*1024
SOURCE={p.source_id:p for p in initial_source_policies()}[SRC]


class SRC28TransportF04(unittest.TestCase):
    def one(self, *, stderr=b"", stdout=RAW, timed_out=False,
            exceeded=False, omitted_stdout=0, omitted_stderr=0):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder=Path(temp.name)/RUN
        folder.mkdir(mode=0o700)
        cap=TransportCapture(stdout,stderr,None if timed_out else 0,
                             8.031 if timed_out else .06,timed_out,exceeded,
                             omitted_stdout,omitted_stderr)
        with patch("lbt_g5.additional.decide_source",
                   return_value=SimpleNamespace(allowed=True,reason="APPROVED")):
            with patch("lbt_g5.additional._resolve_executable",
                       return_value="/usr/bin/dpkg-query"):
                with patch("lbt_g5.additional._capture_child",return_value=cap) as invoked:
                    recorded=capture_and_record(
                        SourceRequest(RUN,SRC,"OFFLINE_METADATA"),"01",
                        EvidenceWriter(str(folder),RUN),ProbeSlots(),SourceCallBudget())
        receipt=json.loads((folder/recorded.receipt_private_path).read_text())
        run=EngineRun(RUN,(CollectorRun(SOURCE.collector_id,(recorded,)),))
        return folder,receipt,run,invoked

    def test_r28_34_01_stderr_limit_records_actual_cap(self):
        folder,receipt,run,invoked=self.one(
            stderr=b"W"*ERR_CAP,exceeded=True,omitted_stderr=7)
        self.assertEqual(invoked.call_args.args[2],ERR_CAP)
        self.assertEqual(invoked.call_args.args[4],8*ERR_CAP)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.6")
        self.assertNotIn("limit_witness",receipt)
        self.assertEqual(receipt["limit_witnesses"],[{
            "unit":"bytes","threshold":ERR_CAP,
            "observed_extent":ERR_CAP,"missing_extent":7,
            "affected_scope":"SRC-28:call0001:stderr","reason":"CAPTURE_LIMIT"}])
        self.assertEqual(len(receipt["evidence_ids"]),2)
        build_canonical(folder,run)
        limits=json.loads((folder/"private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits),1)
        self.assertEqual(limits[0]["missing_extent"],7)

    def test_r28_34_02_timeout_and_overflow_preserve_two_limit_ids(self):
        folder,receipt,run,invoked=self.one(
            stderr=b"E"*ERR_CAP,timed_out=True,exceeded=True,omitted_stderr=1)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.6")
        self.assertEqual(len(receipt["limit_witnesses"]),2)
        seconds=[x for x in receipt["limit_witnesses"] if x["unit"]=="seconds"][0]
        self.assertEqual(seconds["threshold"],invoked.call_args.args[3])
        self.assertEqual(seconds["observed_extent"],8.031)
        build_canonical(folder,run)
        limits=json.loads((folder/"private/system.json").read_text())["capture_limits"]
        statuses=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        status=next(x for x in statuses if x["subject_id"]==SRC)
        self.assertEqual(len(limits),2)
        self.assertEqual(set(status["limit_record_ids"]),{x["limit_id"] for x in limits})

    def test_r28_34_03_short_stderr_cannot_prove_reported_cap(self):
        folder,receipt,run,_=self.one(
            stderr=b"small",exceeded=True,omitted_stderr=1)
        self.assertNotIn("limit_witnesses",receipt)
        with self.assertRaisesRegex(CanonicalContractError,"dimension not evidenced"):
            build_canonical(folder,run)

    def test_r28_34_04_overflow_flag_without_omitted_extent_fails_closed(self):
        folder,receipt,run,_=self.one(stderr=b"warning",exceeded=True)
        self.assertNotIn("limit_witnesses",receipt)
        with self.assertRaisesRegex(CanonicalContractError,"dimension not evidenced"):
            build_canonical(folder,run)

    def test_r28_34_04b_omitted_bytes_without_transport_flag_cannot_pass(self):
        folder,receipt,run,_=self.one(
            stderr=b"E"*ERR_CAP,exceeded=False,omitted_stderr=1)
        self.assertEqual(receipt["outcome"],"PARTIAL")
        self.assertTrue(receipt["capture_limited"])
        self.assertNotIn("limit_witnesses",receipt)
        with self.assertRaisesRegex(CanonicalContractError,"dimension not evidenced"):
            build_canonical(folder,run)

    def test_r28_34_05_clean_transport_is_legacy_v04(self):
        folder,receipt,run,_=self.one()
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.4")
        self.assertNotIn("limit_witnesses",receipt)
        build_canonical(folder,run)
        limits=json.loads((folder/"private/system.json").read_text())["capture_limits"]
        self.assertEqual(limits,[])

    def test_r28_34_06_single_timeout_still_legacy_v05(self):
        folder,receipt,run,invoked=self.one(timed_out=True)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.5")
        self.assertEqual(receipt["limit_witness"]["threshold"],invoked.call_args.args[3])
        build_canonical(folder,run)

    def test_r28_34_07_invalid_scope_or_threshold_rejected(self):
        good=dict(unit="bytes",threshold=ERR_CAP,observed_extent=ERR_CAP,
                  missing_extent=1,affected_scope="SRC-28:call0001:stderr",
                  reason="CAPTURE_LIMIT")
        for bad in (dict(good,threshold=1024),
                    dict(good,affected_scope="SRC-28:call0002:stderr"),
                    dict(good,unit="entries"),
                    dict(good,missing_extent=-1)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","CAPTURE_LIMIT",
                              capture_limited=True,limit_witnesses=[bad])
        with self.assertRaises(ValueError):
            build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","CAPTURE_LIMIT",
                          capture_limited=True,limit_witnesses=[good,good])

if __name__=="__main__":
    unittest.main()
