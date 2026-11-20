"""LBT RP-04 Increment 60 — original CT-06 timing candidate verification.

P1: actual unprivileged Linux CI-host D0 memory acquisition, no O1, sudo,
benchmark or physical Bodhi 7. P2/N1/N2: offline actual private receipts,
factual clock reconciliation, and injected ordinary producer regression.
NOT formal original CP-02 execution/acceptance.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import lbt_g5.canonical_session as cs
from lbt_g5.canonical_contract import CanonicalContractError, new_status
from lbt_g5.engine import CollectorRun, EngineRun, UnifiedCollectorEngine
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.runtime import ProbeSlots, SourceCallBudget
from lbt_g5.safety import SourceRequest, initial_source_policies

RUN="run-2026320206000"
POL={p.source_id:p for p in initial_source_policies()}

def utc(text):
    return datetime.fromisoformat(text.replace("Z","+00:00"))

class RP04CT06Candidate60(unittest.TestCase):
    live_witness=None

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)/RUN
        self.folder.mkdir(mode=0o700)

    def offline_recorded_src08(self):
        writer=EvidenceWriter(str(self.folder),RUN)
        raw=b"MemTotal: 1024 kB\nMemFree: 256 kB\n"
        original=writer.seal_chunks(POL["SRC-08"],"01","item0001",(raw,)).receipt
        self.assertIsNotNone(original)
        outcome=SimpleNamespace(
            disposition="CAPTURED",reason="BYTES_PRESERVED",
            artifacts=(original,),source_paths=("/proc/meminfo",),
            errors=(),elapsed_seconds=.001)
        with patch("lbt_g5.receipt_dispatch.acquire_passive",return_value=outcome):
            recorded=capture_and_record(SourceRequest(RUN,"SRC-08","PROC_MEMINFO"),
                "01",writer,ProbeSlots(),SourceCallBudget())
        return recorded

    @unittest.skipIf(sys.platform!="linux" or os.geteuid()==0,
                     "requires unprivileged Linux CI")
    def test_60_01_CT_06_P1_actual_ci_source_utc_and_monotonic(self):
        run=UnifiedCollectorEngine(str(self.folder),RUN).run(("COL-MEM",))
        self.assertEqual(run.source_attempt_count,3)
        actual=next(x for c in run.collectors for x in c.source_attempts
                    if x.receipt_private_path.endswith("SRC-08-01.json"))
        receipt=json.loads((self.folder/actual.receipt_private_path).read_text())
        self.assertEqual(receipt["source_id"],"SRC-08")
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.4")
        clock=receipt["source_timing"]
        self.assertEqual(set(clock),{"started_utc","completed_utc","elapsed_ms"})
        start,end=utc(clock["started_utc"]),utc(clock["completed_utc"])
        self.assertEqual(start.utcoffset().total_seconds(),0)
        self.assertEqual(end.utcoffset().total_seconds(),0)
        self.assertGreaterEqual(end,start)
        self.assertIs(type(clock["elapsed_ms"]),int)
        self.assertGreaterEqual(clock["elapsed_ms"],0)
        # UTC and monotonic are different clocks: permit 0.25s rounding/clock drift.
        self.assertLessEqual(abs((end-start).total_seconds()*1000-clock["elapsed_ms"]),250)
        manifest=cs.build_canonical(self.folder,run)
        self.assertEqual(cs.validate_canonical(self.folder),manifest)
        acquisitions=json.loads((self.folder/"private/status_records.json").read_text())["status_records"]
        st=next(x for x in acquisitions
                if x["domain"]=="acquisition" and x["subject_id"]=="SRC-08")
        attempts=json.loads((self.folder/"private/source_attempts.json").read_text())["attempts"]
        attempt=next(x for x in attempts if x["source_id"]=="SRC-08")
        for payload in (st,attempt):
            self.assertEqual([payload["started_utc"],payload["completed_utc"],
                              payload["elapsed_ms"]],
                             [clock["started_utc"],clock["completed_utc"],clock["elapsed_ms"]])
        type(self).live_witness={
            "source_id":"SRC-08","context":"UNPRIVILEGED_LINUX_GITHUB_CI_HOST",
            "source_started_utc":clock["started_utc"],
            "source_completed_utc":clock["completed_utc"],
            "measured_monotonic_elapsed_ms":clock["elapsed_ms"],
            "status_record_id":st["record_id"],
            "not_bodhi7_fat":True,
        }

    def test_60_02_CT_06_P2_denied_attempt_has_nullable_execution_clock(self):
        writer=EvidenceWriter(str(self.folder),RUN)
        receipt=build_attempt(RUN,"SRC-13","01","DENY","DENIED",
                              "OPERATOR_AUTH_REQUIRED",evidence=(),bytes_count=0)
        location=commit_attempt(str(self.folder),receipt)
        original=json.loads((self.folder/location).read_text())
        self.assertNotIn("source_timing",original)
        record=SimpleNamespace(
            receipt_private_path=location,
            outcome=SimpleNamespace(artifacts=()))
        run=EngineRun(RUN,(CollectorRun("COL-BLOCK",(record,)),))
        manifest=cs.build_canonical(self.folder,run)
        self.assertEqual(cs.validate_canonical(self.folder),manifest)
        attempts=json.loads((self.folder/"private/source_attempts.json").read_text())["attempts"]
        statuses=json.loads((self.folder/"private/status_records.json").read_text())["status_records"]
        src=next(x for x in statuses
                 if x["domain"]=="acquisition" and x["subject_id"]=="SRC-13")
        self.assertEqual((src["status"],src["reason_code"]),
                         ("UNAUTHORIZED","OPERATOR_AUTH_REQUIRED"))
        for item in (attempts[0],src):
            self.assertIsNone(item["started_utc"])
            self.assertIsNone(item["completed_utc"])
            self.assertIsNone(item["elapsed_ms"])

    def test_60_03_CT_06_N1_actual_recorded_clock_cannot_be_dropped(self):
        recorded=self.offline_recorded_src08()
        source=self.folder/recorded.receipt_private_path
        persisted=json.loads(source.read_text())
        self.assertEqual(persisted["schema_version"],"g5-02-attempt-0.4")
        self.assertIsNotNone(persisted["source_timing"])
        self.assertIsNotNone(recorded.source_timing)
        load=cs._json_load
        def faulty_producer_view(data):
            item=load(data)
            if type(item) is dict and item.get("attempt_id")=="SRC-08-01":
                # Test-only production-reader regression injection: receipt
                # stays immutable on disk, but a consumer loses its clock.
                item.pop("source_timing",None)
            return item
        run=EngineRun(RUN,(CollectorRun("COL-MEM",(recorded,)),))
        with patch("lbt_g5.canonical_session._json_load",
                   side_effect=faulty_producer_view):
            with self.assertRaisesRegex(CanonicalContractError,
                                        "versioned source clock missing"):
                cs.build_canonical(self.folder,run)
        self.assertFalse((self.folder/"private/session_manifest.json").exists())
        self.assertFalse((self.folder/"private/status_records.json").exists())
        self.assertEqual(json.loads(source.read_text()),persisted)
        # With the actual receipt restored and no mutation, result is valid.
        manifest=cs.build_canonical(self.folder,run)
        self.assertEqual(cs.validate_canonical(self.folder),manifest)

    def test_60_04_CT_06_N2_reversed_utc_event_is_rejected(self):
        bad={"started_utc":"2026-11-19T12:00:01.000Z",
             "completed_utc":"2026-11-19T12:00:00.999Z","elapsed_ms":20}
        with self.assertRaises(ValueError):
            build_attempt(RUN,"SRC-08","01","ALLOW","CAPTURED","BYTES_PRESERVED",
                          source_timing=bad)
        with self.assertRaises(CanonicalContractError):
            new_status(record_id="ct06.reversed",domain="acquisition",
                       component_id="COL-MEM",subject_id="SRC-08",
                       status="COMPLETE",reason_code="OK",
                       started_utc=bad["started_utc"],
                       completed_utc=bad["completed_utc"],elapsed_ms=20)


if __name__=="__main__":
    unittest.main()
