"""Source-first approved CP-01 D-04 actual acquired source timing contract.

No host reads: mock the existing G5-03 passive adapter; use sealed bytes.
"""
import json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from datetime import datetime
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt
from lbt_g5.safety import SourceRequest,initial_source_policies
from lbt_g5.runtime import ProbeSlots,SourceCallBudget
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.engine import EngineRun,CollectorRun
from lbt_g5.canonical_session import build_canonical

RUN="run-2026305120000"

class F02SourceTimingSourceFirst(unittest.TestCase):
    def setup_case(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        folder=Path(temp.name)/RUN;folder.mkdir(mode=0o700)
        return folder,EvidenceWriter(str(folder),RUN)
    def make(self,disposition="CAPTURED",reason="BYTES_PRESERVED"):
        folder,writer=self.setup_case()
        req=SourceRequest(RUN,"SRC-08","PROC_MEMINFO")
        pol={x.source_id:x for x in initial_source_policies()}["SRC-08"]
        original=writer.seal_chunks(pol,"01","item0001",(b"MemTotal: 1024 kB\n",)).receipt
        outcome=SimpleNamespace(disposition=disposition,reason=reason,
             artifacts=(original,),source_paths=("/proc/meminfo",),errors=(),elapsed_seconds=.01)
        with patch("lbt_g5.receipt_dispatch.acquire_passive",return_value=outcome):
            recorded=capture_and_record(req,"01",writer,ProbeSlots(),SourceCallBudget())
        payload=json.loads((folder/recorded.receipt_private_path).read_text())
        return folder,payload,recorded

    def test_real_adapter_call_measured_utc_monotonic_and_status(self):
        folder,payload,recorded=self.make()
        self.assertEqual(payload["schema_version"],"g5-02-attempt-0.4")
        clock=payload["source_timing"]
        self.assertEqual(set(clock),{"started_utc","completed_utc","elapsed_ms"})
        start=datetime.fromisoformat(clock["started_utc"].replace("Z","+00:00"))
        end=datetime.fromisoformat(clock["completed_utc"].replace("Z","+00:00"))
        self.assertGreaterEqual(end,start)
        self.assertIsInstance(clock["elapsed_ms"],int)
        self.assertGreaterEqual(clock["elapsed_ms"],0)
        manifest=build_canonical(folder,EngineRun(RUN,(CollectorRun("COL-MEM",(recorded,)),)))
        self.assertTrue(manifest["integrity_verified"])
        statuses=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        record=next(x for x in statuses if x["subject_id"]=="SRC-08")
        self.assertEqual((record["started_utc"],record["completed_utc"],record["elapsed_ms"]),
                         (clock["started_utc"],clock["completed_utc"],clock["elapsed_ms"]))

    def test_denied_pre_execution_has_no_source_clock(self):
        folder,writer=self.setup_case()
        req=SourceRequest(RUN,"SRC-08","PROC_MEMINFO",operator_disabled=True)
        denied=SimpleNamespace(disposition="DENIED",reason="OPERATOR_EXCLUDED",
                                artifacts=(),elapsed_seconds=None)
        with patch("lbt_g5.receipt_dispatch.acquire_passive",return_value=denied):
            recorded=capture_and_record(req,"01",writer,ProbeSlots(),SourceCallBudget())
        payload=json.loads((folder/recorded.receipt_private_path).read_text())
        self.assertEqual(payload["schema_version"],"g5-02-attempt-0.1")
        self.assertNotIn("source_timing",payload)

    def test_partial_operation_retains_measured_clock(self):
        folder,payload,recorded=self.make("PARTIAL","CAPTURE_LIMIT")
        self.assertEqual(payload["schema_version"],"g5-02-attempt-0.4")
        self.assertIsInstance(payload["source_timing"]["elapsed_ms"],int)

    def test_invalid_clock_fails_receipt_precommit(self):
        good=dict(started_utc="2026-11-08T12:00:00.000Z",
                  completed_utc="2026-11-08T12:00:00.200Z",elapsed_ms=200)
        bad=(
           dict(good,elapsed_ms=-1),
           dict(good,elapsed_ms=2.0),
           dict(good,started_utc="2026-11-08T12:00:00"),
           dict(good,completed_utc="2000-01-01T00:00:00Z"),
           dict(good,completed_utc=None)
        )
        for timing in bad:
            with self.subTest(clock=timing),self.assertRaises(ValueError):
                build_attempt(RUN,"SRC-08","01","ALLOW","CAPTURED","BYTES_PRESERVED",
                              invocation="PROC_MEMINFO",source_timing=timing)

    def test_old_receipt_never_fabricates_start(self):
        receipt=build_attempt(RUN,"SRC-08","01","ALLOW","CAPTURED","BYTES_PRESERVED",
                              invocation="PROC_MEMINFO",elapsed_seconds=.1)
        self.assertIsNone(receipt.source_timing)
        self.assertEqual(receipt.schema_version,"g5-02-attempt-0.1")

if __name__=="__main__":unittest.main()
