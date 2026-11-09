"""CT-05 source-first actual effective D1 capture bound dimensions.

All transports are mocked, no source commands or network operations run.
"""
import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.runtime import ProbeSlots,SourceCallBudget,TransportCapture
from lbt_g5.safety import SourceRequest
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.engine import EngineRun,CollectorRun
from lbt_g5.records import build_attempt
from lbt_g5.canonical_session import build_canonical,CanonicalContractError

RUN="run-2026305120000"
SRC="SRC-23"

class F04ActualCaptureLimitOracles(unittest.TestCase):
    def one(self,transport):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
        folder=Path(td.name)/RUN
        folder.mkdir(mode=0o700)
        request=SourceRequest(RUN,SRC,"IP_LOCAL")
        writer=EvidenceWriter(str(folder),RUN)
        with patch("lbt_g5.runtime._resolve_executable",return_value="/usr/bin/ip"):
            with patch("lbt_g5.runtime._capture_child",return_value=transport) as invoked:
                recorded=capture_and_record(request,"01",writer,ProbeSlots(),
                                            SourceCallBudget(),subcall=0)
        receipt=json.loads((folder/recorded.receipt_private_path).read_text())
        run=EngineRun(RUN,(CollectorRun("COL-NET",(recorded,)),))
        return folder,receipt,run,invoked

    def test_actual_time_bound_is_seconds_and_applied_call_ceiling(self):
        t=TransportCapture(b"[]",b"",None,5.03,True,False,0,0)
        folder,receipt,run,mock=self.one(t)
        self.assertEqual(mock.call_count,1)
        self.assertEqual(mock.call_args.args[3],5.0)
        self.assertEqual(receipt["limit_witness"],{
            "unit":"seconds","threshold":5.0,"observed_extent":5.03,
            "missing_extent":None,"affected_scope":"SRC-23:call0001:transport",
            "reason":"TIME_BUDGET_EXCEEDED"})
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.5")
        build_canonical(folder,run)
        limits=json.loads((folder/"private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits),1)
        self.assertEqual(limits[0]["unit"],"seconds")
        self.assertEqual(limits[0]["threshold"],5.0)
        self.assertIsNone(limits[0]["missing_extent"])

    def test_actual_stdout_byte_cap_and_known_omission(self):
        t=TransportCapture(b"[]",b"",0,.05,False,True,7,0)
        folder,receipt,run,_=self.one(t)
        self.assertEqual(receipt["limit_witness"]["unit"],"bytes")
        self.assertEqual(receipt["limit_witness"]["threshold"],8*1024*1024)
        self.assertEqual(receipt["limit_witness"]["observed_extent"],2)
        self.assertEqual(receipt["limit_witness"]["missing_extent"],7)
        build_canonical(folder,run)
        limit=json.loads((folder/"private/system.json").read_text())["capture_limits"][0]
        self.assertEqual((limit["unit"],limit["threshold"],limit["missing_extent"]),
                         ("bytes",8*1024*1024,7))

    def test_not_limited_records_no_capture_limit(self):
        folder,receipt,run,_=self.one(TransportCapture(b"[]",b"",0,.01,False,False,0,0))
        self.assertNotIn("limit_witness",receipt)
        build_canonical(folder,run)
        self.assertFalse(json.loads((folder/"private/system.json").read_text())["capture_limits"])

    def test_invalid_bound_shapes_fail_closed_before_receipt(self):
        base=dict(unit="seconds",threshold=5.0,observed_extent=5.0,
                  missing_extent=None,affected_scope="SRC-23:call0001:transport",
                  reason="TIME_BUDGET_EXCEEDED")
        bad=(
            dict(base,unit="bytes"),
            dict(base,threshold=-1),
            dict(base,observed_extent=float("nan")),
            dict(base,missing_extent=1),
            dict(base,affected_scope="/proc/self/environ"),
            dict(base,reason="CAPTURE_LIMIT"),
        )
        for entry in bad:
            with self.subTest(bound=entry),self.assertRaises(ValueError):
                build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","TIME_BUDGET_EXCEEDED",
                              invocation="IP_LOCAL",limit_witness=entry)

    def test_legacy_timed_out_receipt_cannot_fabricate_effective_seconds(self):
        from lbt_g5.safety import initial_source_policies
        policy={p.source_id:p for p in initial_source_policies()}[SRC]
        self.assertEqual(policy.max_seconds,10)
        self.assertEqual(policy.per_target_seconds,5)
        # Only a runtime-applied bound witness resolves which 5/10s ceiling was
        # actually active; policy.max_seconds alone is not event evidence.
        good=dict(unit="seconds",threshold=5.0,observed_extent=5.03,
                  missing_extent=None,affected_scope="SRC-23:call0001:transport",
                  reason="TIME_BUDGET_EXCEEDED")
        bad=dict(good,threshold=10.0)
        with self.assertRaises(ValueError):
            build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","TIME_BUDGET_EXCEEDED",
                          invocation="IP_LOCAL",limit_witness=bad)

if __name__=="__main__":unittest.main()
