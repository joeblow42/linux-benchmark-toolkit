"""RP-02 D0 writer-bound source-first synthetic fixture suite; no host execution."""
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lbt_g5.evidence import EvidenceWriter, RunMeter
from lbt_g5.engine import EngineRun, CollectorRun
from lbt_g5.runtime import TransportCapture, ProbeSlots, SourceCallBudget
from lbt_g5.safety import SourceRequest, initial_source_policies
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.canonical_session import build_canonical
from lbt_g5.records import build_attempt

RUN="run-2026319130000"
SRC="SRC-02"


class D0WriterOracles(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)/RUN
        self.folder.mkdir(mode=0o700)
        self.pol={p.source_id:p for p in initial_source_policies()}[SRC]

    def writer(self,n):
        return EvidenceWriter(str(self.folder),RUN,RunMeter(max_bytes=n))

    def test_w33_01_measured_run_budget_and_preserved_prefix(self):
        writer=self.writer(3)
        result=writer.seal_chunks(self.pol,"01","item0001",(b"ABCDEFG",))
        self.assertIsNone(result.failure)
        r=result.receipt
        self.assertTrue(r.limit_applied)
        self.assertFalse(r.complete)
        self.assertEqual(r.byte_count,3)
        self.assertEqual(r.omitted_at_least,4)
        self.assertEqual(r.sha256,hashlib.sha256(b"ABC").hexdigest())
        self.assertEqual((self.folder/r.private_relative_path).read_bytes(),b"ABC")
        self.assertEqual(result.limit_events,[{
            "dimension":"writer_run_bytes","threshold":3,
            "observed_extent":3,"omitted_at_least":4
        }])

    def test_w33_02_stream_and_source_ceilings_are_both_witnessed(self):
        writer=self.writer(10*1024*1024)
        payload=b"X"*(self.pol.max_bytes+1)
        result=writer.seal_chunks(self.pol,"01","item0001",(payload,))
        self.assertIsNone(result.failure)
        self.assertEqual(result.receipt.byte_count,self.pol.max_bytes)
        self.assertEqual(result.receipt.omitted_at_least,1)
        self.assertEqual({x["dimension"] for x in result.limit_events},
                         {"writer_stream_bytes","writer_source_bytes"})

    def test_w33_03_no_limit_has_no_writer_events(self):
        result=self.writer(1000).seal_chunks(self.pol,"01","item0001",(b"OK",))
        self.assertTrue(result.receipt.complete)
        self.assertFalse(result.receipt.limit_applied)
        self.assertEqual(result.limit_events,[])

    def test_w33_06_actual_writer_limit_stays_private_v06_and_canonical(self):
        value=b"NAME=Example\n"
        blob=b"".join((json.dumps(x)+"\n").encode() for x in (
            {"path":"/etc/os-release","bytes_b64":base64.b64encode(value).decode(),
             "limited":False},
            {"end":True,"entries":1,"bytes":len(value),"limited":False}))
        transport=TransportCapture(blob,b"",0,.015,False,False,0,0)
        writer=self.writer(3)
        with patch("lbt_g5.passive._resolve_executable",return_value="/usr/bin/python3"):
            with patch("lbt_g5.passive._capture_child",return_value=transport):
                recorded=capture_and_record(SourceRequest(RUN,SRC,self.pol.operation_id),
                                            "01",writer,ProbeSlots(),SourceCallBudget())
        receipt=json.loads((self.folder/recorded.receipt_private_path).read_text())
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.6")
        bound=receipt["limit_witnesses"][0]
        self.assertEqual(bound["affected_scope"],SRC+":call0001:run:writer")
        self.assertEqual((bound["threshold"],bound["observed_extent"],
                          bound["missing_extent"]),(3,3,len(value)-3))
        run=EngineRun(RUN,(CollectorRun(self.pol.collector_id,(recorded,)),))
        build_canonical(self.folder,run)
        limits=json.loads((self.folder/"private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits),1)
        self.assertEqual(limits[0]["missing_extent"],len(value)-3)

    def test_w33_05_invalid_writer_scope_or_threshold_refused(self):
        valid=dict(unit="bytes",threshold=4,observed_extent=4,missing_extent=1,
                   affected_scope=SRC+":call0001:run:writer",reason="CAPTURE_LIMIT")
        for bad in (dict(valid,threshold=0),
                    dict(valid,affected_scope=SRC+":call0001:root:writer"),
                    dict(valid,observed_extent=2),
                    dict(valid,missing_extent=-1)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","CAPTURE_LIMIT",
                              capture_limited=True,limit_witnesses=[bad])


if __name__=="__main__":
    unittest.main()
