"""RP-02.2 SRC-15 per-call source-first F-04 oracle; mock-only."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.runtime import TransportCapture, ProbeSlots, SourceCallBudget
from lbt_g5.safety import SourceRequest, initial_source_policies
from lbt_g5.canonical_session import build_canonical, CanonicalContractError

RUN="run-2026318153200"
SRC="SRC-15"
POL={p.source_id:p for p in initial_source_policies()}
MOUNTINFO=(b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
           b"2 1 8:2 / /boot rw - ext4 /dev/sda2 rw\n")
ERR_CAP=128*1024


def raw(mount="/"):
    return (json.dumps(dict(mount=mount,fragment_size=4096,block_size=4096,
        blocks=100,free_blocks=40,available_blocks=30,
        files=1000,free_files=800),sort_keys=True)+"\n").encode()


class SRC15CallF04(unittest.TestCase):
    def one(self, captures, *, mounts=("/",)):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder=Path(temp.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        original=writer.seal_chunks(POL["SRC-14"],"01","item0001",(MOUNTINFO,)).receipt
        first=build_attempt(RUN,"SRC-14","01","ALLOW","CAPTURED","BYTES_PRESERVED",
                            evidence=(original,),bytes_count=original.byte_count,
                            invocation="MOUNTINFO",
                            source_paths=("/proc/self/mountinfo",))
        path14=commit_attempt(str(folder),first)
        rec14=SimpleNamespace(receipt_private_path=path14,
                              outcome=SimpleNamespace(artifacts=(original,)))
        with patch("lbt_g5.additional.decide_source",
                   return_value=SimpleNamespace(allowed=True,reason="APPROVED")):
            with patch("lbt_g5.additional.eligible_mounts",return_value=mounts):
                with patch("lbt_g5.additional._resolve_executable",
                           return_value="/usr/bin/python3"):
                    with patch("lbt_g5.additional._capture_child",
                               side_effect=captures) as executed:
                        rec=capture_and_record(
                            SourceRequest(RUN,SRC,"FS_STAT"),"01",writer,
                            ProbeSlots(),SourceCallBudget(),
                            source14_evidence=MOUNTINFO)
        receipt=json.loads((folder/rec.receipt_private_path).read_text())
        run=EngineRun(RUN,(CollectorRun(POL[SRC].collector_id,(rec14,rec)),))
        return folder,receipt,run,executed

    def test_s15_35_01_first_call_timeout_records_actual_seconds(self):
        transport=TransportCapture(raw(),b"",None,2.03,True,False,0,0)
        folder,receipt,run,invoked=self.one([transport])
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.6")
        self.assertEqual(receipt["limit_witnesses"],[{
            "unit":"seconds","threshold":invoked.call_args.args[3],
            "observed_extent":2.03,"missing_extent":None,
            "affected_scope":"SRC-15:call0001:transport",
            "reason":"TIME_BUDGET_EXCEEDED"}])
        build_canonical(folder,run)
        limits=json.loads((folder/"private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits),1)

    def test_s15_35_02_second_call_timeout_has_call0002_scope(self):
        transports=[TransportCapture(raw("/"),b"",0,.03,False,False,0,0),
                    TransportCapture(raw("/boot"),b"",None,2.04,True,False,0,0)]
        folder,receipt,run,invoked=self.one(transports,mounts=("/","/boot"))
        self.assertEqual(invoked.call_count,2)
        self.assertEqual(receipt["limit_witnesses"][0]["affected_scope"],
                         "SRC-15:call0002:transport")
        self.assertEqual(len(receipt["evidence_ids"]),2)
        build_canonical(folder,run)

    def test_s15_35_03_stderr_overflow_is_actual_applied_128k(self):
        transport=TransportCapture(raw(),b"W"*ERR_CAP,0,.03,False,True,0,5)
        folder,receipt,run,invoked=self.one([transport])
        self.assertEqual(invoked.call_args.args[2],ERR_CAP)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.6")
        self.assertEqual(receipt["limit_witnesses"][0]["threshold"],ERR_CAP)
        self.assertEqual(receipt["limit_witnesses"][0]["missing_extent"],5)
        self.assertEqual(receipt["limit_witnesses"][0]["affected_scope"],
                         "SRC-15:call0001:stderr")
        build_canonical(folder,run)

    def test_s15_35_05_short_stderr_omission_fails_closed(self):
        transport=TransportCapture(raw(),b"warning",0,.03,False,True,0,5)
        folder,receipt,run,_=self.one([transport])
        self.assertNotIn("limit_witnesses",receipt)
        with self.assertRaisesRegex(CanonicalContractError,"dimension not evidenced"):
            build_canonical(folder,run)

    def test_s15_35_06_nominal_remains_legacy_v04(self):
        transport=TransportCapture(raw(),b"",0,.03,False,False,0,0)
        folder,receipt,run,_=self.one([transport])
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.4")
        self.assertNotIn("limit_witnesses",receipt)
        build_canonical(folder,run)

    def test_s15_35_07_unapproved_call_scope_rejected(self):
        good=dict(unit="seconds",threshold=2.0,observed_extent=2.03,
                  missing_extent=None,affected_scope="SRC-15:call0001:transport",
                  reason="TIME_BUDGET_EXCEEDED")
        for bad in (dict(good,affected_scope="SRC-15:call0000:transport"),
                    dict(good,affected_scope="SRC-15:call0129:transport"),
                    dict(good,threshold=3.0),
                    dict(good,unit="entries")):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","TIME_BUDGET_EXCEEDED",
                              timed_out=True,limit_witnesses=[bad])

if __name__=="__main__":
    unittest.main()
