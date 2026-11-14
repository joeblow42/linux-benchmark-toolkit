"""RP-02.1b independent-target D0 transport facts; mock-only (not CP-02 acceptance)."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lbt_g5.engine import EngineRun, CollectorRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.runtime import TransportCapture, ProbeSlots, SourceCallBudget
from lbt_g5.safety import SourceRequest, initial_source_policies
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.canonical_session import build_canonical, CanonicalContractError
from lbt_g5.records import build_attempt

RUN = "run-2026318130000"
SRC = "SRC-02"
ERR_CAP=65536


def source_blob():
    value=b"NAME=Test OS\n"
    parts=[
        {"path":"/etc/os-release","bytes_b64":base64.b64encode(value).decode(),"limited":False},
        {"end":True,"entries":1,"bytes":len(value),"limited":False}
    ]
    return b"".join((json.dumps(p)+"\n").encode() for p in parts)


class D0TransportOracles(unittest.TestCase):
    def one(self, *, stdout=None, stderr=b"", timed_out=False, exceeded=False,
            stdout_missing=0, stderr_missing=0):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        folder=Path(td.name)/RUN
        folder.mkdir(mode=0o700)
        pol={p.source_id:p for p in initial_source_policies()}[SRC]
        t=TransportCapture(source_blob() if stdout is None else stdout,
                           stderr, None if timed_out else 0,
                           2.125 if timed_out else .025,timed_out,exceeded,
                           stdout_missing,stderr_missing)
        with patch("lbt_g5.passive._resolve_executable",return_value="/usr/bin/python3"):
            with patch("lbt_g5.passive._capture_child",return_value=t) as call:
                rec=capture_and_record(SourceRequest(RUN,SRC,pol.operation_id),
                                       "01",EvidenceWriter(str(folder),RUN),
                                       ProbeSlots(),SourceCallBudget())
        receipt=json.loads((folder/rec.receipt_private_path).read_text())
        run=EngineRun(RUN,(CollectorRun(pol.collector_id,(rec,)),))
        return folder,receipt,run,call

    def test_t32_01_actual_stderr_transport_cap(self):
        folder,receipt,run,call=self.one(
            stderr=b"E"*ERR_CAP,exceeded=True,stderr_missing=3)
        self.assertEqual(call.call_args.args[2],ERR_CAP)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.6")
        limit=receipt["limit_witnesses"][0]
        self.assertEqual(limit["unit"],"bytes")
        self.assertEqual(limit["threshold"],ERR_CAP)
        self.assertEqual(limit["observed_extent"],ERR_CAP)
        self.assertEqual(limit["missing_extent"],3)
        self.assertEqual(limit["affected_scope"],SRC+":call0001:stderr")
        build_canonical(folder,run)
        limits=json.loads((folder/"private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits),1)
        self.assertEqual(limits[0]["missing_extent"],3)

    def test_t32_02_simultaneous_timeout_and_stderr_overrun(self):
        folder,receipt,run,call=self.one(
            stderr=b"E"*ERR_CAP,timed_out=True,exceeded=True,stderr_missing=5)
        bounds=receipt["limit_witnesses"]
        self.assertEqual({b["unit"] for b in bounds},{"bytes","seconds"})
        self.assertEqual(next(b for b in bounds if b["unit"]=="seconds")["threshold"],
                         call.call_args.args[3])
        build_canonical(folder,run)
        limits=json.loads((folder/"private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits),2)
        status=json.loads((folder/"private/status_records.json").read_text())["status_records"][0]
        self.assertEqual(set(status["limit_record_ids"]),{b["limit_id"] for b in limits})

    def test_t32_03_short_stdout_cannot_witness_reported_overflow(self):
        folder,receipt,run,call=self.one(exceeded=True,stdout_missing=3)
        self.assertNotIn("limit_witnesses",receipt)
        with self.assertRaisesRegex(CanonicalContractError,"dimension not evidenced"):
            build_canonical(folder,run)

    def test_t32_04_inconsistent_overflow_without_limited_flag_fails_closed(self):
        folder,receipt,run,call=self.one(stderr_missing=3)
        self.assertNotIn("limit_witnesses",receipt)
        with self.assertRaisesRegex(CanonicalContractError,"dimension not evidenced"):
            build_canonical(folder,run)

    def test_t32_05_invalid_stderr_cap_refused(self):
        good=dict(unit="bytes",threshold=ERR_CAP,observed_extent=ERR_CAP,
                  missing_extent=3,affected_scope=SRC+":call0001:stderr",
                  reason="CAPTURE_LIMIT")
        for bad in (dict(good,threshold=1),dict(good,affected_scope=SRC+":call0001:other"),
                    dict(good,observed_extent=2),dict(good,missing_extent=-2)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","CAPTURE_LIMIT",
                              limit_witnesses=[bad],capture_limited=True)

    def test_t32_06_no_limit_retains_old_receipt(self):
        folder,receipt,run,_=self.one()
        self.assertNotIn("limit_witnesses",receipt)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.4")
        build_canonical(folder,run)
        self.assertEqual(json.loads((folder/"private/system.json").read_text())["capture_limits"],[])


if __name__=="__main__":
    unittest.main()
