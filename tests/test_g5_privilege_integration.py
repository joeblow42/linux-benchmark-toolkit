"""G5-03 privileged SRC-13 route through immutable G5-02 evidence boundary.

No sudo, root permission or physical drive read occurs in these tests.
"""
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
import hashlib
import json
import os
import tempfile
import unittest

from lbt_g5.evidence import EvidenceWriter
from lbt_g5.o1 import OptionalSourcePlan
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest, SourceConsent, initial_source_policies

RUN="run-2026306163727"


class SessionEvidenceIntegration(unittest.TestCase):
    def setUp(self):
        if os.geteuid()==0:
            self.skipTest("primary LBT engine cannot run as root")
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)/RUN
        self.folder.mkdir()
        self.writer=EvidenceWriter(str(self.folder),RUN)

    def _approved(self):
        consent=SourceConsent(RUN,"SRC-13","DEVICE_HEALTH","/dev/sda",
                              datetime.now(timezone.utc),True)
        return SourceRequest(RUN,"SRC-13","DEVICE_HEALTH",
                             target="/dev/sda",consent=consent,
                             trusted_targets=frozenset(("/dev/sda",)))

    def test_privileged_success_seals_verbatim_original_and_receipt(self):
        session=Mock()
        original=b"original smartctl observation bytes\n"
        session.capture.return_value=TransportCapture(
            original,b"",0,0.042,False,False,0,0)
        plan=OptionalSourcePlan("SRC-13","DEVICE_HEALTH","/dev/sda",
                                 ("smartctl","-i","-H","/dev/sda"),
                                 8*1024*1024,12,"may wake drive")
        with patch("lbt_g5.o1_execution.plan_optional",return_value=plan):
            with patch("lbt_g5.o1_execution._resolve_executable",
                       return_value="/usr/sbin/smartctl"):
                result=capture_and_record(
                    self._approved(),"01",self.writer,ProbeSlots(),
                    SourceCallBudget(),privileged_session=session)
        self.assertEqual(result.outcome["disposition"],"CAPTURED")
        receipt=result.outcome["receipts"][0]
        self.assertEqual(
            (self.folder/receipt.private_relative_path).read_bytes(),original)
        self.assertEqual(receipt.sha256,hashlib.sha256(original).hexdigest())
        private=json.loads((self.folder/result.receipt_private_path).read_text())
        self.assertEqual(private["evidence_ids"],[receipt.evidence_id])
        self.assertEqual(private["exit_code"],0)
        self.assertEqual(private["authorization_class"],"O1")
        self.assertEqual(session.capture.call_count,1)

    def test_no_consent_does_not_invoke_helper(self):
        session=Mock()
        request=SourceRequest(RUN,"SRC-13","DEVICE_HEALTH")
        result=capture_and_record(request,"01",self.writer,
                                  ProbeSlots(),SourceCallBudget(),
                                  privileged_session=session)
        self.assertEqual(result.outcome["disposition"],"DENIED")
        session.capture.assert_not_called()
        private=json.loads((self.folder/result.receipt_private_path).read_text())
        self.assertEqual(private["evidence_ids"],[])

    def test_helper_failure_is_recorded_without_fake_smart_measurements(self):
        from lbt_g5.privileged_session import PrivilegedSessionError
        session=Mock()
        session.capture.side_effect=PrivilegedSessionError("test helper failed")
        plan=OptionalSourcePlan("SRC-13","DEVICE_HEALTH","/dev/sda",
                                ("smartctl","-i","-H","/dev/sda"),
                                8*1024*1024,12,"may wake drive")
        with patch("lbt_g5.o1_execution.plan_optional",return_value=plan):
            with patch("lbt_g5.o1_execution._resolve_executable",
                       return_value="/usr/sbin/smartctl"):
                result=capture_and_record(self._approved(),"01",self.writer,
                      ProbeSlots(),SourceCallBudget(),privileged_session=session)
        self.assertEqual(result.outcome["disposition"],"FAILED")
        self.assertEqual(result.outcome["reason"],"PRIVILEGED_HELPER_ERROR")
        stored=json.loads((self.folder/result.receipt_private_path).read_text())
        self.assertEqual(stored["evidence_ids"],[])


if __name__=="__main__":
    unittest.main()
