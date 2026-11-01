import json
import tempfile
import unittest
from pathlib import Path
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.runtime import ProbeSlots,SourceCallBudget
from lbt_g5.safety import SourceRequest
from lbt_g5.receipt_dispatch import capture_and_record
RUN="run-2026305120000"
class ReceiptBoundary(unittest.TestCase):
    def test_o1_refusal_is_recorded_without_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/RUN
            folder.mkdir()
            outcome=capture_and_record(SourceRequest(RUN,"SRC-13","DEVICE_HEALTH"),
                "01",EvidenceWriter(str(folder),RUN),ProbeSlots(),SourceCallBudget())
            self.assertEqual(outcome.outcome["disposition"],"DENIED")
            stored=json.loads((folder/outcome.receipt_private_path).read_text())
            self.assertEqual(stored["outcome"],"DENIED")
            self.assertEqual(stored["evidence_ids"],[])

    def test_o1_exit_code_and_elapsed_durably_recorded(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/RUN
            folder.mkdir()
            mock_outcome={"disposition":"PARTIAL","reason":"ACQUISITION_ERROR",
                    "receipts":(),"exit_code":5,"elapsed_seconds":.2,
                    "timed_out":False,"capture_limited":False}
            with patch("lbt_g5.receipt_dispatch.execute_optional",
                       return_value=mock_outcome):
                result=capture_and_record(SourceRequest(RUN,"SRC-18","OPTICAL_MEDIA",
                            target="/dev/sr0"),"01",EvidenceWriter(str(folder),RUN),
                            ProbeSlots(),SourceCallBudget())
            stored=json.loads((folder/result.receipt_private_path).read_text())
            self.assertEqual(stored["exit_code"],5)
            self.assertEqual(stored["elapsed_seconds"],.2)
            self.assertEqual(stored["outcome"],"PARTIAL")
            self.assertEqual(stored["evidence_ids"],[])
