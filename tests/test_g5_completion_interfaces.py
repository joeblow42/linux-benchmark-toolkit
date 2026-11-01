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
