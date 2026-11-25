"""RP-04 Increment 62: exact CT-08-P1/N1 zero-original offline candidate checks.

CT-08-N2 is G5-06 downstream regeneration and intentionally NOT EXECUTED.
The test simulates ordinary incomplete/denied source outcomes, not hostile
actors or a real unprivileged/physical source run.
"""
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import lbt_g5.canonical_session as canonical
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt

RUN="run-2026320205900"

class RP04CT08Candidate62(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)/RUN
        self.folder.mkdir(mode=0o700)
        self.writer=EvidenceWriter(str(self.folder),RUN)

    def source(self,sid,decision,outcome,reason):
        receipt=build_attempt(RUN,sid,"01",decision,outcome,reason,
                              evidence=(),bytes_count=0)
        location=commit_attempt(str(self.folder),receipt)
        stored=json.loads((self.folder/location).read_text())
        self.assertEqual(stored["evidence_ids"],[])
        return SimpleNamespace(
            receipt_private_path=location,
            outcome=SimpleNamespace(artifacts=()))

    def zero_observation(self):
        denied=self.source("SRC-13","DENY","DENIED","OPERATOR_AUTH_REQUIRED")
        unavailable=self.source("SRC-08","ALLOW","UNAVAILABLE","SOURCE_ABSENT")
        run=EngineRun(RUN,(CollectorRun("COL-BLOCK",(denied,)),
                           CollectorRun("COL-MEM",(unavailable,))))
        manifest=canonical.build_canonical(self.folder,run)
        self.assertEqual(canonical.validate_canonical(self.folder),manifest)
        files={
            name:json.loads((self.folder/"private"/name).read_text())
            for name in ("system.json","source_attempts.json","status_records.json")}
        return manifest,files

    def test_62_01_CT_08_P1_all_denied_unavailable_zero_originals(self):
        manifest,files=self.zero_observation()
        self.assertEqual(manifest["counts"]["attempts"],2)
        self.assertEqual(manifest["counts"]["evidence_artifacts"],0)
        self.assertEqual(manifest["counts"]["original_bytes"],0)
        self.assertEqual(manifest["counts"]["observations"],0)
        self.assertEqual(manifest["evidence"],{})
        self.assertTrue(manifest["integrity_verified"])
        self.assertTrue(manifest["minimum_usable"])
        self.assertEqual(manifest["completion_state"],"INCOMPLETE")
        self.assertEqual(files["system.json"]["header"]["lifecycle_state"],"INCOMPLETE")
        self.assertEqual(files["system.json"]["observations"],[])
        self.assertTrue(files["system.json"]["limitations"])
        status=files["status_records.json"]["status_records"]
        outcomes={(s["subject_id"],s["status"],s["reason_code"])
                  for s in status if s["domain"]=="acquisition"}
        self.assertEqual(outcomes,{
            ("SRC-13","UNAUTHORIZED","OPERATOR_AUTH_REQUIRED"),
            ("SRC-08","UNAVAILABLE","SOURCE_ABSENT")})
        orchestrated=[s for s in status if s["domain"]=="orchestration"]
        self.assertEqual(len(orchestrated),1)
        self.assertEqual((orchestrated[0]["status"],orchestrated[0]["reason_code"]),
                         ("PARTIAL","MINIMUM_WITH_GAPS"))
        self.assertFalse((self.folder/"public").exists())

    def test_62_02_CT_08_N1_false_complete_session_cannot_validate(self):
        manifest,files=self.zero_observation()
        orch=next(s for s in files["status_records.json"]["status_records"]
                  if s["domain"]=="orchestration")
        self.assertNotEqual(orch["status"],"COMPLETE")
        self.assertEqual(manifest["completion_state"],"INCOMPLETE")
        # A simulated ordinary consumer decoding regression presents a
        # supposedly COMPLETE orchestration row despite zero observations.
        # The immutable committed records/digests are never edited.
        load=canonical._json_load
        def bad_memory_view(raw):
            output=load(raw)
            if type(output) is dict and "status_records" in output:
                for item in output["status_records"]:
                    if item.get("domain")=="orchestration":
                        item["status"]="COMPLETE"
                        item["reason_code"]="ALL_REQUIRED_COMPLETE"
            return output
        with patch("lbt_g5.canonical_session._json_load",
                   side_effect=bad_memory_view):
            with self.assertRaises(CanonicalContractError):
                canonical.validate_canonical(self.folder)
        self.assertEqual(canonical.validate_canonical(self.folder),manifest)
        original_status=json.loads((self.folder/"private/status_records.json").read_text())
        self.assertEqual(original_status,files["status_records.json"])


if __name__=="__main__":
    unittest.main()
