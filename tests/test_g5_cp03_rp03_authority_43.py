"""RP-03 Increment 43 — frozen CP-01 §6 D-02 contract authority receipt.

Only checks the byte-verified controlling annex and its approved 41-pair
status/14-field authority against a separate control ledger. Does not claim
that the current producer/validator conforms. RP-03.1 RED tests follow.
"""
import json
from pathlib import Path
import unittest
from lbt_g5.canonical_contract import (
    CANONICAL_SCHEMA_VERSION, STATUS_SCHEMA_VERSION, STATUS_FIELDS, STATUS_PAIRS,
)

CONTROL = Path(__file__).resolve().parents[1] / "verification" / "g5_04" / "rp03_cp01_d02_approved_contract_43.json"


class RP03ApprovedAuthorityOracles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTROL.read_text())

    def test_43_01_controlling_odt_digest_is_archive_verified(self):
        doc = self.contract["source"]
        self.assertEqual(doc["odt_sha256"], "6d836d28af086a0fec7df2ca0949faf9447f9cee29cfabb8751344bd5104c98b")
        self.assertIn("CP01_Contract_Reconciliation_Approval_Review", doc["internal_path"])
        self.assertEqual(doc["archive_integrity"], "zip CRC PASS; 7 of 7 SHA256SUMS payloads PASS")

    def test_43_02_four_closed_world_file_contracts(self):
        files = self.contract["files"]
        self.assertEqual(set(files), {"system.json", "source_attempts.json",
                                       "status_records.json", "session_manifest.json"})
        self.assertEqual(set(files["system.json"]),
                         {"schema_version", "run_id", "header", "observations",
                          "capture_limits", "limitations"})
        self.assertEqual(set(files["source_attempts.json"]),
                         {"schema_version", "run_id", "attempts"})
        self.assertEqual(set(files["status_records.json"]),
                         {"schema_version", "run_id", "status_records"})
        self.assertEqual(set(files["session_manifest.json"]), {
            "schema_version", "manifest_version", "run_id", "completion_state",
            "integrity_verified", "minimum_usable", "finalized_utc",
            "counts", "files", "evidence", "source_receipts",
            "observation_ids", "source_attempt_ids", "status_record_ids",
            "limit_record_ids", "limitations"
        })

    def test_43_03_entity_field_count_and_required_nullability(self):
        e = self.contract["entities"]
        expected = {
            "SessionHeader": 7, "SourceAttempt": 24, "EvidenceArtifact": 12,
            "CanonicalObservation": 17, "CaptureLimit": 9, "StatusRecord": 14,
            "Counts": 7, "FileDigest": 2, "ReceiptDigest": 4,
        }
        self.assertEqual({k: len(v) for k,v in e.items()}, expected)
        self.assertEqual(e["SessionHeader"]["created_by_version"], "str?")
        self.assertEqual(e["SourceAttempt"]["operator_consent"], "map?")
        self.assertEqual(e["EvidenceArtifact"]["sealed_utc"], "utc?")
        self.assertEqual(e["CanonicalObservation"]["acquired_utc"], "utc?")
        self.assertEqual(e["ReceiptDigest"]["restricted_relative_path"], "str")

    def test_43_04_preserve_separate_status_authority(self):
        self.assertEqual(self.contract["versions"], {
            "canonical": "1.0.0", "status_record": "1.0", "status_pair_count": 41
        })
        self.assertEqual(CANONICAL_SCHEMA_VERSION, "1.0.0")
        self.assertEqual(STATUS_SCHEMA_VERSION, "1.0")
        self.assertEqual(set(self.contract["entities"]["StatusRecord"]), set(STATUS_FIELDS))
        self.assertEqual(len(STATUS_PAIRS), 41)

    def test_43_05_no_candidate_keys_in_system_contract(self):
        self.assertNotIn("platform_scope", self.contract["files"]["system.json"])
        self.assertNotIn("normalization_state", self.contract["files"]["system.json"])
        self.assertIn("platform_scope", self.contract["entities"]["SessionHeader"])
        self.assertNotIn("complete", self.contract["entities"]["EvidenceArtifact"])
        self.assertIn("completeness", self.contract["entities"]["EvidenceArtifact"])

    def test_43_06_enum_controls_not_extended(self):
        e = self.contract["enum_sets"]
        self.assertEqual(e["SourceAttempt.authorization_class"], ["D0", "D1", "O1"])
        self.assertNotIn("X", e["SourceAttempt.authorization_class"])
        self.assertEqual(e["EvidenceArtifact.completeness"], ["COMPLETE", "INCOMPLETE"])
        self.assertEqual(e["session_manifest.json.completion_state"],
                         ["COMPLETE", "PARTIAL", "INCOMPLETE", "INTERRUPTED", "FAILED"])

    def test_43_07_source_fallback_not_dropped_for_unknown_canonical_member(self):
        self.assertIn("unknown keys forbidden", self.contract["notation"])
        self.assertIn("unknown acquired data", " ".join(self.contract["linkage"]))
        self.assertIn("sealed fallback", " ".join(self.contract["linkage"]))


if __name__=="__main__":
    unittest.main()
