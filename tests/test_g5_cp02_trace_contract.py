"""CP-02 requirements trace and independent contract-oracle tests.

These tests check the governed test SPECIFICATION and pinned control keys,
not full G5-04 implementation conformance. One explicitly expected failure
represents known incorrect behavior; it is NOT a passing acceptance case.
"""
import csv
import json
from pathlib import Path
import unittest

from lbt_g5.canonical_contract import (
    CANONICAL_SCHEMA_VERSION, STATUS_SCHEMA_VERSION,
    STATUS_FIELDS, STATUS_PAIRS,
)
from lbt_g5.canonical_session import _status_for

ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "verification" / "g5_04"
BASELINE_SHA = "04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702"
SCOPES = {"DIRECT", "BOUNDARY", "DOWNSTREAM", "UNASSESSED_FOR_G5_04"}


def read_csv(name):
    with (CONTROL / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


class G504CP02ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = read_csv("requirements_traceability_rev1_6.csv")
        cls.spec = json.loads((CONTROL / "cp02_independent_contract_cases.json")
                              .read_text(encoding="utf-8"))

    def test_exact_283_baseline_ids_and_checksum_pointer(self):
        expected = {
            *(f"LBT-FR-{i:03}" for i in range(1, 210)),
            *(f"LBT-NFR-{i:03}" for i in range(1, 75)),
        }
        ids = [r["Requirement_ID"] for r in self.rows]
        self.assertEqual(len(ids), 283)
        self.assertEqual(len(set(ids)), 283)
        self.assertEqual(set(ids), expected)
        self.assertEqual({r["Control_CSV_SHA256"] for r in self.rows},
                         {BASELINE_SHA})

    def test_no_requirements_falsely_marked_verified(self):
        self.assertEqual({row["Verification_State"] for row in self.rows},
                         {"NOT_VERIFIED"})
        self.assertFalse(any(row["Verification_Evidence"].strip()
                             for row in self.rows))

    def test_mapped_requirements_have_checkpoints_and_cts(self):
        tests = {x["test_id"] for x in self.spec["cases"]}
        for r in self.rows:
            self.assertIn(r["Trace_Scope"], SCOPES)
            if r["Trace_Scope"] != "UNASSESSED_FOR_G5_04":
                self.assertTrue(r["Assigned_Checkpoint"])
                self.assertTrue(r["CP02_Test_Spec_IDs"])
                self.assertTrue(set(r["CP02_Test_Spec_IDs"].split(";")) <= tests)
            else:
                self.assertFalse(r["CP02_Test_Spec_IDs"])

    def test_count_unassessed_explicitly_not_categorized_as_pass(self):
        from collections import Counter
        counts = Counter(r["Trace_Scope"] for r in self.rows)
        self.assertEqual(dict(counts), {
            "DIRECT": 33, "BOUNDARY": 11,
            "DOWNSTREAM": 6, "UNASSESSED_FOR_G5_04": 233,
        })

    def test_spec_has_exact_all_eleven_cases_and_approved_decisions(self):
        self.assertEqual(
            {x["test_id"] for x in self.spec["cases"]},
            {f"CT-{i:02}" for i in range(1, 12)})
        self.assertEqual(self.spec["baseline_sha256"], BASELINE_SHA)
        self.assertEqual(self.spec["approved_owner_decisions"],
                         ["D-01", "D-02", "D-03", "D-04", "D-05"])
        self.assertEqual(self.spec["status_schema_version"], "1.0")
        self.assertEqual(self.spec["canonical_schema_version"], "1.0.0")
        all_cases = [c for test in self.spec["cases"] for c in test["cases"]]
        self.assertEqual(len(all_cases), 39)
        self.assertEqual(len({c["case_id"] for c in all_cases}), 39)
        self.assertEqual({c["execution_state"] for c in all_cases},
                         {"NOT_EXECUTED"})
        self.assertGreaterEqual(
            sum(c["kind"] == "NEGATIVE" for c in all_cases), 18)
        self.assertTrue(all(t["requirement_ids"] and t["contract_assertion"]
                            for t in self.spec["cases"]))

    def test_reference_41_pairs_independent_from_production_registry(self):
        keys = {(x["Domain"], x["Status"], x["Reason_Code"])
                for x in read_csv("status_pair_keys_rev0_2.csv")}
        self.assertEqual(len(keys), 41)
        self.assertEqual(keys, STATUS_PAIRS)
        self.assertIn(("publication", "BLOCKED",
                       "UNCLASSIFIED_PUBLIC_FIELD"), keys)
        self.assertNotIn(("acquisition", "BLOCKED",
                          "UNCLASSIFIED_PUBLIC_FIELD"), keys)

    def test_reference_exact_14_fields_and_separate_versions(self):
        fields = [x["Field"] for x in
                  read_csv("status_envelope_fields_rev0_1.csv")]
        self.assertEqual(len(fields), 14)
        self.assertEqual(len(set(fields)), 14)
        self.assertEqual(tuple(fields), STATUS_FIELDS)
        self.assertEqual(STATUS_SCHEMA_VERSION, "1.0")
        self.assertEqual(CANONICAL_SCHEMA_VERSION, "1.0.0")

    @unittest.expectedFailure
    def test_known_f01_no_parser_cannot_imply_parse_failed(self):
        """KNOWN FAIL F-01, CT-02-N1: CP-03 must correct then remove xfail."""
        receipt = {"outcome": "CAPTURED", "reason": "BYTES_PRESERVED"}
        status, reason = _status_for(receipt, [object()])
        self.assertNotEqual((status, reason), ("PARTIAL", "PARSE_FAILED"))


if __name__ == "__main__":
    unittest.main()
