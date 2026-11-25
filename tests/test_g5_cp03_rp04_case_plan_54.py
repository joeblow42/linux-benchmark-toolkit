"""Increment 54: audit the original 39-case RP-04 acceptance preparation only.

A passing test validates this planning matrix, NEVER any CP-02 case or FAT.
No host access, source commands, privileges, report publication or benchmark.
"""
import csv
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "verification/g5_04/cp02_independent_contract_cases.json"
METHOD = ROOT / "verification/fat/altb_cp02_39case_method_review_20261116.csv"
OWNER = ROOT / "verification/fat/altb_owner_approval_rev02_20261116.json"
PLAN = ROOT / "verification/g5_04/rp04_increment54_39case_evidence_plan_20261117.json"

class RP04CasePlan54(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads(SPEC.read_text(encoding="utf-8"))
        cls.plan = json.loads(PLAN.read_text(encoding="utf-8"))
        cls.owner = json.loads(OWNER.read_text(encoding="utf-8"))
        with METHOD.open(encoding="utf-8", newline="") as fp:
            cls.method = {row["Case_ID"]: row for row in csv.DictReader(fp)}

    def test_54_01_exact_39_original_case_ids_and_requirements(self):
        expected = {case["case_id"]: (group, case)
                    for group in self.spec["cases"] for case in group["cases"]}
        actual = self.plan["cases"]
        self.assertEqual(len(expected), 39)
        self.assertEqual(len(actual), 39)
        self.assertEqual(set(expected), {c["case_id"] for c in actual})
        for item in actual:
            group, source = expected[item["case_id"]]
            self.assertEqual(item["contract_group"], group["test_id"])
            self.assertEqual(item["kind"], source["kind"])
            self.assertEqual(item["requirement_ids"], group["requirement_ids"])
            self.assertEqual(item["original_input_condition"], source["input_condition"])
            self.assertEqual(item["unchanged_expected_result"], source["expected_result"])
            self.assertEqual(self.method[item["case_id"]]["Expected_Result"], source["expected_result"])

    def test_54_02_only_approved_ct07_n1_method_changes(self):
        approvals = {d["decision_id"]: d["disposition"] for d in self.owner["owner_decisions"]}
        self.assertEqual(approvals["ALT_B_REV02_ROADMAP"], "APPROVED")
        self.assertEqual(approvals["CP02_CT07_N1_TEST_INPUT"], "APPROVED")
        changed = [c for c in self.plan["cases"]
                   if c["approved_execution_input_condition"] != c["original_input_condition"]]
        self.assertEqual([x["case_id"] for x in changed], ["CT-07-N1"])
        self.assertEqual(self.method["CT-07-N1"]["Alternative_B_Method_Disposition"],
                         "REPLACE_WITH_ORDINARY_FAILURE")
        self.assertIn("stale", changed[0]["approved_execution_input_condition"].lower())
        self.assertIn("wrong-run", changed[0]["approved_execution_input_condition"].lower())
        for case in self.plan["cases"]:
            self.assertEqual(case["unchanged_expected_result"],
                             self.method[case["case_id"]]["Expected_Result"])

    def test_54_03_no_claim_of_execution_or_acceptance(self):
        self.assertIn("NO_CP02_EXECUTION_NO_FAT_ACCEPTANCE", self.plan["scope"])
        self.assertEqual(self.plan["conservative_accounting"]["formal_accepted"], 0)
        self.assertEqual(self.plan["conservative_accounting"]["formal_executed"], 0)
        self.assertEqual(self.plan["conservative_accounting"]["physical_host_runs_authorized"], 0)
        self.assertEqual(self.plan["conservative_accounting"]["source_commands_changed"], 0)
        self.assertEqual(self.plan["conservative_accounting"]["protected_schema_or_status_pairs_changed"], 0)
        for case in self.plan["cases"]:
            self.assertEqual(case["formal_execution_state"], "NOT_EXECUTED")
            self.assertFalse(case["formal_acceptance"])
            self.assertTrue(case["candidate_support_only"])
            self.assertFalse(case["authorized_for_physical_host_execution"])
            self.assertEqual(case["independent_review_state"], "NOT_REVIEWED")
            self.assertTrue(case["remaining_fresh_evidence"])

    def test_54_04_candidate_pointers_exist_and_downstream_stays_gated(self):
        allowed = {"OFFLINE_FIXTURE", "CONTROLLED_BOUNDED_RUNTIME",
                   "LINUX_CI_UNPRIVILEGED", "BODHI7_PRE_FAT_READ_ONLY",
                   "G5_06_DOWNSTREAM", "TUI_DOWNSTREAM"}
        downstream = {"CT-08-N2", "CT-11-N2", "CT-11-N3"}
        for case in self.plan["cases"]:
            self.assertIn(case["proposal_execution_context"], allowed)
            self.assertEqual(case["case_disposition"] == "DOWNSTREAM_NOT_EXECUTED",
                             case["case_id"] in downstream)
            self.assertEqual(bool(case["candidate_related_test_files"]),
                             case["case_id"] not in downstream)
            for relative in case["candidate_related_test_files"]:
                self.assertTrue(relative.startswith("tests/"))
                self.assertTrue((ROOT / relative).is_file(), relative)
        host = [c for c in self.plan["cases"]
                if c["proposal_execution_context"] == "BODHI7_PRE_FAT_READ_ONLY"]
        self.assertEqual([c["case_id"] for c in host], ["CT-11-P1"])
        self.assertEqual(host[0]["owner_gate"], "OWNER_READ_ONLY_HOST_PLAN_APPROVAL_REQUIRED")

    def test_54_05_method_overlay_is_entirely_nonaccepting(self):
        self.assertEqual(len(self.method), 39)
        self.assertEqual({c["Source_Spec_Execution_State"] for c in self.method.values()},
                         {"NOT_EXECUTED"})
        self.assertEqual({c["Approved_For_Acceptance"] for c in self.method.values()},
                         {"NO"})

if __name__ == "__main__":
    unittest.main()
