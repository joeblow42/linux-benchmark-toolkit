#!/usr/bin/env python3
"""Run CT-01 bounded candidate case tests and retain factual CI JSON.

A PASS here means development check PASS only: none of the 39 original CP-02
cases is independently accepted, and no FAT execution/acceptance is claimed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tests/test_g5_cp03_rp04_ct01_55.py"
CASE_METHODS = {
    "test_55_01_CT_01_P1_pinned_41_pair_acceptance": "CT-01-P1",
    "test_55_02_CT_01_N1_cross_domain_pair_is_rejected": "CT-01-N1",
    "test_55_03_CT_01_N2_unsupported_reason_is_rejected": "CT-01-N2",
}

class Recorder(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = {}
    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes[test._testMethodName] = "PASS"
    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes[test._testMethodName] = "FAIL"
    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes[test._testMethodName] = "ERROR"
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes[test._testMethodName] = "SKIP"
    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.outcomes[test._testMethodName] = "FAIL"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    spec = importlib.util.spec_from_file_location("rp04_ct01_55", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.RP04CT01Candidate55)
    result = unittest.TextTestRunner(verbosity=2, resultclass=Recorder).run(suite)
    cases = []
    for method, case in CASE_METHODS.items():
        cases.append({
            "case_id": case,
            "development_check_state": result.outcomes.get(method, "NOT_EXECUTED"),
            "method": method,
            "formal_cp02_execution_state": "NOT_EXECUTED",
            "formal_cp02_acceptance": False,
            "independent_reviewer_state": "NOT_REVIEWED",
        })
    ok = (result.wasSuccessful() and result.testsRun == len(CASE_METHODS)
          and all(x["development_check_state"] == "PASS" for x in cases))
    payload = {
        "record_type": "LBT_RP04_INCREMENT55_CT01_DEVELOPMENT_CASE_EVIDENCE",
        "governance": "AI-Assisted Software Engineering Governance Standard v1.0",
        "authority": "verification/g5_04/cp02_independent_contract_cases.json",
        "oracle": "verification/g5_04/status_pair_keys_rev0_2.csv",
        "oracle_pinned_git_blob": module.PINNED_AUTHORITY_GIT_BLOB,
        "scope": "BOUNDED_OFFLINE_CANDIDATE_NOT_FORMAL_CP02_OR_FAT",
        "candidate_execution_result": "PASS" if ok else "FAIL",
        "development_checks_executed": result.testsRun,
        "development_checks_passed": sum(x["development_check_state"] == "PASS" for x in cases),
        "all_original_cp02_cases_formally_accepted": 0,
        "all_original_cp02_cases_formally_executed": 0,
        "cases": cases,
        "physical_host_test": False,
        "production_code_modified": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("RP-04 CT-01 candidate evidence:", args.output)
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
