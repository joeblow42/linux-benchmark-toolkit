#!/usr/bin/env python3
"""CT-11-N1 per-case candidate evidence; not original CP-02 acceptance."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
METHODS = (
    "test_65_01_CT_11_N1_actual_canonical_private_replay_no_acquisition",
    "test_65_02_CT_11_N1_injected_duplicate_source_is_detected",
)


class Recorder(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.states = {}

    def addSuccess(self, test):
        super().addSuccess(test)
        self.states[test._testMethodName] = "PASS"

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.states[test._testMethodName] = "FAIL"

    def addError(self, test, err):
        super().addError(test, err)
        self.states[test._testMethodName] = "ERROR"

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.states[test._testMethodName] = "SKIP"

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.states[test._testMethodName] = "FAIL"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    output = parser.parse_args().output
    spec = importlib.util.spec_from_file_location(
        "rp04_ct11_n1_65", ROOT / "tests/test_g5_cp03_rp04_ct11_n1_65.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        module.CT11N1Candidate65)
    result = unittest.TextTestRunner(
        verbosity=2, resultclass=Recorder).run(suite)
    checks = [
        {"method": method, "development_check_state":
         result.states.get(method, "NOT_EXECUTED")}
        for method in METHODS
    ]
    good = result.wasSuccessful() and result.testsRun == 2 and all(
        x["development_check_state"] == "PASS" for x in checks)
    data = {
        "record_type": "LBT_RP04_INCREMENT65_CT11_N1_OFFLINE_CANDIDATE",
        "case_id": "CT-11-N1",
        "candidate_result": "PASS" if good else "FAIL",
        "development_checks_executed": result.testsRun,
        "development_checks_passed": sum(
            x["development_check_state"] == "PASS" for x in checks),
        "checks": checks,
        "original_cp02_executed": 0,
        "original_cp02_accepted": 0,
        "formal_cp02_execution_state": "NOT_EXECUTED",
        "independent_review_state": "NOT_REVIEWED",
        "ct11_p1": "OWNER_GATED_PHYSICAL_HOST_NOT_EXECUTED",
        "ct11_n2": "G5_06_DOWNSTREAM_NOT_EXECUTED",
        "ct11_n3": "TUI_DOWNSTREAM_NOT_EXECUTED",
        "production_runtime_guard_added": False,
        "production_code_modified": False,
        "originals_modified": False,
        "physical_host": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    print("CT-11-N1 candidate evidence:", output)
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
