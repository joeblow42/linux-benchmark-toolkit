#!/usr/bin/env python3
"""Emit machine-readable CT-03 exact-case development results in GitHub CI.

A CI development PASS is not independent original CP-02 execution/acceptance.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
METHODS = {
    "test_57_01_CT_03_P1_real_invocation_error_and_lossless_fallback": "CT-03-P1",
    "test_57_02_CT_03_N1_never_invoked_must_not_claim_parser_failure": "CT-03-N1",
    "test_57_03_CT_03_N2_missing_original_must_invalidate_parser_status": "CT-03-N2",
}

class Result(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.states={}
    def addSuccess(self,t):
        super().addSuccess(t);self.states[t._testMethodName]="PASS"
    def addFailure(self,t,e):
        super().addFailure(t,e);self.states[t._testMethodName]="FAIL"
    def addError(self,t,e):
        super().addError(t,e);self.states[t._testMethodName]="ERROR"
    def addSkip(self,t,reason):
        super().addSkip(t,reason);self.states[t._testMethodName]="SKIP"
    def addSubTest(self,t,sub,e):
        super().addSubTest(t,sub,e)
        if e is not None:self.states[t._testMethodName]="FAIL"

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    opts=p.parse_args()
    source=ROOT/"tests/test_g5_cp03_rp04_ct03_57.py"
    spec=importlib.util.spec_from_file_location("rp04_ct03_candidate_57",source)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(module.RP04CT03Candidate57)
    outcome=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    cases=[
        {"case_id":case,"method":method,
         "development_check_state":outcome.states.get(method,"NOT_EXECUTED"),
         "formal_cp02_execution_state":"NOT_EXECUTED",
         "formal_cp02_acceptance":False,
         "independent_review_state":"NOT_REVIEWED"}
        for method,case in METHODS.items()
    ]
    passed=outcome.wasSuccessful() and outcome.testsRun==3 and all(
        c["development_check_state"]=="PASS" for c in cases)
    data={
        "record_type":"LBT_RP04_INCREMENT57_CT03_CANDIDATE_CASE_EVIDENCE",
        "governance":"AI-Assisted Software Engineering Governance Standard v1.0",
        "case_authority":"verification/g5_04/cp02_independent_contract_cases.json",
        "scope":"BOUNDED_OFFLINE_CANDIDATE_NOT_FORMAL_CP02_OR_FAT",
        "candidate_result":"PASS" if passed else "FAIL",
        "development_checks_executed":outcome.testsRun,
        "development_checks_passed":sum(c["development_check_state"]=="PASS" for c in cases),
        "original_cp02_cases_formally_executed":0,
        "original_cp02_cases_formally_accepted":0,
        "tests_use_actual_host_sources":False,
        "original_evidence_modified":False,
        "cases":cases,
    }
    opts.output.parent.mkdir(parents=True,exist_ok=True)
    opts.output.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("CT-03 candidate evidence:",opts.output)
    return 0 if passed else 1

if __name__=="__main__":
    sys.exit(main())
