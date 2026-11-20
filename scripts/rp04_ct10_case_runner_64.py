#!/usr/bin/env python3
"""CT-10 per-case development checks, not independent CP-02 case acceptance."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
METHODS={
"test_64_01_CT_10_P1_manifest_last_and_independent_counts":"CT-10-P1",
"test_64_02_CT_10_N1_manifest_persist_failure_does_not_validate":"CT-10-N1",
"test_64_03_CT_10_N2_ordinary_bad_reads_or_counts_fail_validation":"CT-10-N2",
"test_64_04_CT_10_N3_exclusive_duplicate_session_and_receipt":"CT-10-N3",
}

class Recorder(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.states={}
    def addSuccess(self,t):
        super().addSuccess(t)
        self.states[t._testMethodName]="PASS"
    def addFailure(self,t,e):
        super().addFailure(t,e)
        self.states[t._testMethodName]="FAIL"
    def addError(self,t,e):
        super().addError(t,e)
        self.states[t._testMethodName]="ERROR"
    def addSkip(self,t,reason):
        super().addSkip(t,reason)
        self.states[t._testMethodName]="SKIP"
    def addSubTest(self,t,sub,error):
        super().addSubTest(t,sub,error)
        if error is not None:
            self.states[t._testMethodName]="FAIL"

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    sp=importlib.util.spec_from_file_location(
        "rp04_ct10_64",ROOT/"tests/test_g5_cp03_rp04_ct10_64.py")
    module=importlib.util.module_from_spec(sp)
    sp.loader.exec_module(module)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(
        module.RP04CT10Candidate64)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorder).run(suite)
    cases=[{"case_id":value,"method":key,
            "development_check_state":result.states.get(key,"NOT_EXECUTED"),
            "formal_cp02_execution_state":"NOT_EXECUTED",
            "formal_cp02_accepted":False,
            "independent_review_state":"NOT_REVIEWED"}
           for key,value in METHODS.items()]
    ok=(result.wasSuccessful() and result.testsRun==4 and
        all(case["development_check_state"]=="PASS" for case in cases))
    result_json={
        "record_type":"LBT_RP04_INCREMENT64_CT10_PRIVATE_COMMIT_CANDIDATE",
        "scope":"BOUNDED_OFFLINE_REAL_WRITES_ORDINARY_READ_FAULTS",
        "candidate_result":"PASS" if ok else "FAIL",
        "development_checks_executed":result.testsRun,
        "development_checks_passed":sum(
            x["development_check_state"]=="PASS" for x in cases),
        "formal_cp02_executed":0,"formal_cp02_accepted":0,
        "originals_modified":False,
        "physical_host":False,"production_code_modified":False,
        "cases":cases,
    }
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result_json,indent=2,sort_keys=True)+"\n",
                           encoding="utf-8")
    print("CT-10 candidate evidence:",args.output)
    return 0 if ok else 1
if __name__=="__main__":
    sys.exit(main())
