#!/usr/bin/env python3
"""CT-02 candidate evidence JSON from actual offline tests; never CP-02 acceptance."""
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
    "test_56_01_CT_02_P1_explicit_pending_private_diagnostic":"CT-02-P1",
    "test_56_02_CT_02_N1_no_unsubstantiated_parse_failure":"CT-02-N1",
    "test_56_03_CT_02_N2_no_unsupported_complete_status":"CT-02-N2",
}
class Record(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.states={}
    def addSuccess(self,t):
        super().addSuccess(t);self.states[t._testMethodName]="PASS"
    def addError(self,t,e):
        super().addError(t,e);self.states[t._testMethodName]="ERROR"
    def addFailure(self,t,e):
        super().addFailure(t,e);self.states[t._testMethodName]="FAIL"
    def addSkip(self,t,reason):
        super().addSkip(t,reason);self.states[t._testMethodName]="SKIP"
    def addSubTest(self,t,sub,e):
        super().addSubTest(t,sub,e)
        if e is not None:self.states[t._testMethodName]="FAIL"

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    opt=p.parse_args()
    spec=importlib.util.spec_from_file_location("rp04_ct02_candidate_56",
        ROOT/"tests/test_g5_cp03_rp04_ct02_56.py")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(mod.RP04CT02Candidate56)
    run=unittest.TextTestRunner(verbosity=2,resultclass=Record).run(suite)
    cases=[dict(case_id=case,method=method,
                development_check_state=run.states.get(method,"NOT_EXECUTED"),
                formal_cp02_execution_state="NOT_EXECUTED",
                formal_cp02_accepted=False,independent_reviewer="NOT_REVIEWED")
           for method,case in METHODS.items()]
    ok=(run.wasSuccessful() and run.testsRun==3 and
        all(c["development_check_state"]=="PASS" for c in cases))
    out={
        "record_type":"LBT_RP04_INCREMENT56_CT02_DEVELOPMENT_CASE_EVIDENCE",
        "scope":"PRIVATE_OFFLINE_NARROWED_A_NOT_FORMAL_CP02_OR_FAT",
        "candidate_execution_result":"PASS" if ok else "FAIL",
        "development_checks_executed":run.testsRun,
        "development_checks_passed":sum(c["development_check_state"]=="PASS" for c in cases),
        "cases":cases,"original_cp02_cases_accepted":0,
        "physical_host_test":False,"source_commands_changed":False,
        "canonical_schema_changed":False,"new_persistent_diagnostic_file":False}
    opt.output.parent.mkdir(parents=True,exist_ok=True)
    opt.output.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("RP-04 CT-02 candidate evidence:",opt.output)
    return 0 if ok else 1
if __name__=="__main__":
    sys.exit(main())
