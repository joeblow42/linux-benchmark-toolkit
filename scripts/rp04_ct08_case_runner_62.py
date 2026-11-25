#!/usr/bin/env python3
"""CT-08 P1/N1 offline candidate evidence; N2 is G5-06 downstream NOT RUN."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
METHODS={
"test_62_01_CT_08_P1_all_denied_unavailable_zero_originals":"CT-08-P1",
"test_62_02_CT_08_N1_false_complete_session_cannot_validate":"CT-08-N1",
}
class Recorder(unittest.TextTestResult):
    def __init__(self,*a,**kw):super().__init__(*a,**kw);self.states={}
    def addSuccess(self,t):
        super().addSuccess(t);self.states[t._testMethodName]="PASS"
    def addFailure(self,t,e):
        super().addFailure(t,e);self.states[t._testMethodName]="FAIL"
    def addError(self,t,e):
        super().addError(t,e);self.states[t._testMethodName]="ERROR"
    def addSkip(self,t,r):
        super().addSkip(t,r);self.states[t._testMethodName]="SKIP"
    def addSubTest(self,t,s,e):
        super().addSubTest(t,s,e)
        if e is not None:self.states[t._testMethodName]="FAIL"
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    spec=importlib.util.spec_from_file_location("rp04_ct08_62",ROOT/"tests/test_g5_cp03_rp04_ct08_62.py")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorder).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(mod.RP04CT08Candidate62))
    cases=[dict(case_id=case,method=method,
                development_check_state=result.states.get(method,"NOT_EXECUTED"),
                formal_cp02_execution_state="NOT_EXECUTED",
                formally_accepted=False,independent_review="NOT_REVIEWED")
           for method,case in METHODS.items()]
    cases.append({"case_id":"CT-08-N2",
                  "development_check_state":"DEFERRED_G5_06_DOWNSTREAM",
                  "formal_cp02_execution_state":"NOT_EXECUTED",
                  "formally_accepted":False,
                  "independent_review":"NOT_REVIEWED",
                  "reason":"Latest-session regeneration boundary requires actual G5-06 consumer"})
    passed=(result.wasSuccessful() and result.testsRun==2 and all(
        x["development_check_state"]=="PASS" for x in cases[:2]))
    out={"record_type":"LBT_RP04_INCREMENT62_CT08_OFFLINE_PARTIAL_CANDIDATE",
         "scope":"TWO_OFFLINE_CASES_ONLY_DOWNSTREAM_NOT_CLAIMED",
         "candidate_result":"PASS" if passed else "FAIL",
         "development_cases_executed":result.testsRun,
         "development_cases_passed":sum(x["development_check_state"]=="PASS" for x in cases),
         "downstream_cases_deferred":["CT-08-N2"],
         "formal_cp02_executed":0,"formal_cp02_accepted":0,
         "production_files_modified":False,"physical_host":False,"cases":cases}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(out,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("CT-08 candidate evidence:",args.output)
    return 0 if passed else 1
if __name__=="__main__":sys.exit(main())
