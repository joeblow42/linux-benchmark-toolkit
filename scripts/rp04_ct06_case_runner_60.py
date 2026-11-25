#!/usr/bin/env python3
"""CT-06 original-case development evidence, never independent CP-02 acceptance."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
METHODS={
"test_60_01_CT_06_P1_actual_ci_source_utc_and_monotonic":"CT-06-P1",
"test_60_02_CT_06_P2_denied_attempt_has_nullable_execution_clock":"CT-06-P2",
"test_60_03_CT_06_N1_actual_recorded_clock_cannot_be_dropped":"CT-06-N1",
"test_60_04_CT_06_N2_reversed_utc_event_is_rejected":"CT-06-N2",
}
class Recorder(unittest.TextTestResult):
    def __init__(self,*a,**kw):super().__init__(*a,**kw);self.states={}
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
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    sp=importlib.util.spec_from_file_location("rp04_ct06_60",ROOT/"tests/test_g5_cp03_rp04_ct06_60.py")
    mod=importlib.util.module_from_spec(sp);sp.loader.exec_module(mod)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorder).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(mod.RP04CT06Candidate60))
    cases=[dict(case_id=v,method=k,
                development_check_state=result.states.get(k,"NOT_EXECUTED"),
                formal_cp02_execution_state="NOT_EXECUTED",
                formal_cp02_acceptance=False,independent_review="NOT_REVIEWED")
           for k,v in METHODS.items()]
    passed=(result.wasSuccessful() and result.testsRun==4 and
            all(x["development_check_state"]=="PASS" for x in cases))
    data={"record_type":"LBT_RP04_INCREMENT60_CT06_CANDIDATE_TIMING_EVIDENCE",
          "scope":"ACTUAL_CI_HOST_D0_TIMING_PLUS_OFFLINE_NEGATIVES",
          "candidate_result":"PASS" if passed else "FAIL",
          "development_checks_executed":result.testsRun,
          "development_checks_passed":sum(x["development_check_state"]=="PASS" for x in cases),
          "real_linux_ci_host_timing":mod.RP04CT06Candidate60.live_witness,
          "physical_bodhi_host_used":False,
          "formal_cp02_executed":0,"formal_cp02_accepted":0,"cases":cases}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("CT-06 candidate evidence:",args.output)
    return 0 if passed else 1
if __name__=="__main__":sys.exit(main())
