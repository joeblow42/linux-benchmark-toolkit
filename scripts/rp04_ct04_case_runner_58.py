#!/usr/bin/env python3
"""CT-04 per-case CI outcome recording. Not formal CP-02/FAT acceptance."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
METHODS={
"test_58_01_CT_04_P1_unconsented_O1_is_unauthorized":"CT-04-P1",
"test_58_02_CT_04_P2_absent_executable_has_source_report":"CT-04-P2",
"test_58_03_CT_04_N1_unknown_transport_must_fail_closed":"CT-04-N1",
"test_58_04_CT_04_N2_unavailable_cannot_claim_success":"CT-04-N2",
}
class Recorder(unittest.TextTestResult):
    def __init__(self,*args,**kw):super().__init__(*args,**kw);self.outcomes={}
    def addSuccess(self,test):
        super().addSuccess(test);self.outcomes[test._testMethodName]="PASS"
    def addFailure(self,test,err):
        super().addFailure(test,err);self.outcomes[test._testMethodName]="FAIL"
    def addError(self,test,err):
        super().addError(test,err);self.outcomes[test._testMethodName]="ERROR"
    def addSkip(self,test,reason):
        super().addSkip(test,reason);self.outcomes[test._testMethodName]="SKIP"
    def addSubTest(self,test,sub,err):
        super().addSubTest(test,sub,err)
        if err is not None:self.outcomes[test._testMethodName]="FAIL"

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location("rp04_ct04_58",ROOT/"tests/test_g5_cp03_rp04_ct04_58.py")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(mod.RP04CT04Candidate58)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorder).run(suite)
    cases=[{"case_id":case,"test_method":method,
        "development_check_state":result.outcomes.get(method,"NOT_EXECUTED"),
        "formal_cp02_execution_state":"NOT_EXECUTED","formal_cp02_acceptance":False,
        "independent_review_state":"NOT_REVIEWED"}
        for method,case in METHODS.items()]
    passed=(result.wasSuccessful() and result.testsRun==4 and
            all(x["development_check_state"]=="PASS" for x in cases))
    report={"record_type":"LBT_RP04_INCREMENT58_CT04_CANDIDATE_EVIDENCE",
            "scope":"OFFLINE_RECEIPT_CANDIDATE_NOT_FORMAL_CP02_FAT",
            "candidate_result":"PASS" if passed else "FAIL",
            "development_checks_executed":result.testsRun,
            "development_checks_passed":sum(x["development_check_state"]=="PASS" for x in cases),
            "formal_cp02_cases_executed":0,"formal_cp02_cases_accepted":0,
            "tool_absence_fixture":"SRC-27 sealed NULL resolved_path, not live CI tool observation",
            "host_acquisition":False,"production_files_modified":False,"cases":cases}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("CT-04 candidate evidence:",args.output)
    return 0 if passed else 1
if __name__=="__main__":sys.exit(main())
