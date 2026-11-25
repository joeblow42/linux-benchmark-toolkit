#!/usr/bin/env python3
"""CT-05 candidate CI: per-case outcomes and factual measured limit witnesses."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
for path in (ROOT,ROOT/"tests"):
    if str(path) not in sys.path:sys.path.insert(0,str(path))
METHODS={
"test_59_01_CT_05_P1_real_measured_source_elapsed_seconds":"CT-05-P1",
"test_59_02_CT_05_P2_real_writer_byte_omission":"CT-05-P2",
"test_59_03_CT_05_N1_time_event_cannot_be_byte_limit":"CT-05-N1",
}
class Recorder(unittest.TextTestResult):
    def __init__(self,*a,**kw):super().__init__(*a,**kw);self.result_by_method={}
    def addSuccess(self,test):
        super().addSuccess(test);self.result_by_method[test._testMethodName]="PASS"
    def addFailure(self,test,err):
        super().addFailure(test,err);self.result_by_method[test._testMethodName]="FAIL"
    def addError(self,test,err):
        super().addError(test,err);self.result_by_method[test._testMethodName]="ERROR"
    def addSkip(self,test,reason):
        super().addSkip(test,reason);self.result_by_method[test._testMethodName]="SKIP"
    def addSubTest(self,test,sub,err):
        super().addSubTest(test,sub,err)
        if err is not None:self.result_by_method[test._testMethodName]="FAIL"

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location("rp04_ct05_59",
        ROOT/"tests/test_g5_cp03_rp04_ct05_59.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(module.RP04CT05Candidate59)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorder).run(suite)
    cases=[{"case_id":case,"method":method,
            "development_check_state":result.result_by_method.get(method,"NOT_EXECUTED"),
            "formal_cp02_execution_state":"NOT_EXECUTED",
            "formal_cp02_acceptance":False,"reviewer_state":"NOT_REVIEWED"}
           for method,case in METHODS.items()]
    good=(result.wasSuccessful() and result.testsRun==3 and
          all(case["development_check_state"]=="PASS" for case in cases))
    data={"record_type":"LBT_RP04_INCREMENT59_CT05_MEASURED_CANDIDATE_EVIDENCE",
          "scope":"BOUNDED_CI_RUNTIME_AND_TEMP_BYTES_NOT_PHYSICAL_FAT",
          "candidate_result":"PASS" if good else "FAIL",
          "executed":result.testsRun,"passed":sum(x["development_check_state"]=="PASS" for x in cases),
          "time_witness":module.RP04CT05Candidate59.wall_witness,
          "byte_witness":module.RP04CT05Candidate59.byte_witness,
          "source_commands_executed":False,"formally_executed":0,"formally_accepted":0,
          "cases":cases}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("CT-05 candidate evidence:",args.output)
    return 0 if good else 1
if __name__=="__main__":sys.exit(main())
