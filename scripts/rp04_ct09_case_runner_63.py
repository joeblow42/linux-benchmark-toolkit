#!/usr/bin/env python3
"""Emit per-original-case development evidence, not CP-02 acceptance."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
METHODS={
"test_63_01_CT_09_P1_unknown_attribute_typed_or_byte_ref":"CT-09-P1",
"test_63_02_CT_09_P2_known_semantics_have_type_unit_and_provenance":"CT-09-P2",
"test_63_03_CT_09_N1_undeclared_canonical_fields_are_rejected":"CT-09-N1",
"test_63_04_CT_09_N2_silent_drop_of_unknown_semantic_is_detected":"CT-09-N2",
}
class Recorder(unittest.TextTestResult):
    def __init__(self,*a,**k):super().__init__(*a,**k);self.states={}
    def addSuccess(self,t):super().addSuccess(t);self.states[t._testMethodName]="PASS"
    def addFailure(self,t,e):super().addFailure(t,e);self.states[t._testMethodName]="FAIL"
    def addError(self,t,e):super().addError(t,e);self.states[t._testMethodName]="ERROR"
    def addSkip(self,t,r):super().addSkip(t,r);self.states[t._testMethodName]="SKIP"
    def addSubTest(self,t,sub,e):
        super().addSubTest(t,sub,e)
        if e is not None:self.states[t._testMethodName]="FAIL"
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    spec=importlib.util.spec_from_file_location("rp04_ct09_63",ROOT/"tests/test_g5_cp03_rp04_ct09_63.py")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorder).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(mod.RP04CT09Candidate63))
    cases=[dict(case_id=v,method=k,
        development_check_state=result.states.get(k,"NOT_EXECUTED"),
        formal_cp02_execution_state="NOT_EXECUTED",formal_cp02_acceptance=False,
        independent_review_state="NOT_REVIEWED") for k,v in METHODS.items()]
    passed=(result.wasSuccessful() and result.testsRun==4 and
            all(x["development_check_state"]=="PASS" for x in cases))
    report={"record_type":"LBT_RP04_INCREMENT63_CT09_LOSSLESS_CANDIDATE_CASE_EVIDENCE",
            "scope":"OFFLINE_SEALED_SOURCE_AND_READONLY_CONSUMER_NEGATIVES",
            "result":"PASS" if passed else "FAIL",
            "candidate_tests_executed":result.testsRun,
            "candidate_tests_passed":sum(x["development_check_state"]=="PASS" for x in cases),
            "formal_cp02_executed":0,"formal_cp02_accepted":0,
            "original_files_modified":False,"production_changed":False,
            "physical_host_test":False,"cases":cases}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("CT-09 candidate evidence:",args.output)
    return 0 if passed else 1
if __name__=="__main__":sys.exit(main())
