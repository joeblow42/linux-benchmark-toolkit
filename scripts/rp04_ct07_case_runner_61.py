#!/usr/bin/env python3
"""CT-07 bounded candidate per-case CI recording; no formal acceptance."""
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
"test_61_01_CT_07_P1_semantic_value_cites_two_originals":"CT-07-P1",
"test_61_02_CT_07_P2_identical_bytes_distinct_attempt_ids":"CT-07-P2",
"test_61_03_CT_07_N1_stale_or_missing_provenance_rejected":"CT-07-N1",
"test_61_04_CT_07_N2_accidental_corrupt_read_fails_digest":"CT-07-N2",
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
    def addSubTest(self,t,sub,e):
        super().addSubTest(t,sub,e)
        if e is not None:self.states[t._testMethodName]="FAIL"
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    spec=importlib.util.spec_from_file_location("rp04_ct07_61",
        ROOT/"tests/test_g5_cp03_rp04_ct07_61.py")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorder).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(mod.RP04CT07Candidate61))
    cases=[{"case_id":v,"method":k,
            "development_check_state":result.states.get(k,"NOT_EXECUTED"),
            "formal_cp02_execution_state":"NOT_EXECUTED",
            "formal_cp02_acceptance":False,"independent_review_state":"NOT_REVIEWED"}
           for k,v in METHODS.items()]
    ok=(result.wasSuccessful() and result.testsRun==4 and
        all(x["development_check_state"]=="PASS" for x in cases))
    payload={"record_type":"LBT_RP04_INCREMENT61_CT07_SOURCE_PROVENANCE_CANDIDATE",
      "scope":"OFFLINE_ORIGINALS_READ_ONLY_FAULT_INJECTION",
      "candidate_result":"PASS" if ok else "FAIL",
      "development_checks_executed":result.testsRun,
      "development_checks_passed":sum(x["development_check_state"]=="PASS" for x in cases),
      "original_evidence_modified":False,"host_source_acquisition":False,
      "original_cp02_formally_executed":0,"original_cp02_formally_accepted":0,
      "cases":cases}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(payload,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("CT-07 candidate evidence:",args.output)
    return 0 if ok else 1
if __name__=="__main__":sys.exit(main())
