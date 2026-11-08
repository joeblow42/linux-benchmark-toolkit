"""Review-only regression guards against CP02/CP03 known contract gaps.

No production code, host source execution, package query or permissions.
Expected failures document open governed contract gaps; they are NOT passes
or acceptance of any original CT-01..CT-11 39-case specifications.
"""
import csv
from dataclasses import fields
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from lbt_g5.additional import AdditionalOutcome
from lbt_g5.canonical_session import build_canonical
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.engine import EngineRun, CollectorRun
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

ROOT=Path(__file__).resolve().parents[1]
CONTROL=ROOT/"verification"/"g5_04"
RUN="run-2026305120000"

def make_sealed_run(*,source_id="SRC-28",outcome="CAPTURED",
                    reason="BYTES_PRESERVED",capture_limited=False,
                    timed_out=False,elapsed_seconds=.50):
    tmp=tempfile.TemporaryDirectory()
    folder=Path(tmp.name)/RUN
    folder.mkdir(mode=0o700)
    policy={p.source_id:p for p in initial_source_policies()}[source_id]
    writer=EvidenceWriter(str(folder),RUN)
    if source_id=="SRC-28":
        raw=b"dpkg\t1.0\n"
        artifact_name="call0001-stdout"
        paths=("installed-packages:stdout",)
        invocation="OFFLINE_METADATA"
        cid="COL-SOFTCODEC"
    else:
        raw=b"MemTotal: 1024 kB\n"
        artifact_name="item0001"
        paths=()
        invocation="PROC_MEMINFO"
        cid="COL-MEM"
    artifact=writer.seal_chunks(policy,"01",artifact_name,(raw,)).receipt
    receipt=build_attempt(RUN,source_id,"01","ALLOW",outcome,reason,
                          evidence=(artifact,),bytes_count=artifact.byte_count,
                          invocation=invocation,source_paths=paths,
                          elapsed_seconds=elapsed_seconds,
                          timed_out=timed_out,capture_limited=capture_limited)
    loc=commit_attempt(str(folder),receipt)
    entry=SimpleNamespace(receipt_private_path=loc,
                          outcome=SimpleNamespace(artifacts=(artifact,)))
    run=EngineRun(RUN,(CollectorRun(cid,(entry,)),))
    return tmp,folder,run

class CP02ReconciliationReviewGuards(unittest.TestCase):
    def test_original_39_case_spec_unexecuted_and_reconciliation_complete(self):
        spec=json.loads((CONTROL/"cp02_independent_contract_cases.json").read_text())
        with (CONTROL/"cp02_39case_coverage_review_25.csv").open(newline="") as f:
            audit=list(csv.DictReader(f))
        source=[x for group in spec["cases"] for x in group["cases"]]
        self.assertEqual(len(source),39)
        self.assertEqual(len(audit),39)
        self.assertEqual({x["case_id"] for x in source},
                         {x["Case_ID"] for x in audit})
        self.assertEqual({x["Source_Spec_Execution_State"] for x in audit},
                         {"NOT_EXECUTED"})
        self.assertEqual({x["Approved_For_Acceptance"] for x in audit},{"NO"})
        self.assertEqual({x["Reviewer_Independence"] for x in audit},
                         {"NOT_INDEPENDENT_AI_AUTHOR"})
        for case in source:
            row=next(x for x in audit if x["Case_ID"]==case["case_id"])
            self.assertEqual(row["Input_Condition"],case["input_condition"])
            self.assertEqual(row["Expected_Result"],case["expected_result"])

    @unittest.expectedFailure
    def test_known_gap_f02_executed_source_must_have_measured_status_timing(self):
        tmp,folder,run=make_sealed_run(source_id="SRC-28")
        self.addCleanup(tmp.cleanup)
        build_canonical(folder,run)
        data=json.loads((folder/"private/status_records.json").read_text())
        row=next(x for x in data["status_records"] if x["subject_id"]=="SRC-28")
        self.assertIsNotNone(row["started_utc"])
        self.assertIsNotNone(row["completed_utc"])
        self.assertEqual(row["elapsed_ms"],500)

    @unittest.expectedFailure
    def test_known_gap_f04_time_limit_must_not_emit_byte_ceiling(self):
        tmp,folder,run=make_sealed_run(outcome="PARTIAL",
             reason="TIME_BUDGET_EXCEEDED",capture_limited=True,timed_out=True)
        self.addCleanup(tmp.cleanup)
        build_canonical(folder,run)
        system=json.loads((folder/"private/system.json").read_text())
        limit=system["capture_limits"][0]
        self.assertEqual(limit["unit"],"seconds")
        self.assertEqual(limit["threshold"],20)

    @unittest.expectedFailure
    def test_known_gap_f06_exact_owner_approved_d02_entities_and_manifest(self):
        tmp,folder,run=make_sealed_run(source_id="SRC-08")
        self.addCleanup(tmp.cleanup)
        build_canonical(folder,run)
        system=json.loads((folder/"private/system.json").read_text())
        approved={"schema_version","run_id","header","observations",
                  "capture_limits","limitations"}
        self.assertEqual(set(system),approved)
        manifest=json.loads((folder/"private/session_manifest.json").read_text())
        self.assertIn("minimum_usable",manifest)
        self.assertIn("source_receipts",manifest)
        self.assertIn("counts",manifest)

    @unittest.expectedFailure
    def test_src28_operational_provenance_gap_has_no_argv_or_returncode(self):
        recorded_fields={field.name for field in fields(AdditionalOutcome)}
        self.assertIn("argv",recorded_fields)
        self.assertIn("exit_code",recorded_fields)

if __name__=="__main__":
    unittest.main()
