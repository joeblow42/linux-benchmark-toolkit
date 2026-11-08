"""CP03-26 owner Alternative A: sealed SRC28 source execution provenance.

The _resolve_executable and _capture_child functions are mocked. No dpkg,
subprocess, network, package database, root helper, or host source is accessed.
Frozen source-first review oracle is committed separately before implementation.
"""
import json, math, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from datetime import datetime
from lbt_g5.additional import _DPKG_ARGV
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.records import build_attempt
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest, initial_source_policies

RUN="run-2026305120000"
POL={p.source_id:p for p in initial_source_policies()}["SRC-28"]
RAW=b"dpkg\t1.21.22\n"
ARGV=("/usr/bin/dpkg-query",)+_DPKG_ARGV[1:]

class SRC28SourceFirstOperationalReceiptTests(unittest.TestCase):
    def source(self,*,exit_code=0,stderr=b"",stdout=RAW,tool="/usr/bin/dpkg-query",
               capture=None,disabled=False):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        folder=Path(td.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        request=SourceRequest(RUN,"SRC-28","OFFLINE_METADATA",operator_disabled=disabled)
        capture=capture if capture is not None else TransportCapture(
            stdout,stderr,exit_code,.075,False,False,0,0)
        calls=[]
        def worker(*args,**kwargs):
            calls.append(args)
            return capture
        with patch("lbt_g5.additional.decide_source",
                   return_value=SimpleNamespace(allowed=not disabled,reason="OPERATOR_EXCLUDED")):
            with patch("lbt_g5.additional._resolve_executable",return_value=tool) as resolve:
                with patch("lbt_g5.additional._capture_child",side_effect=worker) as execute:
                    rec=capture_and_record(request,"01",writer,ProbeSlots(),SourceCallBudget())
        receipt=json.loads((folder/rec.receipt_private_path).read_text())
        run=EngineRun(RUN,(CollectorRun("COL-SOFTCODEC",(rec,)),))
        return folder,run,rec,receipt,resolve.call_count,execute.call_count,calls

    def test_success_receipt_has_actual_fixed_executed_argv_exit_and_clock(self):
        folder,run,rec,receipt,resolves,executes,calls=self.source(stderr=b"warning\n")
        self.assertEqual((resolves,executes),(1,1))
        self.assertEqual(calls[0][0],ARGV)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.3")
        self.assertEqual(receipt["invocation"],"OFFLINE_METADATA")
        self.assertEqual(receipt["exit_code"],0)
        p=receipt["execution_provenance"]
        self.assertEqual(p["argv_executed"],list(ARGV))
        self.assertEqual(p["exit_code"],0)
        self.assertEqual(p["elapsed_seconds"],.075)
        start=datetime.fromisoformat(p["started_utc"].replace("Z","+00:00"))
        end=datetime.fromisoformat(p["completed_utc"].replace("Z","+00:00"))
        self.assertGreaterEqual(end,start)
        self.assertEqual(p,rec.outcome.execution_provenance)
        m=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),m)
        status=json.loads((folder/"private/status_records.json").read_text())
        row=next(x for x in status["status_records"] if x["subject_id"]=="SRC-28")
        self.assertEqual((row["status"],row["reason_code"]),("COMPLETE","OK"))

    def test_nonzero_source_exit_is_retained_without_completion(self):
        folder,run,rec,receipt,_,_,_=self.source(exit_code=2)
        self.assertEqual((rec.outcome.disposition,rec.outcome.reason),
                         ("PARTIAL","SOURCE_INCOMPLETE"))
        self.assertEqual((receipt["exit_code"],
                          receipt["execution_provenance"]["exit_code"]),(2,2))
        build_canonical(folder,run)
        rows=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        item=next(x for x in rows if x["subject_id"]=="SRC-28")
        self.assertEqual((item["status"],item["reason_code"]),("PARTIAL","SOURCE_INCOMPLETE"))
        self.assertIn("exit_code=2",item["detail"])

    def test_missing_executable_does_not_fabricate_execution(self):
        folder,run,rec,receipt,resolves,executes,_=self.source(tool=None)
        self.assertEqual((resolves,executes),(1,0))
        self.assertEqual(rec.outcome.disposition,"UNAVAILABLE")
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.1")
        self.assertNotIn("execution_provenance",receipt)
        self.assertIsNone(receipt["exit_code"])

    def test_denied_source_does_not_execute_or_claim_execution(self):
        folder,run,rec,receipt,resolves,executes,_=self.source(disabled=True)
        self.assertEqual((resolves,executes),(0,0))
        self.assertNotIn("execution_provenance",receipt)
        self.assertEqual(receipt["decision"],"DENY")

    def test_legacy_record_cannot_be_upgraded_to_complete_by_guessing(self):
        from lbt_g5.records import commit_attempt
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        folder=Path(td.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        artifact=writer.seal_chunks(POL,"01","call0001-stdout",(RAW,)).receipt
        record=build_attempt(RUN,"SRC-28","01","ALLOW","CAPTURED","BYTES_PRESERVED",
                             evidence=(artifact,),bytes_count=artifact.byte_count,
                             source_paths=("installed-packages:stdout",),
                             invocation="OFFLINE_METADATA")
        path=commit_attempt(str(folder),record)
        entry=SimpleNamespace(outcome=SimpleNamespace(artifacts=(artifact,)),receipt_private_path=path)
        run=EngineRun(RUN,(CollectorRun("COL-SOFTCODEC",(entry,)),))
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder,run)

    def test_receipt_forgery_with_original_untouched_fails_closed(self):
        mutations=(
          lambda p:p["execution_provenance"]["argv_executed"].__setitem__(0,"/usr/bin/apt"),
          lambda p:p["execution_provenance"]["argv_executed"].__setitem__(2,"-f=outside"),
          lambda p:p["execution_provenance"].__setitem__("exit_code",2),
          lambda p:p.__setitem__("exit_code",3),
          lambda p:p["execution_provenance"].__setitem__("started_utc","2026-11-08T12:00:00"),
          lambda p:p["execution_provenance"].__setitem__("completed_utc","2000-01-01T00:00:00Z"),
          lambda p:p["execution_provenance"].__setitem__("elapsed_seconds",-2),
          lambda p:p["execution_provenance"].__setitem__("elapsed_seconds",float("nan")),
          lambda p:p["execution_provenance"].__setitem__("argv_executed",["dpkg-query","-W"]),
          lambda p:p.__setitem__("schema_version","g5-02-attempt-0.1"),
          lambda p:p.pop("execution_provenance"),
          lambda p:p.__setitem__("target","/var/lib/dpkg/status"),
          lambda p:p.__setitem__("invocation","apt update"),
        )
        for mutate in mutations:
            with self.subTest(mutate=str(mutate)):
                folder,run,rec,receipt,_,_,_=self.source()
                mutate(receipt)
                (folder/rec.receipt_private_path).write_text(
                    json.dumps(receipt,allow_nan=True,sort_keys=True)+"\n")
                with self.assertRaises((CanonicalContractError,ValueError)):
                    build_canonical(folder,run)
                self.assertFalse((folder/"private/session_manifest.json").exists())

    def test_captured_with_no_stdout_must_not_be_complete(self):
        folder,run,rec,receipt,_,_,_=self.source(stdout=b"",stderr=b"warning\n")
        self.assertEqual(receipt["exit_code"],0)
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder,run)

    def test_approved_scope_rejects_cross_source_execution_witness(self):
        args=dict(
            run_id=RUN,source_id="SRC-15",attempt="01",decision="ALLOW",
            outcome="CAPTURED",reason="BYTES_PRESERVED",invocation="FS_STAT",
            execution_provenance={
                "argv_executed":list(ARGV),"exit_code":0,
                "started_utc":"2026-11-08T12:00:00.000Z",
                "completed_utc":"2026-11-08T12:00:00.075Z",
                "elapsed_seconds":.075,
            })
        with self.assertRaises(ValueError):
            build_attempt(**args)

if __name__=="__main__":
    unittest.main()
