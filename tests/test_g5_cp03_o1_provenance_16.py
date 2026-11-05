"""CP03-16 source-first O1 provenance/exit-status oracles, no device actions.

Frozen oracle: verification/g5_04/cp03_o1_provenance_nonzero_oracle_16.json.
AI-authored fixtures are NOT independent human assurance.
"""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import _status_for, build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.receipt_dispatch import RecordedOutcome
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
INVPATH = "/sys/class/block/sda/size"
TARGET = "/dev/sda"
CMD = "smartctl -i -H /dev/sda"


class O1ApprovedOwnerOracles(unittest.TestCase):
    def receipt(self, **overrides):
        attrs = dict(outcome="PARTIAL",reason="ACQUISITION_ERROR",
                     authorization_class="O1",source_id="SRC-13",
                     decision="ALLOW",target=TARGET,exit_code=2,
                     capture_limited=False,timed_out=False)
        attrs.update(overrides)
        return attrs

    def test_o1_nonzero_only_with_verified_provenance(self):
        for state in ("OK", "FAILED", "NOT_RUN"):
            with self.subTest(parser_state=state):
                self.assertEqual(
                    _status_for(self.receipt(),[object()],parser_state=state,
                                o1_provenance_verified=True),
                    ("PARTIAL","SOURCE_INCOMPLETE"))
        for source in ("SRC-13","SRC-18","SRC-21"):
            with self.subTest(source=source):
                self.assertEqual(
                    _status_for(self.receipt(source_id=source),[object()],
                                o1_provenance_verified=True),
                    ("PARTIAL","SOURCE_INCOMPLETE"))

    def test_missing_provenance_and_invalid_exit_are_rejected(self):
        with self.assertRaises(CanonicalContractError):
            _status_for(self.receipt(),[object()])
        for code in (None,0,True,False,"2",2.5,65536,-65536):
            with self.subTest(code=code),self.assertRaises(CanonicalContractError):
                _status_for(self.receipt(exit_code=code),[object()],
                            o1_provenance_verified=True)
        with self.assertRaises(CanonicalContractError):
            _status_for(self.receipt(),[],o1_provenance_verified=True)

    def test_wrong_class_source_outcome_and_limited_priority(self):
        for data in (dict(authorization_class="D1"),
                     dict(authorization_class="D0"),
                     dict(source_id="SRC-11"),
                     dict(decision="DENY"),
                     dict(timed_out=True),
                     dict(outcome="CAPTURED"),
                     dict(reason="EXIT_NONZERO")):
            with self.subTest(data=data),self.assertRaises(CanonicalContractError):
                _status_for(self.receipt(**data),[object()],
                            o1_provenance_verified=True)
        self.assertEqual(
            _status_for(self.receipt(capture_limited=True),[object()]),
            ("PARTIAL","CAPTURE_LIMIT"))

    def inventory(self,folder,writer,*,path=INVPATH):
        pol={p.source_id:p for p in initial_source_policies()}["SRC-12"]
        artifact=writer.seal_chunks(pol,"01","item0001",(b"3907029168\\n",)).receipt
        self.assertIsNotNone(artifact)
        receipt=build_attempt(RUN,"SRC-12","01","ALLOW","CAPTURED",
                              "BYTES_PRESERVED",evidence=(artifact,),
                              bytes_count=artifact.byte_count,
                              source_paths=(path,))
        loc=commit_attempt(str(folder),receipt)
        return RecordedOutcome(
            SimpleNamespace(artifacts=(artifact,),disposition="CAPTURED",
                            source_paths=(path,)),loc),artifact

    def provenance(self,inventory,**overrides):
        record=dict(run_id=RUN,source_id="SRC-13",operation_id="DEVICE_HEALTH",
                    target=TARGET,consent_run_id=RUN,consent_source_id="SRC-13",
                    consent_operation_id="DEVICE_HEALTH",consent_target=TARGET,
                    consent_issued_utc="2026-11-01T12:00:00Z",
                    impact_acknowledged=True,
                    inventory_source_id="SRC-12",
                    inventory_source_path=INVPATH,
                    inventory_evidence_id=inventory.evidence_id,
                    approved_argv=["smartctl","-i","-H",TARGET])
        record.update(overrides)
        return record

    def canonical_fixture(self,*,o1_changes=None,provenance_changes=None,
                          include_inventory=True,wrong_memory_proof=False,
                          change_original=False,original_name="call0001-stdout",
                          inventory_path=INVPATH):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        folder=Path(self.tmp.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        inventory,inv_art=self.inventory(folder,writer,path=inventory_path)
        p13={p.source_id:p for p in initial_source_policies()}["SRC-13"]
        raw=b"SMART data available but exit bits are nonzero\\n"
        origin=writer.seal_chunks(p13,"01",original_name,(raw,)).receipt
        self.assertIsNotNone(origin)
        provenance=self.provenance(inv_art,**(provenance_changes or {}))
        opts=dict(invocation=CMD,target=TARGET,exit_code=2,
                  evidence=(origin,),bytes_count=origin.byte_count,
                  authorization_provenance=provenance)
        opts.update(o1_changes or {})
        record=build_attempt(RUN,"SRC-13","01","ALLOW","PARTIAL",
                             "ACQUISITION_ERROR",**opts)
        rec_path=commit_attempt(str(folder),record)
        memory_proof=(None if wrong_memory_proof else provenance)
        o1=RecordedOutcome(
            {"disposition":"PARTIAL","reason":"ACQUISITION_ERROR",
             "receipts":(origin,)},rec_path,
            authorization_provenance=memory_proof)
        if change_original:
            (folder/origin.private_relative_path).write_bytes(b"forged")
        attempts=(inventory,o1) if include_inventory else (o1,)
        run=EngineRun(RUN,(CollectorRun("COL-BLOCK",attempts),))
        return folder,run,origin,rec_path

    def test_same_run_original_and_consent_provenance_map_to_incomplete(self):
        folder,run,artifact,_=self.canonical_fixture()
        manifest=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),manifest)
        statuses=json.loads((folder/"private/status_records.json").read_text())
        o1=next(s for s in statuses["status_records"] if s["subject_id"]=="SRC-13")
        self.assertEqual((o1["status"],o1["reason_code"]),
                         ("PARTIAL","SOURCE_INCOMPLETE"))
        self.assertIn("transport=PARTIAL/ACQUISITION_ERROR",o1["detail"])
        self.assertIn("exit_code=2",o1["detail"])
        self.assertIn("target=/dev/sda",o1["detail"])
        self.assertNotIn("healthy",o1["detail"].lower())
        self.assertNotIn("failing",o1["detail"].lower())
        self.assertEqual((folder/artifact.private_relative_path).read_bytes(),
                         b"SMART data available but exit bits are nonzero\\n")

    def test_no_in_memory_attestation_or_inventory_fails_closed(self):
        for mods in (dict(wrong_memory_proof=True),
                     dict(include_inventory=False),
                     dict(change_original=True)):
            with self.subTest(mods=mods):
                folder,run,*_=self.canonical_fixture(**mods)
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)
                self.assertFalse((folder/"private/session_manifest.json").exists())

    def test_forged_consent_inventory_or_command_fails_closed(self):
        bad=[
            {"consent_run_id":"run-2026305120001"},
            {"consent_source_id":"SRC-18"},
            {"consent_operation_id":"FAKE"},
            {"consent_target":"/dev/sdb"},
            {"consent_issued_utc":"invalid"},
            {"impact_acknowledged":False},
            {"inventory_source_id":"SRC-19"},
            {"inventory_source_path":"/sys/class/block/sdb/size"},
            {"inventory_evidence_id":"forged"},
            {"approved_argv":["smartctl","-H","/dev/sda"]},
            {"target":"/dev/sdb"},
        ]
        for changes in bad:
            with self.subTest(changes=changes):
                folder,run,*_=self.canonical_fixture(provenance_changes=changes)
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)

    def test_forged_invocation_and_exit_and_no_evidence_fails_closed(self):
        for opts in (dict(invocation="smartctl --all /dev/sda"),
                     dict(target="/dev/sdb"),
                     dict(exit_code=0),
                     dict(exit_code=None),
                     dict(exit_code=65536)):
            with self.subTest(opts=opts):
                try:
                    folder,run,*_=self.canonical_fixture(o1_changes=opts)
                except ValueError:
                    continue # Operational builder already rejected invalid code
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)


    def test_stderr_only_original_is_diagnostic_not_drive_health(self):
        folder,run,*_=self.canonical_fixture(original_name="call0001-stderr")
        manifest=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),manifest)
        observed=json.loads((folder/"private/system.json").read_text())["observations"]
        self.assertFalse(any(x["datum_path"].startswith("health.")
                             for x in observed))
        statuses=json.loads((folder/"private/status_records.json").read_text())
        o1=next(s for s in statuses["status_records"] if s["subject_id"]=="SRC-13")
        self.assertEqual(o1["reason_code"],"SOURCE_INCOMPLETE")

    def test_nvme_controller_traced_to_same_run_namespace(self):
        path="/sys/class/block/nvme0n1/size"
        folder,run,*_=self.canonical_fixture(
            inventory_path=path,
            provenance_changes=dict(
                target="/dev/nvme0",consent_target="/dev/nvme0",
                inventory_source_path=path,
                approved_argv=["nvme","smart-log","/dev/nvme0"]),
            o1_changes=dict(target="/dev/nvme0",
                            invocation="nvme smart-log /dev/nvme0"))
        self.assertEqual(validate_canonical(folder) if
                         (folder/"private/session_manifest.json").exists()
                         else build_canonical(folder,run)["attempt_count"],2)

    def test_rejected_stream_ordinal_and_modified_receipt(self):
        folder,run,*_=self.canonical_fixture(original_name="call0002-stdout")
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder,run)
        folder,run,origin,receipt=self.canonical_fixture()
        receipt_path=folder/receipt
        metadata=json.loads(receipt_path.read_text())
        metadata["authorization_provenance"]["consent_target"]="/dev/sdb"
        receipt_path.write_text(json.dumps(metadata))
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder,run)

    def test_g503_engine_binding_flows_to_real_g502_receipt_without_device_io(self):
        """Mock transport and device metadata only; run real source dispatcher."""
        from datetime import datetime,timezone
        import os
        import stat
        from unittest.mock import patch
        from lbt_g5.engine import UnifiedCollectorEngine
        from lbt_g5.receipt_dispatch import capture_and_record
        from lbt_g5.o1 import OptionalSourcePlan
        from lbt_g5.runtime import TransportCapture
        from lbt_g5.safety import SourceRequest,SourceConsent
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder=Path(temp.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        inventory,_=self.inventory(folder,writer)
        consent=SourceConsent(RUN,"SRC-13","DEVICE_HEALTH",TARGET,
                              datetime.now(timezone.utc),True)
        req=SourceRequest(RUN,"SRC-13","DEVICE_HEALTH",
                          target=TARGET,consent=consent,
                          trusted_targets=frozenset({"/dev/forged"}))
        engine=UnifiedCollectorEngine(str(folder),RUN,writer=writer)
        real_lstat=os.lstat
        def device_stat(path,*args,**kwargs):
            if str(path)==TARGET:
                return SimpleNamespace(st_mode=stat.S_IFBLK)
            return real_lstat(path,*args,**kwargs)
        def dispatch(request,*args,**kwargs):
            if request.source_id=="SRC-11":
                return RecordedOutcome(
                    SimpleNamespace(disposition="DENIED",source_paths=(),
                                    artifacts=()),"not-used")
            if request.source_id=="SRC-12":
                return inventory
            return capture_and_record(request,*args,**kwargs)
        plan=OptionalSourcePlan("SRC-13","DEVICE_HEALTH",TARGET,
                                ("smartctl","-i","-H",TARGET),4096,2,
                                "may wake device")
        transport=TransportCapture(b"SMART device excerpt\\n",b"",2,.01,
                                    False,False,0,0)
        with patch("lbt_g5.engine.os.lstat",side_effect=device_stat),\\
             patch("lbt_g5.o1_execution.plan_optional",return_value=plan),\\
             patch("lbt_g5.o1_execution._resolve_executable",
                   return_value="/usr/sbin/smartctl"),\\
             patch("lbt_g5.o1_execution._capture_child",
                   return_value=transport),\\
             patch("lbt_g5.engine.capture_and_record",side_effect=dispatch):
            run=engine.run(("COL-BLOCK",),o1_requests={"SRC-13":req})
        o1=run.collectors[0].source_attempts[-1]
        meta=json.loads((folder/o1.receipt_private_path).read_text())
        self.assertEqual(meta["schema_version"],"g5-02-attempt-0.2")
        self.assertEqual(meta["authorization_provenance"]["inventory_source_path"],INVPATH)
        self.assertEqual(meta["authorization_provenance"]["consent_target"],TARGET)
        self.assertEqual(meta["exit_code"],2)
        self.assertEqual(meta["invocation"],CMD)
        subset=EngineRun(RUN,(CollectorRun("COL-BLOCK",(inventory,o1)),))
        canonical=build_canonical(folder,subset)
        self.assertEqual(validate_canonical(folder),canonical)
        statuses=json.loads((folder/"private/status_records.json").read_text())
        o1_status=next(s for s in statuses["status_records"]
                       if s["subject_id"]=="SRC-13")
        self.assertEqual(o1_status["reason_code"],"SOURCE_INCOMPLETE")

    def test_prior_d1_source_incomplete_remains_unchanged(self):
        self.assertEqual(_status_for(
            dict(outcome="PARTIAL",reason="EXIT_NONZERO",
                 authorization_class="D1",exit_code=2,
                 timed_out=False,capture_limited=False),
            [object()],parser_state="NOT_RUN"),
            ("PARTIAL","SOURCE_INCOMPLETE"))


if __name__=="__main__":
    unittest.main()
