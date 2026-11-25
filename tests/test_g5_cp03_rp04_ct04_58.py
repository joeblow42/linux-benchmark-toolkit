"""LBT RP-04 Increment 58: original CT-04 source-outcome candidate checks.

Offline G5-02 source receipts; tool absence is source-reported in a sealed
SRC-27 fixture, not a claim about installed tools on the CI host.
Formal CP-02 independent case execution/acceptance is NOT implied.
"""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import _status_for, build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026318185858"
ABSENT_TOOL = "lscpu"

class RP04CT04Candidate58(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / RUN
        self.folder.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.folder), RUN)
        self.policies = {p.source_id:p for p in initial_source_policies()}

    def recorded(self, sid, decision, outcome, reason, *, raw=None):
        original = None
        if raw is not None:
            original = self.writer.seal_chunks(
                self.policies[sid], "01", "item0001", (raw,)).receipt
            self.assertIsNotNone(original)
        evidence = (original,) if original is not None else ()
        receipt = build_attempt(
            RUN, sid, "01", decision, outcome, reason,
            evidence=evidence,
            bytes_count=sum(x.byte_count for x in evidence))
        path = commit_attempt(str(self.folder),receipt)
        record = SimpleNamespace(
            receipt_private_path=path,
            outcome=SimpleNamespace(artifacts=evidence))
        return record, original, path

    def produce(self,*owners):
        session = EngineRun(RUN, tuple(
            CollectorRun(owner,tuple(records)) for owner,records in owners))
        manifest=build_canonical(self.folder,session)
        self.assertEqual(validate_canonical(self.folder),manifest)
        data={name:json.loads((self.folder/"private"/name).read_text())
              for name in ("system.json","source_attempts.json","status_records.json")}
        return manifest,data

    def test_58_01_CT_04_P1_unconsented_O1_is_unauthorized(self):
        record, original, path = self.recorded(
            "SRC-13","DENY","DENIED","OPERATOR_AUTH_REQUIRED")
        self.assertIsNone(original)
        receipt=json.loads((self.folder/path).read_text())
        self.assertEqual(receipt["decision"],"DENY")
        self.assertEqual(receipt["outcome"],"DENIED")
        self.assertEqual(receipt["evidence_ids"],[])
        self.assertIsNone(receipt.get("authorization_provenance"))
        manifest,data=self.produce(("COL-BLOCK",(record,)))
        source=next(x for x in data["status_records.json"]["status_records"]
                    if x["domain"]=="acquisition")
        self.assertEqual((source["status"],source["reason_code"]),
                         ("UNAUTHORIZED","OPERATOR_AUTH_REQUIRED"))
        self.assertEqual(source["source_attempt_ids"],["SRC-13-01"])
        self.assertEqual(source["evidence_refs"],[])
        self.assertEqual(manifest["counts"]["evidence_artifacts"],0)

    def test_58_02_CT_04_P2_absent_executable_has_source_report(self):
        # Offline representation of the approved SRC-27 fixed-PATH resolver
        # returning a NULL path, not an assumption about this host.
        raw=json.dumps({"tool":ABSENT_TOOL,"path":None},
                       sort_keys=True,separators=(",",":")).encode("utf-8")
        resolver,original,path=self.recorded(
            "SRC-27","ALLOW","CAPTURED","BYTES_PRESERVED",raw=raw)
        missing,_,missing_path=self.recorded(
            "SRC-05","ALLOW","UNAVAILABLE","EXECUTABLE_NOT_FOUND")
        manifest,data=self.produce(
            ("COL-TOOLS",(resolver,)),("COL-CPU",(missing,)))
        tool_obs=next(x for x in data["system.json"]["observations"]
                      if x["datum_path"]=="tools.resolution."+ABSENT_TOOL)
        self.assertEqual(tool_obs["normalized_value"],
                         {"available":False,"resolved_path":None})
        self.assertEqual(tool_obs["evidence_refs"],[original.evidence_id])
        self.assertEqual((self.folder/original.private_relative_path).read_bytes(),raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),original.sha256)
        statuses=data["status_records.json"]["status_records"]
        source=next(x for x in statuses
                    if x["domain"]=="acquisition" and x["subject_id"]=="SRC-05")
        self.assertEqual((source["status"],source["reason_code"]),
                         ("TOOL_MISSING","EXECUTABLE_NOT_FOUND"))
        self.assertEqual(source["source_attempt_ids"],["SRC-05-01"])
        self.assertEqual(manifest["counts"]["evidence_artifacts"],1)
        missing_receipt=json.loads((self.folder/missing_path).read_text())
        self.assertEqual(missing_receipt["outcome"],"UNAVAILABLE")
        self.assertEqual(missing_receipt["reason"],"EXECUTABLE_NOT_FOUND")

    def test_58_03_CT_04_N1_unknown_transport_must_fail_closed(self):
        record,_,path=self.recorded(
            "SRC-02","ALLOW","FAILED","UNRECOGNIZED_TRANSPORT_REASON")
        with self.assertRaises(CanonicalContractError) as raised:
            build_canonical(self.folder,EngineRun(
                RUN,(CollectorRun("COL-OS",(record,)),)))
        self.assertIn("unclassified source outcome/reason",str(raised.exception))
        self.assertFalse((self.folder/"private/status_records.json").exists())
        self.assertFalse((self.folder/"private/session_manifest.json").exists())
        persisted=json.loads((self.folder/path).read_text())
        self.assertEqual(persisted["reason"],"UNRECOGNIZED_TRANSPORT_REASON")
        # Unknown disposition also must never acquire a synthetic failure key.
        with self.assertRaises(CanonicalContractError):
            _status_for({"outcome":"UNRECOGNIZED","reason":"UNKNOWN"},[])

    def test_58_04_CT_04_N2_unavailable_cannot_claim_success(self):
        record,_,path=self.recorded(
            "SRC-02","ALLOW","UNAVAILABLE","SOURCE_ABSENT")
        _,data=self.produce(("COL-OS",(record,)))
        source=next(x for x in data["status_records.json"]["status_records"]
                    if x["domain"]=="acquisition")
        self.assertEqual((source["status"],source["reason_code"]),
                         ("UNAVAILABLE","SOURCE_ABSENT"))
        self.assertNotEqual(source["status"],"COMPLETE")
        self.assertEqual(source["source_attempt_ids"],["SRC-02-01"])
        self.assertEqual(source["evidence_refs"],[])
        persisted=json.loads((self.folder/path).read_text())
        self.assertEqual(persisted["outcome"],"UNAVAILABLE")
        with self.assertRaises(CanonicalContractError):
            _status_for({"outcome":"CAPTURED","reason":"BYTES_PRESERVED"},
                        [],parser_state="OK")


if __name__=="__main__":
    unittest.main()
