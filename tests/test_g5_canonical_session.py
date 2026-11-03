"""G5-04 private canonical persistence, no re-acquisition and integrity tests."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import (
    build_canonical, validate_canonical, _atomic_new_private,
)
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"


class G504CanonicalSession(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folder = self.root / RUN
        self.folder.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.folder), RUN)
        self.policies = {p.source_id: p for p in initial_source_policies()}

    def recorded(self, sid="SRC-02", raw=b"ID=testos\nNAME=TestOS\n", *, outcome="CAPTURED",
                 reason="BYTES_PRESERVED", attempt="01", fail=False):
        policy = self.policies[sid]
        evidence = ()
        if not fail:
            receipt = self.writer.seal_chunks(policy, attempt, "item0001",
                                              (raw,)).receipt
            self.assertIsNotNone(receipt)
            evidence = (receipt,)
        operational = build_attempt(
            RUN, sid, attempt, "DENY" if outcome == "DENIED" else "ALLOW",
            outcome, reason, evidence=evidence,
            bytes_count=sum(x.byte_count for x in evidence))
        path = commit_attempt(str(self.folder), operational)
        recorded = SimpleNamespace(
            outcome=SimpleNamespace(artifacts=evidence),
            receipt_private_path=path)
        return recorded

    def run_for(self, *recorded, cid="COL-OS"):
        return EngineRun(RUN, (CollectorRun(cid, recorded),))

    def test_text_original_and_provenance_committed_and_revalidated(self):
        x = self.recorded()
        manifest = build_canonical(self.folder, self.run_for(x))
        self.assertEqual(manifest["observation_count"], 3)
        self.assertEqual(manifest["original_byte_count"], len(b"ID=testos\nNAME=TestOS\n"))
        self.assertEqual(manifest["completion_state"], "INCOMPLETE")
        self.assertFalse(manifest["semantic_normalization_complete"])
        system = json.loads((self.folder / "private/system.json").read_text())
        obs = system["observations"][0]
        self.assertEqual(obs["value_type"], "STRING")
        self.assertEqual(obs["observed_value"], "ID=testos\nNAME=TestOS\n")
        self.assertIsNone(obs["normalized_value"])
        self.assertEqual(len(obs["evidence_refs"]), 1)
        statuses = json.loads((self.folder / "private/status_records.json").read_text())
        self.assertEqual(statuses["status_records"][0]["reason_code"],
                         "OK")
        typed = {v["datum_path"]: v for v in system["observations"][1:]}
        self.assertEqual(typed["os.release.ID"]["normalized_value"], "testos")
        self.assertEqual(typed["os.release.NAME"]["normalized_value"], "TestOS")
        self.assertEqual(validate_canonical(self.folder), manifest)

    def test_binary_original_kept_without_mutation(self):
        x = self.recorded(raw=b"\xff\x00\x80")
        build_canonical(self.folder, self.run_for(x))
        system = json.loads((self.folder / "private/system.json").read_text())
        obs = system["observations"][0]
        self.assertEqual(obs["value_type"], "BYTES_REF")
        self.assertEqual(obs["observed_value"]["sealed_bytes_ref"],
                         obs["evidence_refs"][0])

    def test_zero_observation_denial_still_has_manifest(self):
        x = self.recorded(sid="SRC-13", outcome="DENIED",
                          reason="OPERATOR_AUTH_REQUIRED", fail=True)
        m = build_canonical(self.folder, self.run_for(x, cid="COL-BLOCK"))
        self.assertEqual(m["observation_count"], 0)
        statuses = json.loads((self.folder / "private/status_records.json").read_text())
        self.assertEqual(statuses["status_records"][0]["status"], "UNAUTHORIZED")
        self.assertEqual(statuses["status_records"][0]["reason_code"],
                         "OPERATOR_AUTH_REQUIRED")
        self.assertEqual(validate_canonical(self.folder), m)

    def test_tamper_original_before_commit_rejected(self):
        x = self.recorded()
        evidence_path = next((self.folder / "private/evidence").iterdir())
        evidence_path.write_bytes(b"changed")
        with self.assertRaises(CanonicalContractError):
            build_canonical(self.folder, self.run_for(x))
        self.assertFalse((self.folder / "private/session_manifest.json").exists())

    def test_tamper_original_after_commit_rejected(self):
        x = self.recorded()
        build_canonical(self.folder, self.run_for(x))
        evidence_path = next((self.folder / "private/evidence").iterdir())
        evidence_path.write_bytes(b"changed")
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_tamper_original_attempt_receipt_after_commit_rejected(self):
        x = self.recorded()
        build_canonical(self.folder, self.run_for(x))
        receipt = self.folder / x.receipt_private_path
        current = json.loads(receipt.read_text())
        current["reason"] = "FORGED_REASON"
        receipt.write_text(json.dumps(current))
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_tamper_canonical_after_commit_rejected(self):
        x = self.recorded()
        build_canonical(self.folder, self.run_for(x))
        (self.folder / "private/system.json").write_text("{}\n")
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_exclusive_finalization_cannot_overwrite(self):
        x = self.recorded()
        build_canonical(self.folder, self.run_for(x))
        with self.assertRaises(FileExistsError):
            build_canonical(self.folder, self.run_for(x))
        with self.assertRaises(FileExistsError):
            _atomic_new_private(self.folder / "private", "system.json", b"{}")

    def test_truncated_commit_never_presented_as_valid_session(self):
        x = self.recorded()
        _atomic_new_private(self.folder / "private", "system.json", b"{}")
        with self.assertRaises(FileNotFoundError):
            validate_canonical(self.folder)
        with self.assertRaises(FileExistsError):
            build_canonical(self.folder, self.run_for(x))
        self.assertFalse((self.folder / "private/session_manifest.json").exists())

    def test_receipt_tamper_rejected_before_manifest(self):
        x = self.recorded()
        p = self.folder / x.receipt_private_path
        record = json.loads(p.read_text())
        record["acquired_bytes"] += 1
        p.write_text(json.dumps(record))
        with self.assertRaises(CanonicalContractError):
            build_canonical(self.folder, self.run_for(x))

    def test_nonowner_private_permissions_rejected(self):
        x = self.recorded()
        os.chmod(self.folder / "private", 0o755)
        with self.assertRaises(CanonicalContractError):
            build_canonical(self.folder, self.run_for(x))

    def test_no_synthetic_public_artifacts_or_test_results(self):
        x = self.recorded()
        build_canonical(self.folder, self.run_for(x))
        self.assertFalse((self.folder / "public").exists())
        self.assertFalse((self.folder / "benchmarks.json").exists())
        self.assertFalse((self.folder / "validation.json").exists())


if __name__ == "__main__":
    unittest.main()
