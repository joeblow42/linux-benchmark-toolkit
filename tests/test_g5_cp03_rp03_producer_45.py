"""RP-03.1 Increment 45 independent source-first production/verification oracles.

Approved CP-01 D-02 §6 is frozen in rp03_cp01_d02_approved_contract_43.json.
These tests exercise *produced* files, not sample-shaped input to d02_schema.
No physical device probing, changes to acquisition policy, or formal CP-02 claim.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.d02_schema import validate_d02_file, validate_d02_entity
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

ROOT = Path(__file__).resolve().parents[1]
CONTROL = json.loads((ROOT / "verification/g5_04/rp03_cp01_d02_approved_contract_43.json").read_text())
RUN = "run-2026318184500"
FILES = ("system.json", "source_attempts.json", "status_records.json", "session_manifest.json")


class ProducedD02Contract(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name) / RUN
        self.folder.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.folder), RUN)
        self.policies = {p.source_id: p for p in initial_source_policies()}

    def recorded(self, sid="SRC-02", *, raw=b"ID=sample\nNAME=Sample\n",
                 denied=False, slot="01"):
        policy = self.policies[sid]
        originals = ()
        if not denied:
            original = self.writer.seal_chunks(policy, slot, "item0001", (raw,)).receipt
            self.assertIsNotNone(original)
            originals = (original,)
        receipt = build_attempt(
            RUN, sid, slot, "DENY" if denied else "ALLOW",
            "DENIED" if denied else "CAPTURED",
            "OPERATOR_AUTH_REQUIRED" if denied else "BYTES_PRESERVED",
            evidence=originals, bytes_count=sum(x.byte_count for x in originals))
        path = commit_attempt(str(self.folder), receipt)
        return SimpleNamespace(
            outcome=SimpleNamespace(artifacts=originals), receipt_private_path=path)

    def produce(self, *sources, collector="COL-OS"):
        run = EngineRun(RUN, (CollectorRun(collector, sources),))
        manifest = build_canonical(self.folder, run)
        payloads = {name: json.loads((self.folder / "private" / name).read_text())
                    for name in FILES}
        return manifest, payloads

    def reseal_json(self, name, payload):
        """Adversarial postcommit mutation with digest recomputed, no weakened oracle."""
        path = self.folder / "private" / name
        raw = (json.dumps(payload, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False) + "\n").encode()
        path.write_bytes(raw)
        if name != "session_manifest.json":
            manifest_path = self.folder / "private/session_manifest.json"
            ledger = json.loads(manifest_path.read_text())
            ledger["files"][name] = {
                "sha256": hashlib.sha256(raw).hexdigest(), "byte_count": len(raw)}
            self.reseal_json("session_manifest.json", ledger)

    def assert_exact_file_and_entities(self, files):
        for filename, payload in files.items():
            with self.subTest(filename=filename):
                self.assertEqual(set(payload), set(CONTROL["files"][filename]))
                validate_d02_file(filename, payload)
        system, attempts, status, manifest = (files[key] for key in FILES)
        entities = [
            ("SessionHeader", system["header"]),
            *[("CanonicalObservation", x) for x in system["observations"]],
            *[("CaptureLimit", x) for x in system["capture_limits"]],
            *[("SourceAttempt", x) for x in attempts["attempts"]],
            *[("StatusRecord", x) for x in status["status_records"]],
            ("Counts", manifest["counts"]),
            *[("FileDigest", x) for x in manifest["files"].values()],
            *[("EvidenceArtifact", x) for x in manifest["evidence"].values()],
            *[("ReceiptDigest", x) for x in manifest["source_receipts"].values()],
        ]
        for kind, item in entities:
            with self.subTest(entity=kind):
                self.assertEqual(set(item), set(CONTROL["entities"][kind]))
                validate_d02_entity(kind, item)

    def test_45_01_source_first_all_four_produced_files_exact(self):
        _, files = self.produce(self.recorded())
        self.assert_exact_file_and_entities(files)
        self.assertEqual(validate_canonical(self.folder), files["session_manifest.json"])

    def test_45_02_zero_observation_denial_usable_and_not_complete(self):
        _, files = self.produce(
            self.recorded("SRC-13", denied=True), collector="COL-BLOCK")
        self.assert_exact_file_and_entities(files)
        self.assertEqual(files["session_manifest.json"]["counts"]["observations"], 0)
        self.assertTrue(files["session_manifest.json"]["minimum_usable"])
        self.assertEqual(files["session_manifest.json"]["completion_state"], "INCOMPLETE")
        self.assertEqual(files["status_records.json"]["status_records"][0]["status"],
                         "UNAUTHORIZED")

    def test_45_03_original_receipt_and_manifest_correspond_to_same_run(self):
        receipt = self.recorded()
        _, files = self.produce(receipt)
        manifest = files["session_manifest.json"]
        attempt = files["source_attempts.json"]["attempts"][0]
        self.assertEqual(manifest["counts"]["attempts"], 1)
        self.assertEqual(manifest["counts"]["sources"], 1)
        self.assertEqual(manifest["counts"]["evidence_artifacts"], 1)
        self.assertEqual(manifest["counts"]["statuses"], 2)
        self.assertEqual(manifest["source_attempt_ids"], [attempt["attempt_id"]])
        self.assertEqual(set(manifest["source_receipts"]), {attempt["attempt_id"]})
        digest = manifest["source_receipts"][attempt["attempt_id"]]
        raw_receipt = (self.folder / digest["restricted_relative_path"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw_receipt).hexdigest(), digest["sha256"])
        self.assertEqual(len(raw_receipt), digest["byte_count"])
        evidence_id, ev = next(iter(manifest["evidence"].items()))
        self.assertEqual(ev["source_attempt_id"], attempt["attempt_id"])
        self.assertEqual(hashlib.sha256(
            (self.folder / ev["restricted_relative_path"]).read_bytes()).hexdigest(),
            ev["sha256"])
        self.assertIn(evidence_id, attempt["evidence_ids"])

    def test_45_04_rehashed_unknown_production_field_rejected(self):
        _, files = self.produce(self.recorded())
        system = copy.deepcopy(files["system.json"])
        system["unknown_production_field"] = "surreptitious"
        self.reseal_json("system.json", system)
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_45_05_rehashed_observation_foreign_evidence_rejected(self):
        _, files = self.produce(self.recorded())
        system = copy.deepcopy(files["system.json"])
        system["observations"][0]["evidence_refs"] = ["not-this-run"]
        self.reseal_json("system.json", system)
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_45_06_rehashed_manifest_identity_list_rejected(self):
        _, files = self.produce(self.recorded())
        manifest = copy.deepcopy(files["session_manifest.json"])
        manifest["source_attempt_ids"].append("SRC-99-01")
        self.reseal_json("session_manifest.json", manifest)
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_45_07_rehashed_source_attempt_status_relationship_rejected(self):
        _, files = self.produce(self.recorded())
        attempts = copy.deepcopy(files["source_attempts.json"])
        attempts["attempts"][0]["status_record_id"] = "st:missing"
        self.reseal_json("source_attempts.json", attempts)
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_45_08_manifest_wrong_receipt_digest_rejected(self):
        _, files = self.produce(self.recorded())
        manifest = copy.deepcopy(files["session_manifest.json"])
        key = next(iter(manifest["source_receipts"]))
        manifest["source_receipts"][key]["sha256"] = "0" * 64
        self.reseal_json("session_manifest.json", manifest)
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)


if __name__ == "__main__":
    unittest.main()
