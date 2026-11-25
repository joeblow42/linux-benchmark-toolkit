"""RP-04 Increment 64: exact CT-10 bounded canonical-session commit checks.

Use real G5-02 sealed temp originals and actual G5-04 private writer. Negative
scenarios simulate ordinary I/O loss or in-memory reading mistakes, never
altering a sealed original, rewriting digests, or assuming a hostile actor.
Development CI only; formal CP-02 and physical FAT remain unexecuted.
"""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import lbt_g5.canonical_session as canonical
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.d02_schema import validate_d02_file
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026320205900"
RAW = b"ID=bodhi\nNAME=Bodhi\n"

class RP04CT10Candidate64(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder=Path(temp.name)/RUN
        self.folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(self.folder),RUN)
        policy={p.source_id:p for p in initial_source_policies()}["SRC-02"]
        self.original=writer.seal_chunks(policy,"01","item0001",(RAW,)).receipt
        self.assertIsNotNone(self.original)
        self.receipt=build_attempt(
            RUN,"SRC-02","01","ALLOW","CAPTURED","BYTES_PRESERVED",
            evidence=(self.original,),bytes_count=self.original.byte_count)
        self.receipt_path=commit_attempt(str(self.folder),self.receipt)
        rec=SimpleNamespace(
            receipt_private_path=self.receipt_path,
            outcome=SimpleNamespace(artifacts=(self.original,)))
        self.run=EngineRun(RUN,(CollectorRun("COL-OS",(rec,)),))

    def snapshot(self):
        private=self.folder/"private"
        return {str(path.relative_to(private)):hashlib.sha256(path.read_bytes()).hexdigest()
                for path in private.rglob("*") if path.is_file()}

    def assert_unchanged_originals(self):
        original=self.folder/self.original.private_relative_path
        self.assertEqual(original.read_bytes(),RAW)
        self.assertEqual(hashlib.sha256(RAW).hexdigest(),self.original.sha256)
        receipt=json.loads((self.folder/self.receipt_path).read_text())
        self.assertEqual(receipt["evidence_ids"],[self.original.evidence_id])
        self.assertEqual(receipt["outcome"],"CAPTURED")

    def produce(self):
        manifest=canonical.build_canonical(self.folder,self.run)
        self.assertEqual(canonical.validate_canonical(self.folder),manifest)
        self.assert_unchanged_originals()
        return manifest

    def test_64_01_CT_10_P1_manifest_last_and_independent_counts(self):
        real_write=canonical._atomic_new_private
        published=[]
        def record_publish(private,name,raw):
            published.append(name)
            return real_write(private,name,raw)
        with patch("lbt_g5.canonical_session._atomic_new_private",
                   side_effect=record_publish):
            manifest=self.produce()
        self.assertEqual(published,
            ["system.json","source_attempts.json","status_records.json",
             "session_manifest.json"])
        self.assertEqual(set(manifest["files"]),set(canonical.PRIVATE_FILES))
        self.assertEqual(manifest["counts"]["attempts"],1)
        self.assertEqual(manifest["counts"]["sources"],1)
        self.assertEqual(manifest["counts"]["evidence_artifacts"],1)
        self.assertEqual(manifest["counts"]["original_bytes"],len(RAW))
        self.assertEqual(manifest["counts"]["observations"],3)
        self.assertEqual(manifest["counts"]["statuses"],2)
        self.assertTrue(manifest["integrity_verified"])
        self.assertTrue(manifest["minimum_usable"])
        self.assertEqual(manifest["completion_state"],"INCOMPLETE")
        for name,record in manifest["files"].items():
            raw=(self.folder/"private"/name).read_bytes()
            self.assertEqual(len(raw),record["byte_count"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),record["sha256"])
            validate_d02_file(name,json.loads(raw))
        evidence=manifest["evidence"][self.original.evidence_id]
        self.assertEqual((evidence["sha256"],evidence["byte_count"]),
                         (self.original.sha256,len(RAW)))
        self.assertEqual(evidence["source_attempt_id"],"SRC-02-01")
        receipt=manifest["source_receipts"]["SRC-02-01"]
        orig_bytes=(self.folder/self.receipt_path).read_bytes()
        self.assertEqual((receipt["sha256"],receipt["byte_count"]),
                         (hashlib.sha256(orig_bytes).hexdigest(),len(orig_bytes)))
        self.assertEqual(manifest["source_attempt_ids"],["SRC-02-01"])
        self.assertEqual(canonical.validate_canonical(self.folder),manifest)

    def test_64_02_CT_10_N1_manifest_persist_failure_does_not_validate(self):
        original_publish=canonical._atomic_new_private
        seen=[]
        def no_manifest(private,name,raw):
            seen.append(name)
            if name=="session_manifest.json":
                raise OSError("simulated ordinary manifest persistence interruption")
            return original_publish(private,name,raw)
        with patch("lbt_g5.canonical_session._atomic_new_private",
                   side_effect=no_manifest):
            with self.assertRaises(OSError):
                canonical.build_canonical(self.folder,self.run)
        self.assertEqual(seen,list(canonical.PRIVATE_FILES)+["session_manifest.json"])
        for name in canonical.PRIVATE_FILES:
            self.assertTrue((self.folder/"private"/name).is_file())
        self.assertFalse((self.folder/"private/session_manifest.json").exists())
        with self.assertRaises((CanonicalContractError,FileNotFoundError)):
            canonical.validate_canonical(self.folder)
        self.assert_unchanged_originals()

    def test_64_03_CT_10_N2_ordinary_bad_reads_or_counts_fail_validation(self):
        manifest=self.produce()
        before=self.snapshot()
        read=canonical._read_restricted
        paths={
            "canonical_json":self.folder/"private/system.json",
            "receipt":self.folder/self.receipt_path,
            "original":self.folder/self.original.private_relative_path,
        }
        for label,target in paths.items():
            def faulty_read(path,bound,target=target):
                raw=read(path,bound)
                if Path(path)==target:
                    return raw+b" " if label!="original" else bytes((raw[0]^1,))+raw[1:]
                return raw
            with self.subTest(label=label), patch(
                "lbt_g5.canonical_session._read_restricted",
                side_effect=faulty_read):
                with self.assertRaises(CanonicalContractError):
                    canonical.validate_canonical(self.folder)
        load=canonical._json_load
        def wrong_count_view(raw):
            data=load(raw)
            if type(data) is dict and "manifest_version" in data:
                data["counts"]["observations"]+=1
            return data
        with patch("lbt_g5.canonical_session._json_load",
                   side_effect=wrong_count_view):
            with self.assertRaises(CanonicalContractError):
                canonical.validate_canonical(self.folder)
        self.assertEqual(self.snapshot(),before)
        self.assertEqual(canonical.validate_canonical(self.folder),manifest)

    def test_64_04_CT_10_N3_exclusive_duplicate_session_and_receipt(self):
        self.produce()
        before=self.snapshot()
        with self.assertRaises(FileExistsError):
            canonical.build_canonical(self.folder,self.run)
        with self.assertRaises(FileExistsError):
            commit_attempt(str(self.folder),self.receipt)
        self.assertEqual(self.snapshot(),before)
        self.assert_unchanged_originals()


if __name__=="__main__":
    unittest.main()
