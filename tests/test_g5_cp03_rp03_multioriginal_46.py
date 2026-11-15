"""RP-03.2 Increment 46: independent sealed multi-original/source attribution.

Tests are source-first against approved D-02; no real device access or policy
mutation. Source 15 FS_STAT consumes its own sealed D1 worker original and the
same-run, independently sealed SRC-14 mountinfo selection original.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest, initial_source_policies

RUN = "run-2026319150000"
POL = {p.source_id: p for p in initial_source_policies()}
MOUNTINFO = (
    b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
    b"2 1 8:2 / /boot rw - ext4 /dev/sda2 rw\n"
)


def fsstat(mount):
    return (json.dumps({
        "mount": mount, "fragment_size": 4096, "block_size": 4096,
        "blocks": 100, "free_blocks": 40, "available_blocks": 30,
        "files": 1000, "free_files": 800,
    }, sort_keys=True) + "\n").encode()


class MultiOriginalProvenance46(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name) / RUN
        self.folder.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.folder), RUN)

    def sealed(self, source, raw, slot="01", **kwargs):
        original = self.writer.seal_chunks(
            POL[source], slot, "item0001", (raw,)).receipt
        receipt = build_attempt(
            RUN, source, slot, "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=(original,), bytes_count=original.byte_count, **kwargs)
        record = SimpleNamespace(
            outcome=SimpleNamespace(artifacts=(original,)),
            receipt_private_path=commit_attempt(str(self.folder), receipt))
        return record, original

    def fs_session(self):
        rec14, original14 = self.sealed(
            "SRC-14", MOUNTINFO, invocation="MOUNTINFO",
            source_paths=("/proc/self/mountinfo",))
        stream = [
            TransportCapture(fsstat("/"), b"", 0, .01, False, False, 0, 0),
            TransportCapture(fsstat("/boot"), b"", 0, .01, False, False, 0, 0),
        ]
        with patch("lbt_g5.additional.decide_source",
                   return_value=SimpleNamespace(allowed=True, reason="APPROVED")), \
             patch("lbt_g5.additional.eligible_mounts",
                   return_value=("/", "/boot")), \
             patch("lbt_g5.additional._resolve_executable",
                   return_value="/usr/bin/python3"), \
             patch("lbt_g5.additional._capture_child", side_effect=stream):
            rec15 = capture_and_record(
                SourceRequest(RUN, "SRC-15", "FS_STAT"), "01", self.writer,
                ProbeSlots(), SourceCallBudget(), source14_evidence=MOUNTINFO)
        originals15 = tuple(rec15.outcome.artifacts)
        self.assertEqual(len(originals15), 2)
        run = EngineRun(RUN, (
            CollectorRun("COL-FS", (rec14, rec15)),))
        manifest = build_canonical(self.folder, run)
        files = {
            name: json.loads((self.folder / "private" / name).read_text())
            for name in ("system.json", "source_attempts.json",
                         "status_records.json", "session_manifest.json")
        }
        return manifest, files, original14, originals15

    def reseal(self, name, payload):
        path = self.folder / "private" / name
        raw = (json.dumps(payload, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False) + "\n").encode()
        path.write_bytes(raw)
        if name != "session_manifest.json":
            mp = self.folder / "private" / "session_manifest.json"
            manifest = json.loads(mp.read_text())
            manifest["files"][name] = {
                "sha256": hashlib.sha256(raw).hexdigest(), "byte_count": len(raw)}
            self.reseal("session_manifest.json", manifest)

    def test_46_01_real_two_original_semantic_contributors(self):
        manifest, files, src14, src15 = self.fs_session()
        observations = files["system.json"]["observations"]
        for raw15 in src15:
            row = next(o for o in observations if o["observation_id"] ==
                       "obs:" + raw15.evidence_id + ":sem:0")
            self.assertEqual(row["datum_path"], "storage.fs_stat.snapshot")
            self.assertEqual(row["evidence_refs"],
                             [raw15.evidence_id, src14.evidence_id])
            self.assertEqual(row["source_attempt_ids"],
                             ["SRC-15-01", "SRC-14-01"])
            self.assertEqual(row["status_record_id"], "st:SRC-15-01")
            self.assertEqual(row["instance_key"], raw15.evidence_id)
        self.assertEqual(validate_canonical(self.folder), manifest)

    def test_46_02_distinct_source_artifacts_are_not_interchangeable(self):
        _, files, _, src15 = self.fs_session()
        obs = copy.deepcopy(files["system.json"])
        first = next(o for o in obs["observations"] if o["observation_id"] ==
                     "obs:" + src15[0].evidence_id + ":sem:0")
        first["evidence_refs"] = [src15[1].evidence_id]
        self.reseal("system.json", obs)
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_46_03_same_bytes_distinct_attempts_remain_distinct(self):
        raw = b"MemTotal: 1024 kB\nMemFree: 128 kB\n"
        rec1, original1 = self.sealed("SRC-08", raw, slot="01")
        rec2, original2 = self.sealed("SRC-08", raw, slot="02")
        self.assertNotEqual(original1.evidence_id, original2.evidence_id)
        run = EngineRun(RUN, (
            CollectorRun("COL-MEM", (rec1, rec2)),))
        manifest = build_canonical(self.folder, run)
        self.assertEqual(validate_canonical(self.folder), manifest)
        observations = json.loads(
            (self.folder / "private/system.json").read_text())["observations"]
        for raw_item, aid in ((original1, "SRC-08-01"),
                              (original2, "SRC-08-02")):
            own = [o for o in observations
                   if o["instance_key"] == raw_item.evidence_id]
            self.assertTrue(own)
            self.assertTrue(all(o["evidence_refs"] == [raw_item.evidence_id]
                                and o["source_attempt_ids"] == [aid]
                                for o in own))

    def test_46_04_rehashed_semantic_value_not_supported_by_original(self):
        _, files, _, src15 = self.fs_session()
        system = copy.deepcopy(files["system.json"])
        row = next(o for o in system["observations"] if o["observation_id"] ==
                   "obs:" + src15[0].evidence_id + ":sem:0")
        row["normalized_value"]["free_blocks"] = 999999
        self.reseal("system.json", system)
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_46_05_rehashed_literal_original_not_supported_by_bytes(self):
        _, files, _, src15 = self.fs_session()
        system = copy.deepcopy(files["system.json"])
        row = next(o for o in system["observations"] if o["observation_id"] ==
                   "obs:" + src15[0].evidence_id)
        row["observed_value"] = "fabricated original"
        self.reseal("system.json", system)
        with self.assertRaises(CanonicalContractError):
            validate_canonical(self.folder)

    def test_46_06_non_utf8_lossless_fallback(self):
        raw = b"ID=ubuntu\nNAME=\xff\n"
        rec, original = self.sealed("SRC-02", raw)
        run = EngineRun(RUN, (
            CollectorRun("COL-OS", (rec,)),))
        manifest = build_canonical(self.folder, run)
        self.assertEqual(validate_canonical(self.folder), manifest)
        obs = json.loads(
            (self.folder / "private/system.json").read_text())["observations"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0]["observed_value"],
                         {"sealed_bytes_ref": original.evidence_id})
        self.assertEqual(obs[0]["value_type"], "BYTES_REF")
        self.assertEqual(
            (self.folder / original.private_relative_path).read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
