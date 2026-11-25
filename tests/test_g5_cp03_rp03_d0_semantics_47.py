"""RP-03.2 Increment 47: source-first independent D0 typed-value oracles.

All input is deterministic, already sealed and off-host. The independently
specified values below are not derived from the production parser. Rehashing
a forged canonical document must never create genuine original-byte authority.
This increment covers SRC-02/08/09/10 only; other families remain OPEN.
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
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies


POL = {p.source_id: p for p in initial_source_policies()}
OS_BYTES = b'ID=ubuntu\nNAME="Ubuntu Linux"\nPRETTY_NAME="Ubuntu 22.04 LTS"\n'
MEM_BYTES = b"MemTotal: 1024 kB\nMemFree: 128 kB\nHugePages_Total: 3\n"
SWAP_BYTES = (b"Filename Type Size Used Priority\n"
              b"/swapfile file 1024 16 -2\n")
PSI_BYTES = (b"some avg10=0.01 avg60=0.02 avg300=0.03 total=123\n"
             b"full avg10=0.00 avg60=0.04 avg300=0.05 total=456\n")
FAMILIES = {
    "SRC-02": (OS_BYTES, [
        ("os.release.ID", "ubuntu", "ubuntu", "STRING", None),
        ("os.release.NAME", '"Ubuntu Linux"', "Ubuntu Linux", "STRING", None),
        ("os.release.PRETTY_NAME", '"Ubuntu 22.04 LTS"',
         "Ubuntu 22.04 LTS", "STRING", None),
    ], "linux-os-release-v1"),
    "SRC-08": (MEM_BYTES, [
        ("memory.meminfo.MemTotal", "1024 kB", 1048576, "INTEGER", "bytes"),
        ("memory.meminfo.MemFree", "128 kB", 131072, "INTEGER", "bytes"),
        ("memory.meminfo.HugePages_Total", "3", 3, "INTEGER", "count"),
    ], "linux-proc-meminfo-v1"),
    "SRC-09": (SWAP_BYTES, [
        ("memory.swap.entries", "SWAPS_TABLE", [{
            "name": "/swapfile", "type": "file",
            "size_bytes": 1048576, "used_bytes": 16384, "priority": -2,
        }], "ARRAY", None),
    ], "linux-proc-swaps-v1"),
    "SRC-10": (PSI_BYTES, [
        ("memory.pressure.some.avg10", "0.01", 0.01, "NUMBER", "percent"),
        ("memory.pressure.some.avg60", "0.02", 0.02, "NUMBER", "percent"),
        ("memory.pressure.some.avg300", "0.03", 0.03, "NUMBER", "percent"),
        ("memory.pressure.some.total", "123", 123, "INTEGER", "microseconds"),
        ("memory.pressure.full.avg10", "0.00", 0.0, "NUMBER", "percent"),
        ("memory.pressure.full.avg60", "0.04", 0.04, "NUMBER", "percent"),
        ("memory.pressure.full.avg300", "0.05", 0.05, "NUMBER", "percent"),
        ("memory.pressure.full.total", "456", 456, "INTEGER", "microseconds"),
    ], "linux-psi-memory-v1"),
}


class IndependentD0Semantic47(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.counter = 0

    def session(self, sid, raw=None):
        self.counter += 1
        run = "run-20263191547" + str(self.counter).zfill(2)
        folder = self.root / run
        folder.mkdir(mode=0o700)
        writer = EvidenceWriter(str(folder), run)
        data = FAMILIES[sid][0] if raw is None else raw
        original = writer.seal_chunks(POL[sid], "01", "item0001",
                                      (data,)).receipt
        receipt = build_attempt(
            run, sid, "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=(original,), bytes_count=original.byte_count)
        record = SimpleNamespace(
            outcome=SimpleNamespace(artifacts=(original,)),
            receipt_private_path=commit_attempt(str(folder), receipt))
        engine = EngineRun(run, (CollectorRun(
            POL[sid].collector_id, (record,)),))
        manifest = build_canonical(folder, engine)
        observations = json.loads(
            (folder / "private/system.json").read_text())["observations"]
        return folder, manifest, original, observations

    def reseal_system(self, folder, system, *, rewrite_identity=False):
        private = folder / "private"
        raw = (json.dumps(system, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False) + "\n").encode()
        (private / "system.json").write_bytes(raw)
        manifest = json.loads((private / "session_manifest.json").read_text())
        manifest["files"]["system.json"] = {
            "sha256": hashlib.sha256(raw).hexdigest(), "byte_count": len(raw),
        }
        if rewrite_identity:
            manifest["observation_ids"] = [
                row["observation_id"] for row in system["observations"]]
            manifest["counts"]["observations"] = len(system["observations"])
        (private / "session_manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

    def forge(self, sid, operation, *, raw=None, rewrite_identity=False):
        folder, original_manifest, original, _ = self.session(sid, raw)
        system = json.loads((folder / "private/system.json").read_text())
        operation(system)
        self.reseal_system(folder, system, rewrite_identity=rewrite_identity)
        self.assertEqual(
            (folder / original.private_relative_path).read_bytes(),
            FAMILIES[sid][0] if raw is None else raw)
        with self.assertRaises(CanonicalContractError):
            validate_canonical(folder)

    def test_47_01_independent_expected_values_for_four_sealed_d0_families(self):
        for sid, (raw, expected, parser_id) in FAMILIES.items():
            with self.subTest(source=sid):
                folder, manifest, artifact, observations = self.session(sid)
                typed = [row for row in observations
                         if row["transformation_ids"]]
                actual = [
                    (row["datum_path"], row["observed_value"],
                     row["normalized_value"], row["value_type"], row["unit"])
                    for row in typed
                ]
                self.assertEqual(actual, expected)
                self.assertEqual([row["ordinal"] for row in typed],
                                 list(range(len(expected))))
                self.assertTrue(all(
                    row["evidence_refs"] == [artifact.evidence_id]
                    and row["source_attempt_ids"] == [sid + "-01"]
                    and row["transformation_ids"] == [parser_id]
                    for row in typed))
                self.assertEqual(validate_canonical(folder), manifest)

    def test_47_02_rehashed_os_release_typed_value_forgery(self):
        def alter(system):
            next(r for r in system["observations"]
                 if r["datum_path"] == "os.release.ID")[
                     "normalized_value"] = "forged-os"
        self.forge("SRC-02", alter)

    def test_47_03_rehashed_meminfo_unit_converted_value_forgery(self):
        def alter(system):
            next(r for r in system["observations"]
                 if r["datum_path"] == "memory.meminfo.MemTotal")[
                     "normalized_value"] = 2097152
        self.forge("SRC-08", alter)

    def test_47_04_rehashed_swaps_array_entry_forgery(self):
        def alter(system):
            next(r for r in system["observations"]
                 if r["datum_path"] == "memory.swap.entries")[
                     "normalized_value"][0]["used_bytes"] = 32768
        self.forge("SRC-09", alter)

    def test_47_05_rehashed_psi_typed_metric_forgery(self):
        def alter(system):
            next(r for r in system["observations"]
                 if r["datum_path"] == "memory.pressure.some.avg10")[
                     "normalized_value"] = 9.5
        self.forge("SRC-10", alter)

    def test_47_06_rehashed_semantic_row_omission_and_identity_list(self):
        def alter(system):
            system["observations"] = [
                r for r in system["observations"]
                if r["datum_path"] != "os.release.NAME"]
        self.forge("SRC-02", alter, rewrite_identity=True)

    def test_47_07_rehashed_parser_identity_substitution(self):
        def alter(system):
            next(r for r in system["observations"]
                 if r["datum_path"] == "memory.meminfo.MemFree")[
                     "transformation_ids"] = ["unwitnessed-parser-v1"]
        self.forge("SRC-08", alter)

    def test_47_08_non_utf8_d0_original_is_lossless_not_false_semantics(self):
        raw = b"ID=ubuntu\nNAME=\xff\n"
        folder, manifest, original, observations = self.session("SRC-02", raw)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["value_type"], "BYTES_REF")
        self.assertEqual(observations[0]["observed_value"],
                         {"sealed_bytes_ref": original.evidence_id})
        self.assertFalse(observations[0]["transformation_ids"])
        self.assertEqual((folder / original.private_relative_path).read_bytes(),
                         raw)
        self.assertEqual(validate_canonical(folder), manifest)


if __name__ == "__main__":
    unittest.main()
