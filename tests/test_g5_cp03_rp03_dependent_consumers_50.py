"""Increment 50: private consumer integration for dependent D1 and O1 facts.

Sealed source bytes, approved existing receipts and D-02 producer/validator
only; no device/driver execution, network, privilege or public publication.
"""
from datetime import datetime, timezone
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
from lbt_g5.private_inventory import read_private_inventory
from lbt_g5.receipt_dispatch import RecordedOutcome
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026320223348"
POL = {p.source_id: p for p in initial_source_policies()}
MOUNTINFO = b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
STAT = {
    "mount": "/", "fragment_size": 4096, "block_size": 4096,
    "blocks": 100, "free_blocks": 30, "available_blocks": 20,
    "files": 1000, "free_files": 900,
}
STAT_BYTES = (json.dumps(STAT, sort_keys=True, separators=(",", ":")) + "\n").encode()
GPU_PATH = "/sys/class/drm/card0/device/vendor"
VA_TARGET = "/dev/dri/renderD128"
VA_ARGV = ["vainfo", "--display", "drm", "--device", VA_TARGET]
VA_BYTES = (b"Trying display: drm\n"
            b"vainfo: VA-API version: 1.14 (libva 2.12.0)\n"
            b"vainfo: Driver version: Mesa Gallium 23.2.1\n"
            b"vainfo: Supported profile and entrypoints\n"
            b"      VAProfileMPEG2Simple            : VAEntrypointVLD\n"
            b"      VAProfileH264Main               : VAEntrypointEncSlice\n"
            b"      VAProfileNone                   : VAEntrypointVideoProc\n")


class DependentSourceConsumer50(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name) / RUN
        self.folder.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.folder), RUN)
        self.records = []
        self.originals = []

    def add(self, sid, *, streams=(), paths=(),
            invocation="NOT_INVOKED", target=None, provenance=None,
            outcome="CAPTURED", reason="BYTES_PRESERVED", exit_code=None):
        sealed = []
        for name, raw in streams:
            item = self.writer.seal_chunks(
                POL[sid], "01", name, (raw,)).receipt
            self.assertIsNotNone(item)
            self.originals.append((item, raw))
            sealed.append(item)
        receipt = build_attempt(
            RUN, sid, "01", "DENY" if outcome == "DENIED" else "ALLOW",
            outcome, reason, evidence=tuple(sealed),
            bytes_count=sum(x.byte_count for x in sealed),
            invocation=invocation, target=target, source_paths=paths,
            authorization_provenance=provenance, exit_code=exit_code)
        path = commit_attempt(str(self.folder), receipt)
        result = RecordedOutcome(
            SimpleNamespace(artifacts=tuple(sealed)), path,
            authorization_provenance=provenance)
        self.records.append((POL[sid].collector_id, result))
        return sealed

    def fsstat(self, *, include_mount=True, stat_bytes=STAT_BYTES):
        if include_mount:
            self.add("SRC-14", streams=(("item0001", MOUNTINFO),),
                     paths=("/proc/self/mountinfo",), invocation="MOUNTINFO")
        self.add("SRC-15",
                 streams=(("call0001-stdout", stat_bytes),),
                 paths=("/:stdout",), invocation="FS_STAT")

    def vaapi(self, *, raw=VA_BYTES, partial=False):
        inventory = self.add(
            "SRC-19", streams=(("item0001", b"0x8086\n"),),
            paths=(GPU_PATH,), invocation="DRM_PCI_SYSFS")
        issued = datetime.strptime(
            RUN[4:], "%Y%j%H%M%S").replace(tzinfo=timezone.utc)
        proof = {
            "run_id": RUN, "source_id": "SRC-21",
            "operation_id": "VAINFO", "target": VA_TARGET,
            "consent_run_id": RUN, "consent_source_id": "SRC-21",
            "consent_operation_id": "VAINFO",
            "consent_target": VA_TARGET,
            "consent_issued_utc": issued.isoformat().replace("+00:00", "Z"),
            "impact_acknowledged": True,
            "inventory_source_id": "SRC-19",
            "inventory_source_path": GPU_PATH,
            "inventory_evidence_id": inventory[0].evidence_id,
            "approved_argv": VA_ARGV,
        }
        self.add("SRC-21",
                 streams=(("call0001-stdout", raw),),
                 invocation=" ".join(VA_ARGV), target=VA_TARGET,
                 provenance=proof,
                 outcome="PARTIAL" if partial else "CAPTURED",
                 reason="ACQUISITION_ERROR" if partial else "BYTES_PRESERVED",
                 exit_code=2 if partial else 0)

    def engine(self):
        groups = {}
        for collector, recorded in self.records:
            groups.setdefault(collector, []).append(recorded)
        return EngineRun(RUN, tuple(
            CollectorRun(cid, tuple(entries))
            for cid, entries in groups.items()))

    def consume(self):
        with patch("subprocess.run", side_effect=AssertionError(
                "source-to-consumer fixture must not run commands")):
            manifest = build_canonical(self.folder, self.engine())
            self.assertEqual(validate_canonical(self.folder), manifest)
            result = read_private_inventory(self.folder)
        return result, manifest

    @staticmethod
    def source(view, sid):
        return next(x for x in view["source_outcomes"] if x["source_id"] == sid)

    def test_50_01_fs_stat_keeps_same_run_mountinfo_support(self):
        self.fsstat()
        view, manifest = self.consume()
        facts = [f for f in view["facts"]
                 if f["datum_path"] == "storage.fs_stat.snapshot"]
        self.assertEqual(len(facts), 1)
        fact = facts[0]
        self.assertEqual(fact["source_id"], "SRC-15")
        self.assertEqual(fact["supporting_source_ids"], ["SRC-14"])
        self.assertEqual(fact["value_type"], "OBJECT")
        self.assertEqual(fact["normalized_value"], STAT)
        self.assertEqual(fact["acquisition_status"], "COMPLETE")
        self.assertEqual(self.source(view, "SRC-14")["reason_code"], "OK")
        self.assertEqual(self.source(view, "SRC-15")["reason_code"], "OK")
        self.assertEqual(view["raw_original_observation_rows"], 2)
        self.assertEqual(manifest["counts"]["evidence_artifacts"], 2)
        self.assertEqual(view["completion_state"], "INCOMPLETE")
        for art, raw in self.originals:
            self.assertEqual((self.folder / art.private_relative_path).read_bytes(), raw)
            self.assertEqual(art.sha256, hashlib.sha256(raw).hexdigest())

    def test_50_02_missing_mountinfo_selection_blocks_fs_stat_claim(self):
        self.fsstat(include_mount=False)
        with patch("subprocess.run", side_effect=AssertionError("no probe")):
            with self.assertRaises(CanonicalContractError):
                build_canonical(self.folder, self.engine())
        self.assertFalse((self.folder / "private/session_manifest.json").exists())

    def test_50_03_malformed_fs_stat_stays_lossless_not_typed(self):
        self.fsstat(stat_bytes=b"not-json\n")
        view, _ = self.consume()
        self.assertFalse(any(f["datum_path"] == "storage.fs_stat.snapshot"
                             for f in view["facts"]))
        src = self.source(view, "SRC-15")
        self.assertEqual((src["status"], src["reason_code"],
                          src["semantic_fact_count"]),
                         ("PARTIAL", "PARSE_FAILED", 0))
        self.assertEqual(view["raw_original_observation_rows"], 2)

    def test_50_04_o1_vaapi_reported_profiles_are_not_benchmarks(self):
        self.vaapi()
        view, _ = self.consume()
        src = self.source(view, "SRC-21")
        self.assertEqual((src["authorization_class"], src["status"],
                          src["reason_code"], src["exit_code"]),
                         ("O1", "COMPLETE", "OK", 0))
        facts = [f for f in view["facts"]
                 if f["datum_path"] == "gpu.vaapi.reported_capabilities"]
        self.assertEqual(len(facts), 1)
        reported = facts[0]["normalized_value"]
        self.assertEqual(reported["va_api_version"], "1.14 (libva 2.12.0)")
        self.assertEqual(reported["profile_entrypoints"][1],
                         {"profile": "VAProfileH264Main",
                          "entrypoint": "VAEntrypointEncSlice"})
        self.assertEqual(facts[0]["source_id"], "SRC-21")
        self.assertEqual(self.source(view, "SRC-19")["status"], "COMPLETE")
        self.assertFalse(any("benchmark" in x["datum_path"]
                             for x in view["facts"]))
        self.assertEqual(view["completion_state"], "INCOMPLETE")

    def test_50_05_o1_partial_keeps_capability_text_qualified(self):
        self.vaapi(partial=True)
        view, _ = self.consume()
        src = self.source(view, "SRC-21")
        self.assertEqual((src["status"], src["reason_code"], src["exit_code"]),
                         ("PARTIAL", "SOURCE_INCOMPLETE", 2))
        capabilities = next(f for f in view["facts"]
                            if f["datum_path"] == "gpu.vaapi.reported_capabilities")
        self.assertEqual((capabilities["acquisition_status"],
                          capabilities["acquisition_reason"]),
                         ("PARTIAL", "SOURCE_INCOMPLETE"))
        self.assertEqual(capabilities["normalized_value"]["profile_entrypoints"][1]
                         ["profile"], "VAProfileH264Main")
        self.assertEqual(view["orchestration_status"], "PARTIAL")

    def test_50_06_absent_vaapi_device_has_no_unsupported_capabilities(self):
        self.add("SRC-21", outcome="UNAVAILABLE",
                 reason="NO_RELEVANT_DEVICE")
        view, _ = self.consume()
        src = self.source(view, "SRC-21")
        self.assertEqual((src["status"], src["reason_code"],
                          src["semantic_fact_count"]),
                         ("NOT_APPLICABLE", "NO_RELEVANT_DEVICE", 0))
        self.assertEqual(view["facts"], [])
        self.assertEqual(view["sealed_original_artifact_count"], 0)

    def test_50_07_malformed_vaapi_original_is_not_a_capability_fact(self):
        self.vaapi(raw=b"vainfo: Supported profile and entrypoints\nBroken\n")
        view, _ = self.consume()
        src = self.source(view, "SRC-21")
        self.assertEqual((src["status"], src["reason_code"]),
                         ("PARTIAL", "PARSE_FAILED"))
        self.assertFalse(any(f["datum_path"] == "gpu.vaapi.reported_capabilities"
                             for f in view["facts"]))
        self.assertEqual(view["raw_original_observation_rows"], 2)

    def test_50_08_no_restricted_original_identifiers_in_private_view(self):
        self.fsstat()
        view, _ = self.consume()
        rendered = json.dumps(view, sort_keys=True)
        for forbidden in (
            "private/evidence/", "receipt_private_path",
            "evidence_refs", "source_attempt_ids",
            "/proc/self/mountinfo", "/:stdout",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(self.source(view, "SRC-15")["semantic_fact_count"], 1)


if __name__ == "__main__":
    unittest.main()
