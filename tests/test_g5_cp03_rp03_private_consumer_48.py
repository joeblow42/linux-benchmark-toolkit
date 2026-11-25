"""Increment 48: real sealed-source -> D-02 -> private factual consumer.

All sources are deterministic sealed test bytes, not host probes. This is
ordinary data/availability/incomplete-run integration, not hostile-edit
forgery testing and not physical FAT or public-report validation.
"""
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
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026320223348"
POL = {s.source_id: s for s in initial_source_policies()}


class PrivateInventoryIntegration48(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.run_dir = Path(temp.name) / RUN
        self.run_dir.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.run_dir), RUN)

    def source(self, sid, *, raw=None, denied=False):
        policy = POL[sid]
        originals = ()
        if not denied:
            assert isinstance(raw, bytes)
            item = self.writer.seal_chunks(
                policy, "01", "item0001", (raw,)).receipt
            self.assertIsNotNone(item)
            originals = (item,)
        receipt = build_attempt(
            RUN, sid, "01", "DENY" if denied else "ALLOW",
            "DENIED" if denied else "CAPTURED",
            "OPERATOR_AUTH_REQUIRED" if denied else "BYTES_PRESERVED",
            evidence=originals,
            bytes_count=sum(item.byte_count for item in originals),
        )
        path = commit_attempt(str(self.run_dir), receipt)
        return sid, SimpleNamespace(
            outcome=SimpleNamespace(artifacts=originals),
            receipt_private_path=path,
        )

    def produce(self, *sources):
        grouped = {}
        for sid, result in sources:
            grouped.setdefault(POL[sid].collector_id, []).append(result)
        run = EngineRun(RUN, tuple(
            CollectorRun(collector, tuple(items))
            for collector, items in grouped.items()
        ))
        manifest = build_canonical(self.run_dir, run)
        self.assertEqual(validate_canonical(self.run_dir), manifest)
        return read_private_inventory(self.run_dir)

    def test_48_01_two_real_sealed_sources_reach_private_consumer(self):
        os_source = self.source("SRC-02", raw=b'ID=ubuntu\nNAME="Ubuntu Linux"\n')
        mem_source = self.source("SRC-08", raw=b"MemTotal: 1024 kB\nMemFree: 128 kB\n")
        with patch("subprocess.run", side_effect=AssertionError("no new command")):
            view = self.produce(os_source, mem_source)
        data = {item["datum_path"]: item for item in view["facts"]}
        self.assertEqual(data["os.release.ID"]["normalized_value"], "ubuntu")
        self.assertEqual(data["os.release.NAME"]["normalized_value"], "Ubuntu Linux")
        self.assertEqual(data["memory.meminfo.MemTotal"]["normalized_value"], 1048576)
        self.assertEqual(data["memory.meminfo.MemTotal"]["unit"], "bytes")
        self.assertEqual(data["memory.meminfo.MemFree"]["normalized_value"], 131072)
        self.assertEqual(view["raw_original_observation_rows"], 2)
        self.assertEqual(view["sealed_original_artifact_count"], 2)
        self.assertEqual(len(view["source_outcomes"]), 2)
        self.assertTrue(all(s["status"] == "COMPLETE" for s in view["source_outcomes"]))
        self.assertEqual(view["completion_state"], "INCOMPLETE")
        self.assertEqual(view["lifecycle_state"], "INCOMPLETE")
        self.assertEqual(view["orchestration_status"], "PARTIAL")
        self.assertEqual(view["orchestration_reason"], "MINIMUM_WITH_GAPS")
        self.assertTrue(view["minimum_usable"])

    def test_48_02_denied_only_stays_truthfully_empty(self):
        view = self.produce(self.source("SRC-13", denied=True))
        self.assertEqual(view["facts"], [])
        self.assertEqual(view["raw_original_observation_rows"], 0)
        self.assertEqual(view["sealed_original_artifact_count"], 0)
        self.assertEqual(view["source_outcomes"][0]["status"], "UNAUTHORIZED")
        self.assertEqual(view["source_outcomes"][0]["reason_code"], "OPERATOR_AUTH_REQUIRED")
        self.assertEqual(view["source_outcomes"][0]["capture_bytes"], 0)
        self.assertEqual(view["completion_state"], "INCOMPLETE")
        self.assertEqual(view["orchestration_status"], "PARTIAL")
        self.assertTrue(view["minimum_usable"])

    def test_48_03_malformed_input_yields_parse_failure_not_a_fact(self):
        view = self.produce(self.source("SRC-02", raw=b"BROKEN_ASSIGNMENT\n"))
        self.assertEqual(view["facts"], [])
        self.assertEqual(view["raw_original_observation_rows"], 1)
        self.assertEqual(view["sealed_original_artifact_count"], 1)
        self.assertEqual(view["source_outcomes"][0]["status"], "PARTIAL")
        self.assertEqual(view["source_outcomes"][0]["reason_code"], "PARSE_FAILED")
        self.assertEqual(view["source_outcomes"][0]["semantic_fact_count"], 0)
        self.assertEqual(view["completion_state"], "INCOMPLETE")

    def test_48_04_ordinary_missing_canonical_file_blocks_consumption(self):
        self.produce(self.source("SRC-02", raw=b"ID=ubuntu\n"))
        (self.run_dir / "private" / "status_records.json").unlink()
        with self.assertRaises((CanonicalContractError, OSError)):
            read_private_inventory(self.run_dir)

    def test_48_05_no_private_evidence_or_command_pointers_in_intermediary(self):
        view = self.produce(self.source("SRC-02", raw=b"ID=ubuntu\n"))
        rendered = json.dumps(view, sort_keys=True)
        for forbidden in (
            "receipt_private_path", "restricted_relative_path",
            "source_attempt_ids", "evidence_refs", "obs:",
            "private/evidence/", "/etc/os-release",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(view["source_outcomes"][0]["semantic_fact_count"], 1)

    def test_48_06_incomplete_without_manifest_not_a_private_session(self):
        self.produce(self.source("SRC-08", raw=b"MemTotal: 1024 kB\n"))
        (self.run_dir / "private" / "session_manifest.json").unlink()
        with self.assertRaises((CanonicalContractError, OSError)):
            read_private_inventory(self.run_dir)


if __name__ == "__main__":
    unittest.main()
