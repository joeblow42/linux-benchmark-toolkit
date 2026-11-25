"""Increment 49: sealed D1/O1 originals through D-02 to PRIVATE inventory.

Deterministic source receipts model normal, missing, malformed and partial
operational outcomes only. No real device, sudo, external command or public
publication. This development fixture is NOT host FAT or CP-02 acceptance.
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
LSBLK_CMD = "lsblk --bytes --json --output NAME,KNAME,TYPE,SIZE,RO,RM,MODEL,SERIAL,TRAN"
SMART_CMD = "smartctl -i -H /dev/sda"
INVENTORY_PATH = "/sys/class/block/sda/size"
LSBLK = (json.dumps({"blockdevices": [{
    "name": "sda", "kname": "sda", "type": "disk", "size": 10000,
    "ro": False, "rm": False, "model": "Example", "serial": "SERIAL-LOCAL",
    "tran": "sata",
}]}, sort_keys=True) + "\n").encode()
SMART = (b"smartctl 7.4\n=== START OF INFORMATION SECTION ===\n"
         b"Device Model:    Example Drive\nSerial Number: SERIAL-LOCAL\n"
         b"=== START OF READ SMART DATA SECTION ===\n"
         b"SMART overall-health self-assessment test result: PASSED\n")


class PrivateD1O1Integration49(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name) / RUN
        self.folder.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.folder), RUN)
        self.entries = []
        self.originals = []

    def add_source(self, sid, *, streams=(), outcome="CAPTURED",
                   reason="BYTES_PRESERVED", invocation="NOT_INVOKED",
                   target=None, source_paths=(), exit_code=None,
                   provenance=None, unavailable_fields=()):
        artifacts = []
        for artifact_name, raw in streams:
            item = self.writer.seal_chunks(
                POL[sid], "01", artifact_name, (raw,)).receipt
            self.assertIsNotNone(item)
            self.originals.append((item, raw))
            artifacts.append(item)
        receipt = build_attempt(
            RUN, sid, "01", "DENY" if outcome == "DENIED" else "ALLOW",
            outcome, reason, evidence=tuple(artifacts),
            bytes_count=sum(i.byte_count for i in artifacts),
            invocation=invocation, target=target,
            source_paths=source_paths, exit_code=exit_code,
            authorization_provenance=provenance,
            unavailable_fields=unavailable_fields)
        path = commit_attempt(str(self.folder), receipt)
        record = RecordedOutcome(
            SimpleNamespace(artifacts=tuple(artifacts)), path,
            authorization_provenance=provenance)
        self.entries.append((POL[sid].collector_id, record))
        return artifacts

    def d1(self, raw=LSBLK, *, outcome="CAPTURED",
           reason="BYTES_PRESERVED", exit_code=0, stderr=None,
           stdout=True, unavailable_fields=()):
        streams = []
        if stdout:
            streams.append(("call0001-stdout", raw))
        if stderr is not None:
            streams.append(("call0001-stderr", stderr))
        return self.add_source(
            "SRC-11", streams=streams, outcome=outcome,
            reason=reason, invocation=LSBLK_CMD, exit_code=exit_code,
            unavailable_fields=unavailable_fields)

    def o1(self, *, raw=SMART, partial=False):
        inventory = self.add_source(
            "SRC-12", streams=(("item0001", b"3907029168\n"),),
            source_paths=(INVENTORY_PATH,))
        issued = datetime.strptime(
            RUN[4:], "%Y%j%H%M%S").replace(tzinfo=timezone.utc)
        provenance = {
            "run_id": RUN, "source_id": "SRC-13",
            "operation_id": "DEVICE_HEALTH", "target": "/dev/sda",
            "consent_run_id": RUN, "consent_source_id": "SRC-13",
            "consent_operation_id": "DEVICE_HEALTH",
            "consent_target": "/dev/sda",
            "consent_issued_utc": issued.isoformat().replace("+00:00", "Z"),
            "impact_acknowledged": True,
            "inventory_source_id": "SRC-12",
            "inventory_source_path": INVENTORY_PATH,
            "inventory_evidence_id": inventory[0].evidence_id,
            "approved_argv": ["smartctl", "-i", "-H", "/dev/sda"],
        }
        self.add_source(
            "SRC-13", streams=(("call0001-stdout", raw),),
            outcome="PARTIAL" if partial else "CAPTURED",
            reason="ACQUISITION_ERROR" if partial else "BYTES_PRESERVED",
            invocation=SMART_CMD, target="/dev/sda",
            exit_code=2 if partial else 0, provenance=provenance)

    def consume(self):
        grouped = {}
        for collector, entry in self.entries:
            grouped.setdefault(collector, []).append(entry)
        run = EngineRun(RUN, tuple(
            CollectorRun(cid, tuple(rows)) for cid, rows in grouped.items()))
        with patch("subprocess.run", side_effect=AssertionError(
                "sealed evidence integration must not run a probe")):
            manifest = build_canonical(self.folder, run)
            self.assertEqual(validate_canonical(self.folder), manifest)
            view = read_private_inventory(self.folder)
        return view, manifest

    @staticmethod
    def source(view, sid):
        return next(row for row in view["source_outcomes"]
                    if row["source_id"] == sid)

    def test_49_01_d1_stdout_and_diagnostic_stderr_reach_consumer(self):
        self.d1(stderr=b"notice: local diagnostic\n")
        view, manifest = self.consume()
        source = self.source(view, "SRC-11")
        typed = [x for x in view["facts"]
                 if x["datum_path"] == "storage.lsblk.blockdevices"]
        self.assertEqual(len(typed), 1)
        self.assertEqual(typed[0]["normalized_value"][0]["size"], 10000)
        self.assertEqual(typed[0]["normalized_value"][0]["serial"],
                         "SERIAL-LOCAL")
        self.assertEqual((source["status"], source["reason_code"]),
                         ("COMPLETE", "OK"))
        self.assertEqual(source["authorization_class"], "D1")
        self.assertEqual(source["exit_code"], 0)
        self.assertEqual(source["semantic_fact_count"], 1)
        self.assertEqual(view["raw_original_observation_rows"], 2)
        self.assertEqual(manifest["counts"]["evidence_artifacts"], 2)
        self.assertEqual(view["completion_state"], "INCOMPLETE")
        for original, raw in self.originals:
            self.assertEqual((self.folder / original.private_relative_path).read_bytes(), raw)
            self.assertEqual(original.sha256, hashlib.sha256(raw).hexdigest())

    def test_49_02_d1_nonzero_preserves_typed_data_but_not_success(self):
        self.d1(outcome="PARTIAL", reason="EXIT_NONZERO", exit_code=2)
        view, _ = self.consume()
        source = self.source(view, "SRC-11")
        self.assertEqual((source["status"], source["reason_code"], source["exit_code"]),
                         ("PARTIAL", "SOURCE_INCOMPLETE", 2))
        typed = [x for x in view["facts"]
                 if x["datum_path"] == "storage.lsblk.blockdevices"]
        self.assertEqual(len(typed), 1)
        self.assertEqual((typed[0]["acquisition_status"],
                          typed[0]["acquisition_reason"]),
                         ("PARTIAL", "SOURCE_INCOMPLETE"))
        self.assertEqual(view["orchestration_status"], "PARTIAL")

    def test_49_03_d1_stderr_only_nonzero_is_not_hardware_inventory(self):
        self.d1(stderr=b"lsblk: could not read device\n",
                stdout=False, outcome="PARTIAL",
                reason="EXIT_NONZERO", exit_code=2)
        view, _ = self.consume()
        self.assertEqual(view["facts"], [])
        self.assertEqual(self.source(view, "SRC-11")["semantic_fact_count"], 0)
        self.assertEqual(self.source(view, "SRC-11")["reason_code"],
                         "SOURCE_INCOMPLETE")
        self.assertEqual(view["raw_original_observation_rows"], 1)

    def test_49_04_malformed_d1_stdout_is_a_parser_failure(self):
        self.d1(raw=b'{"blockdevices": not_json}\n')
        view, _ = self.consume()
        self.assertEqual(view["facts"], [])
        self.assertEqual((self.source(view, "SRC-11")["status"],
                          self.source(view, "SRC-11")["reason_code"]),
                         ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual(view["raw_original_observation_rows"], 1)

    def test_49_05_missing_d1_tool_is_not_reported_as_captured(self):
        self.d1(outcome="UNAVAILABLE", reason="EXECUTABLE_NOT_FOUND",
                exit_code=None, stdout=False,
                unavailable_fields=("lsblk command unavailable",))
        view, _ = self.consume()
        src = self.source(view, "SRC-11")
        self.assertEqual((src["status"], src["reason_code"], src["capture_bytes"]),
                         ("TOOL_MISSING", "EXECUTABLE_NOT_FOUND", 0))
        self.assertEqual(src["unavailable_fields"],
                         ["lsblk command unavailable"])
        self.assertIsNone(src["exit_code"])
        self.assertEqual(view["facts"], [])

    def test_49_06_o1_same_run_inventory_and_consent_reach_consumer(self):
        self.o1()
        view, _ = self.consume()
        src = self.source(view, "SRC-13")
        self.assertEqual((src["authorization_class"], src["status"],
                          src["reason_code"], src["exit_code"]),
                         ("O1", "COMPLETE", "OK", 0))
        values = {x["datum_path"]: x for x in view["facts"]}
        fact = values["storage.device_health.smartctl.reported_assessment"]
        self.assertEqual(fact["normalized_value"], "PASSED")
        self.assertEqual(fact["source_id"], "SRC-13")
        self.assertEqual(fact["acquisition_status"], "COMPLETE")
        self.assertFalse(any("health_verdict" in key for key in values))
        self.assertEqual(view["raw_original_observation_rows"], 2)
        self.assertEqual(view["completion_state"], "INCOMPLETE")
        rendered = json.dumps(view, sort_keys=True)
        for forbidden in ("receipt_private_path", "evidence_refs",
                          "private/evidence/", SMART_CMD, INVENTORY_PATH):
            self.assertNotIn(forbidden, rendered)

    def test_49_07_o1_nonzero_keeps_reported_text_and_partial_outcome(self):
        self.o1(partial=True)
        view, _ = self.consume()
        src = self.source(view, "SRC-13")
        self.assertEqual((src["status"], src["reason_code"], src["exit_code"]),
                         ("PARTIAL", "SOURCE_INCOMPLETE", 2))
        facts = [x for x in view["facts"] if x["source_id"] == "SRC-13"]
        self.assertTrue(facts)
        self.assertTrue(all(x["acquisition_status"] == "PARTIAL" for x in facts))
        self.assertTrue(all(x["acquisition_reason"] == "SOURCE_INCOMPLETE"
                            for x in facts))
        self.assertIn("PASSED", [x["normalized_value"] for x in facts])
        self.assertEqual(view["orchestration_status"], "PARTIAL")

    def test_49_08_denied_o1_without_inventory_remains_unobserved(self):
        self.add_source("SRC-13", streams=(), outcome="DENIED",
                        reason="OPERATOR_AUTH_REQUIRED")
        view, _ = self.consume()
        src = self.source(view, "SRC-13")
        self.assertEqual((src["authorization_decision"], src["status"],
                          src["reason_code"]),
                         ("DENY", "UNAUTHORIZED", "OPERATOR_AUTH_REQUIRED"))
        self.assertEqual(src["semantic_fact_count"], 0)
        self.assertEqual(view["facts"], [])
        self.assertEqual(view["sealed_original_artifact_count"], 0)


if __name__ == "__main__":
    unittest.main()
