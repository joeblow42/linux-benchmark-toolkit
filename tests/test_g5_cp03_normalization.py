"""CP-03 semantic parser behavioral tests independently covering CT-02/03/04/09.

No source execution occurs: fixtures supply only bytes as though already sealed.
A normalizer cannot claim success without a registered parser or proven facts.
"""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical, _status_for
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.normalization import (
    SourceParseError, normalize_sealed_source, parser_available
)
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"


class G504CP03PureParserTests(unittest.TestCase):
    def test_os_release_quoted_values_and_identity(self):
        parsed = normalize_sealed_source(
            "SRC-02", b'ID=ubuntu\nNAME="Ubuntu Linux"\nPRETTY_NAME="Ubuntu 22.04 LTS"\n')
        data = {v.datum_path: v for v in parsed.values}
        self.assertEqual(data["os.release.ID"].normalized_value, "ubuntu")
        self.assertEqual(data["os.release.PRETTY_NAME"].normalized_value,
                         "Ubuntu 22.04 LTS")
        self.assertEqual(data["os.release.NAME"].value_type, "STRING")

    def test_os_release_invalid_quotes_duplicate_or_missing_id(self):
        for raw in (
            b'ID="missing quote\n',
            b'ID=ubuntu\nID=fedora\n',
            b'NAME="Only name"\n',
            b'ID=ubuntu\nmalformed line\n',
        ):
            with self.subTest(raw=raw), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-02", raw)

    def test_meminfo_byte_units_and_count_units(self):
        parsed = normalize_sealed_source(
            "SRC-08", b"MemTotal: 8192 kB\nMemFree: 4096 kB\nHugePages_Total: 2\n")
        data = {x.datum_path: x for x in parsed.values}
        self.assertEqual(data["memory.meminfo.MemTotal"].normalized_value, 8388608)
        self.assertEqual(data["memory.meminfo.MemTotal"].unit, "bytes")
        self.assertEqual(data["memory.meminfo.HugePages_Total"].normalized_value, 2)
        self.assertEqual(data["memory.meminfo.HugePages_Total"].unit, "count")

    def test_meminfo_malformed_or_missing_memtotal_fails(self):
        for raw in (b"MemFree: 20 kB\n", b"MemTotal: nonsense kB\n",
                    b"MemTotal: 1 kB\nMemTotal: 2 kB\n"):
            with self.subTest(raw=raw), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-08", raw)

    def test_swaps_empty_and_mounted(self):
        header = b"Filename\tType\tSize\tUsed\tPriority\n"
        empty = normalize_sealed_source("SRC-09", header)
        self.assertEqual(empty.values[0].normalized_value, [])
        active = normalize_sealed_source(
            "SRC-09", header + b"/swapfile\tfile\t100\t30\t-2\n")
        data = active.values[0].normalized_value[0]
        self.assertEqual(data["used_bytes"], 30 * 1024)
        self.assertEqual(data["size_bytes"], 100 * 1024)
        self.assertEqual(data["priority"], -2)
        with self.assertRaises(SourceParseError):
            normalize_sealed_source("SRC-09", header + b"/swapfile file 1 5 -2\n")

    def test_memory_psi_metrics_are_numeric_and_units_are_truthful(self):
        parsed = normalize_sealed_source(
            "SRC-10", b"some avg10=0.03 avg60=0.05 avg300=0.10 total=1234\n"
                      b"full avg10=0.00 avg60=0.00 avg300=0.01 total=100\n")
        data = {v.datum_path: v for v in parsed.values}
        self.assertEqual(data["memory.pressure.some.total"].normalized_value, 1234)
        self.assertEqual(data["memory.pressure.some.total"].unit, "microseconds")
        self.assertEqual(data["memory.pressure.some.avg10"].normalized_value, 0.03)
        self.assertEqual(data["memory.pressure.some.avg10"].unit, "percent")
        for invalid in (b"some avg10=nan avg60=0 avg300=0 total=3\n",
                        b"some avg10=0 avg60=0 avg300=0\n",
                        b"some avg10=101 avg60=0 avg300=0 total=3\n"):
            with self.subTest(raw=invalid), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-10", invalid)

    def test_excessive_numeric_inputs_produce_bounded_parser_error(self):
        cases = (
            ("SRC-08", b"MemTotal: " + b"9" * 5000 + b" kB\n"),
            ("SRC-09", b"Filename Type Size Used Priority\n/swap file " +
             b"9" * 5000 + b" 0 1\n"),
            ("SRC-10", b"some avg10=0 avg60=0 avg300=0 total=" +
             b"9" * 5000 + b"\n"),
        )
        for source, raw in cases:
            with self.subTest(source=source), self.assertRaises(SourceParseError):
                normalize_sealed_source(source, raw)

    def test_unknown_source_fails_closed_and_never_fakes_parser_failure(self):
        self.assertFalse(parser_available("SRC-15"))
        self.assertIsNone(normalize_sealed_source("SRC-15", b"arbitrary host bytes"))
        with self.assertRaises(CanonicalContractError):
            _status_for({"outcome": "CAPTURED", "reason": "BYTES_PRESERVED"},
                        [object()])
        with self.assertRaises(CanonicalContractError):
            _status_for({"outcome": "FAILED", "reason": "UNRECOGNIZED_TRANSPORT"},
                        [])

    def test_unknown_partial_and_unavailable_reasons_fail_closed(self):
        with self.assertRaises(CanonicalContractError):
            _status_for({"outcome": "PARTIAL",
                         "reason": "UNRECOGNIZED_REASON",
                         "capture_limited": False}, [object()],
                        parser_state="OK")
        with self.assertRaises(CanonicalContractError):
            _status_for({"outcome": "UNAVAILABLE",
                         "reason": "WORKER_NOT_FOUND"}, [])
        self.assertEqual(
            _status_for({"outcome": "UNAVAILABLE",
                         "reason": "EXECUTABLE_NOT_FOUND"}, []),
            ("TOOL_MISSING", "EXECUTABLE_NOT_FOUND"))

    def test_proved_parser_error_not_the_same_as_parser_absent(self):
        receipt = {"outcome": "CAPTURED", "reason": "BYTES_PRESERVED"}
        self.assertEqual(_status_for(receipt, [object()], parser_state="FAILED"),
                         ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual(_status_for(receipt, [object()], parser_state="OK"),
                         ("COMPLETE", "OK"))
        with self.assertRaises(CanonicalContractError):
            _status_for(receipt, [object()], parser_state="NOT_RUN")


class G504CP03CanonicalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Path(self.temp.name) / RUN
        self.run.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.run), RUN)
        self.policies = {p.source_id: p for p in initial_source_policies()}

    def saved(self, sid, raw, *, outcome="CAPTURED", reason="BYTES_PRESERVED"):
        policy = self.policies[sid]
        item = self.writer.seal_chunks(policy, "01", "item0001", (raw,)).receipt
        self.assertIsNotNone(item)
        receipt = build_attempt(
            RUN, sid, "01", "ALLOW", outcome, reason,
            evidence=(item,), bytes_count=item.byte_count)
        path = commit_attempt(str(self.run), receipt)
        record = SimpleNamespace(
            outcome=SimpleNamespace(artifacts=(item,)), receipt_private_path=path)
        return record, item

    def test_real_parser_error_requires_fallback_and_hash_verified_provenance(self):
        raw = b"ID=ubuntu\nnot-an-assignment\n"
        saved, original = self.saved("SRC-02", raw)
        engine_run = EngineRun(RUN, (CollectorRun("COL-OS", (saved,)),))
        manifest = build_canonical(self.run, engine_run)
        self.assertEqual(manifest["observation_count"], 1)
        self.assertEqual(validate_canonical(self.run), manifest)
        system = json.loads((self.run / "private/system.json").read_text())
        obs = system["observations"][0]
        self.assertIn("PARSER_FAILED:OS_RELEASE_MALFORMED_ASSIGNMENT",
                      obs["parser_findings"])
        self.assertEqual(obs["observed_value"], raw.decode("utf-8"))
        self.assertEqual(obs["evidence_refs"], [original.evidence_id])
        status = json.loads((self.run / "private/status_records.json").read_text())
        self.assertEqual(status["status_records"][0]["reason_code"], "PARSE_FAILED")
        self.assertIn("OS_RELEASE_MALFORMED_ASSIGNMENT",
                      status["status_records"][0]["detail"])
        preserved = self.run / original.private_relative_path
        self.assertEqual(hashlib.sha256(preserved.read_bytes()).hexdigest(), original.sha256)

    def test_unsupported_captured_source_does_not_commit_final_manifest(self):
        saved, original = self.saved("SRC-15", b"unrecognized semantic source")
        run = EngineRun(RUN, (CollectorRun("COL-FS", (saved,)),))
        with self.assertRaises(CanonicalContractError):
            build_canonical(self.run, run)
        self.assertFalse((self.run / "private/session_manifest.json").exists())
        self.assertEqual((self.run / original.private_relative_path).read_bytes(),
                         b"unrecognized semantic source")

    def test_semantic_observations_each_cite_sealed_contributor_and_status(self):
        saved, original = self.saved("SRC-08", b"MemTotal: 1024 kB\nMemFree: 128 kB\n")
        engine_run = EngineRun(RUN, (CollectorRun("COL-MEM", (saved,)),))
        manifest = build_canonical(self.run, engine_run)
        self.assertEqual(manifest["observation_count"], 3)
        sys = json.loads((self.run / "private/system.json").read_text())
        for obs in sys["observations"]:
            self.assertEqual(obs["evidence_refs"], [original.evidence_id])
            self.assertEqual(obs["source_attempt_ids"], ["SRC-08-01"])
            self.assertEqual(obs["status_record_id"], "st:SRC-08-01")
        self.assertEqual(validate_canonical(self.run), manifest)


if __name__ == "__main__":
    unittest.main()
