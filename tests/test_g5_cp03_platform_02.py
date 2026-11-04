"""CP-03 increment 02 independent D0 platform, firmware and tools fixtures.

The test oracle is the G5-02 passive worker output contract, not a
reconstruction of the production parser. No device or network probes.
"""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.normalization import (
    SourceParseError, normalize_sealed_source, parser_available,
)
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"


class PlatformParserTests(unittest.TestCase):
    def test_platform_api_three_required_fields(self):
        raw = b'{"machine":"x86_64","release":"6.2.0-26-generic","system":"Linux"}'
        result = normalize_sealed_source("SRC-01", raw)
        by_path = {item.datum_path: item for item in result.values}
        self.assertEqual(result.parser_id, "linux-platform-api-v1")
        self.assertEqual(len(by_path), 3)
        self.assertEqual(by_path["os.kernel.machine"].normalized_value, "x86_64")
        self.assertEqual(by_path["os.kernel.release"].normalized_value,
                         "6.2.0-26-generic")
        self.assertEqual(by_path["os.kernel.system"].normalized_value, "Linux")

    def test_platform_rejects_extra_missing_wrong_types_and_duplicate_keys(self):
        for raw in (
            b'{"system":"Linux","machine":"x86_64"}',
            b'{"system":"Linux","machine":"x86_64","release":"1","extra":true}',
            b'{"system":"Windows","machine":"x86_64","release":"1"}',
            b'{"system":"Linux","system":"Linux","machine":"x86_64","release":"1"}',
            b'{"system":"Linux","machine":false,"release":"1"}',
            b'{"system":"Linux","machine":"x86_64","release":NaN}',
        ):
            with self.subTest(raw=raw), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-01", raw)

    def test_efi_presence_exact_markers(self):
        self.assertTrue(normalize_sealed_source("SRC-03", b"present\n")
                        .values[0].normalized_value)
        self.assertFalse(normalize_sealed_source("SRC-03", b"absent\n")
                         .values[0].normalized_value)
        for bad in (b"present", b"Present\n", b"unknown\n", b"\x00absent\n", b""):
            with self.subTest(bad=bad), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-03", bad)

    def test_tool_resolver_available_and_missing(self):
        available = normalize_sealed_source(
            "SRC-27", b'{"path":"/usr/bin/lscpu","tool":"lscpu"}')
        missing = normalize_sealed_source(
            "SRC-27", b'{"path":null,"tool":"nvme"}')
        self.assertEqual(available.values[0].datum_path,
                         "tools.resolution.lscpu")
        self.assertEqual(available.values[0].normalized_value,
                         {"available": True, "resolved_path": "/usr/bin/lscpu"})
        self.assertEqual(missing.values[0].normalized_value,
                         {"available": False, "resolved_path": None})

    def test_tool_resolver_rejects_unregistered_path_and_wrong_identity(self):
        for raw in (
            b'{"tool":"curl","path":"/usr/bin/curl"}',
            b'{"tool":"lscpu","path":"/tmp/lscpu"}',
            b'{"tool":"lscpu","path":"/usr/bin/../bin/lscpu"}',
            b'{"tool":"lscpu","path":"/usr/bin/nested/lscpu"}',
            b'{"tool":"lscpu","path":"/usr/bin//lscpu"}',
            b'{"tool":"lscpu","path":"../../etc/passwd"}',
            b'{"tool":"lsblk","path":"/usr/bin/lscpu"}',
            b'{"tool":"nvme","path":false}',
            b'{"tool":"nvme","path":null,"foo":"bar"}',
            b'{"tool":"nvme","tool":"nvme","path":null}',
        ):
            with self.subTest(raw=raw), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-27", raw)

    def test_parser_registration_is_bounded_to_declared_sources(self):
        for sid in ("SRC-01", "SRC-03", "SRC-27"):
            self.assertTrue(parser_available(sid))
        for sid in ("SRC-11", "SRC-13", "SRC-14", "SRC-28"):
            self.assertFalse(parser_available(sid))


class PlatformCanonicalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / RUN
        self.folder.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.folder), RUN)
        self.policies = {p.source_id: p for p in initial_source_policies()}

    def _record(self, sid, raw, attempt="01"):
        policy = self.policies[sid]
        receipt = self.writer.seal_chunks(
            policy, attempt, "item0001", (raw,)).receipt
        self.assertIsNotNone(receipt)
        source_receipt = build_attempt(
            RUN, sid, attempt, "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=(receipt,), bytes_count=receipt.byte_count)
        location = commit_attempt(str(self.folder), source_receipt)
        recorded = SimpleNamespace(
            outcome=SimpleNamespace(artifacts=(receipt,)),
            receipt_private_path=location)
        return recorded, receipt

    def test_platform_and_efi_originals_both_retained_and_typed(self):
        a, a_original = self._record("SRC-01",
            b'{"machine":"x86_64","release":"6.2","system":"Linux"}')
        b, b_original = self._record("SRC-03", b"present\n")
        run = EngineRun(RUN, (CollectorRun("COL-OS", (a, b)),))
        manifest = build_canonical(self.folder, run)
        self.assertEqual(manifest["attempt_count"], 2)
        self.assertEqual(manifest["observation_count"], 6)
        self.assertEqual(validate_canonical(self.folder), manifest)
        data = json.loads((self.folder / "private/system.json").read_text())
        known = {x["datum_path"]: x for x in data["observations"]}
        self.assertTrue(known["firmware.efi.present"]["normalized_value"])
        self.assertEqual(known["os.kernel.system"]["normalized_value"], "Linux")
        for original in (a_original, b_original):
            sealed = (self.folder / original.private_relative_path).read_bytes()
            self.assertEqual(hashlib.sha256(sealed).hexdigest(), original.sha256)

    def test_tool_resolver_distinct_same_source_evidence_refs(self):
        # SRC-27 yields one independently sealed record per tool; source-level
        # status is supported only if every record parsed.
        policy = self.policies["SRC-27"]
        receipts = tuple(
            self.writer.seal_chunks(policy, "01", "item%04d" % i, (raw,)).receipt
            for i, raw in enumerate((
                b'{"tool":"lscpu","path":"/usr/bin/lscpu"}',
                b'{"tool":"nvme","path":null}',
            ), 1))
        self.assertTrue(all(receipts))
        saved = build_attempt(
            RUN, "SRC-27", "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=receipts, bytes_count=sum(x.byte_count for x in receipts))
        path = commit_attempt(str(self.folder), saved)
        rec = SimpleNamespace(outcome=SimpleNamespace(artifacts=receipts),
                              receipt_private_path=path)
        manifest = build_canonical(
            self.folder, EngineRun(RUN, (CollectorRun("COL-TOOLS", (rec,)),)))
        self.assertEqual(manifest["observation_count"], 4)
        observations = json.loads((self.folder / "private/system.json")
                                  .read_text())["observations"]
        fields = {v["datum_path"]: v for v in observations}
        self.assertEqual(fields["tools.resolution.nvme"]["normalized_value"]
                         ["available"], False)
        self.assertNotEqual(fields["tools.resolution.nvme"]["evidence_refs"],
                            fields["tools.resolution.lscpu"]["evidence_refs"])
        self.assertEqual(validate_canonical(self.folder), manifest)


if __name__ == "__main__":
    unittest.main()
