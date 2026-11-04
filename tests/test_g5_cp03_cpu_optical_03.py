"""CP-03 increment 03 independently specified CPU and optical parser fixtures.

Fixtures use the documented Linux procfs formatting emitted unchanged by
the G5-02 static-file worker; only already-sealed bytes are normalized.
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
CPU = (b"processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Test CPU\n"
       b"physical id\t: 0\ncore id\t: 0\ncpu cores\t: 2\nsiblings\t: 4\n"
       b"cpu MHz\t\t: 1234.500\nflags\t\t: sse sse2 avx\n\n"
       b"processor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Test CPU\n"
       b"physical id\t: 0\ncore id\t: 0\ncpu cores\t: 2\nsiblings\t: 4\n"
       b"cpu MHz\t\t: 1222.250\nflags\t\t: sse sse2 avx\n")
CDROM = (b"CD-ROM information, Id:\tcdrom.c 3.20 2003/12/17\n\n"
         b"drive name:\t\tsr0\tsr1\n"
         b"drive speed:\t\t24\t16\n"
         b"drive # of slots:\t1\t1\n"
         b"Can close tray:\t\t1\t0\n"
         b"Can read DVD:\t\t1\t1\n"
         b"Can write DVD-R:\t0\t0\n")


class CpuOpticalParsers(unittest.TestCase):
    def test_cpuinfo_two_logical_processors_with_typed_parameters(self):
        result = normalize_sealed_source("SRC-06", CPU)
        self.assertEqual(result.parser_id, "linux-proc-cpuinfo-v1")
        self.assertEqual(len(result.values), 2)
        a, b = (datum.normalized_value for datum in result.values)
        self.assertEqual((a["processor"], b["processor"]), (0, 1))
        self.assertEqual(a["model_name"], "Test CPU")
        self.assertEqual(a["frequency_mhz"], 1234.5)
        self.assertEqual(a["cpu_cores"], 2)
        self.assertEqual(a["flags"], ["sse", "sse2", "avx"])
        self.assertEqual(result.values[0].value_type, "OBJECT")
        self.assertIn("vendor_id", result.values[0].observed_value)

    def test_cpuinfo_rejects_duplicate_processor_or_field(self):
        for raw in (
            CPU + b"\nprocessor: 0\n",
            b"processor: 0\nprocessor: 1\n",
            b"processor: not-an-integer\n",
            b"processor: 0\ncpu MHz: nan\n",
            b"processor: 0\ncpu MHz: 1e999\n",
            b"processor: 0\ninvalid line\n",
            b"vendor_id: GenuineIntel\n",
        ):
            with self.subTest(raw=raw[:45]), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-06", raw)

    def test_cpuinfo_one_processor_without_model_is_incomplete_not_fabricated(self):
        result = normalize_sealed_source("SRC-06", b"processor: 0\n")
        self.assertEqual(result.values[0].normalized_value, {"processor": 0})
        self.assertNotIn("model_name", result.values[0].normalized_value)

    def test_cdrom_two_drives_with_typed_capabilities(self):
        result = normalize_sealed_source("SRC-16", CDROM)
        self.assertEqual(result.parser_id, "linux-proc-cdrom-info-v1")
        data = result.values[0].normalized_value
        self.assertEqual(data["device_count"], 2)
        self.assertEqual(data["drives"][0]["name"], "sr0")
        self.assertEqual(data["drives"][1]["capabilities"]["drive speed"], 16)
        self.assertTrue(data["drives"][0]["capabilities"]["Can read DVD"])
        self.assertFalse(data["drives"][1]["capabilities"]["Can close tray"])

    def test_cdrom_no_drives_does_not_invent_hardware(self):
        raw = (b"CD-ROM information, Id:\tcdrom.c 3.20\n"
               b"drive name:\nCan read DVD:\n")
        result = normalize_sealed_source("SRC-16", raw)
        self.assertEqual(result.values[0].normalized_value,
                         {"device_count": 0, "drives": []})

    def test_cdrom_rejects_column_mismatch_and_duplicate_row(self):
        bad = (
            b"drive name: sr0 sr1\nCan read DVD: 1\n",
            b"drive name: sr0\nCan read DVD: 1\nCan read DVD: 0\n",
            b"drive name: sr0 sr0\nCan read DVD: 1 1\n",
            b"CD-ROM information, Id: old\nCan read DVD: 1\n",
            b"drive name: sr0\ninvalid row\n",
        )
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-16", raw)

    def test_registration_is_explicit_and_bounded(self):
        for source in ("SRC-06", "SRC-16"):
            self.assertTrue(parser_available(source))
        for source in ("SRC-05", "SRC-11", "SRC-26", "SRC-28"):
            self.assertFalse(parser_available(source))


class CpuOpticalIntegration(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name) / RUN
        self.folder.mkdir(mode=0o700)
        self.writer = EvidenceWriter(str(self.folder), RUN)
        self.policies = {p.source_id: p for p in initial_source_policies()}

    def capture(self, source, raw, owner):
        policy = self.policies[source]
        evidence = self.writer.seal_chunks(
            policy, "01", "item0001", (raw,)).receipt
        self.assertIsNotNone(evidence)
        attempt = build_attempt(
            RUN, source, "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=(evidence,), bytes_count=evidence.byte_count)
        location = commit_attempt(str(self.folder), attempt)
        rec = SimpleNamespace(
            outcome=SimpleNamespace(artifacts=(evidence,)),
            receipt_private_path=location)
        return CollectorRun(owner, (rec,)), evidence

    def test_cpu_canonical_trace_and_original_integrity(self):
        cpu, original = self.capture("SRC-06", CPU, "COL-CPU")
        manifest = build_canonical(self.folder, EngineRun(RUN, (cpu,)))
        self.assertEqual(manifest["observation_count"], 3)
        self.assertEqual(manifest["original_byte_count"], len(CPU))
        data = json.loads((self.folder / "private/system.json").read_text())
        for obs in data["observations"]:
            self.assertEqual(obs["evidence_refs"], [original.evidence_id])
            self.assertEqual(obs["source_attempt_ids"], ["SRC-06-01"])
        self.assertEqual(
            hashlib.sha256((self.folder / original.private_relative_path)
                           .read_bytes()).hexdigest(), original.sha256)
        self.assertEqual(validate_canonical(self.folder), manifest)

    def test_optical_canonical_does_not_conflate_capability_with_media_test(self):
        optical, original = self.capture("SRC-16", CDROM, "COL-OPTICAL")
        manifest = build_canonical(self.folder, EngineRun(RUN, (optical,)))
        self.assertEqual(manifest["observation_count"], 2)
        values = json.loads((self.folder / "private/system.json")
                            .read_text())["observations"]
        self.assertEqual(values[1]["normalized_value"]["device_count"], 2)
        self.assertNotIn("media_verified", values[1]["normalized_value"])
        self.assertEqual(values[1]["evidence_refs"], [original.evidence_id])
        self.assertEqual(validate_canonical(self.folder), manifest)


if __name__ == "__main__":
    unittest.main()
