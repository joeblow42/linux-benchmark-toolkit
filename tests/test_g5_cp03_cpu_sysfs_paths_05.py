"""SRC-07 source-first oracle fixtures: approved CPU sysfs scope and original order.

Independent expected results specified before this implementation at
verification/g5_04/cp03_cpu_sysfs_oracle_05.json. These tests do not prove
full canonical schema conformance or CP-06 host verification.
"""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.normalization import (
    SourceParseError, normalize_sealed_source, parser_available,
    cpu_sysfs_path_identity,
)
from lbt_g5.passive_worker import ATTRS, CPU_ROOT, ROOTS
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
ROOT = "/sys/devices/system/cpu/"
ROOT_FIELDS = ("online", "possible", "present")
CPU_FIELDS = (
    "topology/core_id", "topology/physical_package_id",
    "topology/thread_siblings_list", "topology/core_siblings_list",
    "online", "cpufreq/scaling_cur_freq", "cpufreq/cpuinfo_max_freq",
    "cpufreq/scaling_min_freq", "cpufreq/scaling_max_freq",
)


class CpuSysfsSourceFirstOracles(unittest.TestCase):
    @contextmanager
    def captured(self, originals, paths, *, names=None, unavailable=(),
                 corrupt_run=False):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / RUN
            folder.mkdir(mode=0o700)
            writer = EvidenceWriter(str(folder), RUN)
            policy = {x.source_id: x for x in initial_source_policies()}["SRC-07"]
            if names is None:
                names = ["item" + format(i, "04d")
                         for i in range(1, len(originals) + 1)]
            self.assertEqual(len(names), len(originals))
            artifacts = []
            for name, raw in zip(names, originals):
                receipt = writer.seal_chunks(policy, "01", name, (raw,)).receipt
                self.assertIsNotNone(receipt)
                artifacts.append(receipt)
            attempt = build_attempt(
                RUN, "SRC-07", "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
                evidence=artifacts,
                bytes_count=sum(x.byte_count for x in artifacts),
                source_paths=paths, unavailable_fields=unavailable)
            receipt_path = commit_attempt(str(folder), attempt)
            if corrupt_run:
                artifacts[0] = replace(artifacts[0],
                                       run_id="run-2026305120001")
            recorded = SimpleNamespace(
                receipt_private_path=receipt_path,
                outcome=SimpleNamespace(artifacts=tuple(artifacts)))
            engine = EngineRun(RUN, (CollectorRun("COL-CPU", (recorded,)),))
            yield folder, engine, tuple(artifacts)

    def test_fixed_path_contract_matches_worker(self):
        self.assertEqual(ROOTS["SRC-07"], ROOT.rstrip("/"))
        self.assertEqual(tuple(sorted(CPU_ROOT)), ROOT_FIELDS)
        self.assertEqual(ATTRS["SRC-07"], CPU_FIELDS)
        self.assertTrue(parser_available("SRC-07"))
        self.assertFalse(parser_available("SRC-12"))

    def test_root_ranges_core_id_and_khz_have_separate_original_bindings(self):
        paths = (ROOT + "online", ROOT + "cpu0/topology/core_id",
                 ROOT + "cpu0/cpufreq/scaling_cur_freq")
        originals = (b"0-1,4\n", b"2\n", b"1400000\n")
        with self.captured(originals, paths) as (folder, engine, artifacts):
            manifest = build_canonical(folder, engine)
            self.assertEqual(manifest["observation_count"], 6)
            self.assertEqual(validate_canonical(folder), manifest)
            obs = json.loads((folder / "private/system.json").read_text())["observations"]
            typed = [x for x in obs if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in typed], [
                "cpu.sysfs.global.online",
                "cpu.sysfs.cpu0.topology.core_id",
                "cpu.sysfs.cpu0.cpufreq.scaling_cur_freq",
            ])
            self.assertEqual(typed[0]["normalized_value"],
                             {"ranges": [[0, 1], [4, 4]]})
            self.assertEqual(typed[1]["normalized_value"], 2)
            self.assertEqual(typed[2]["normalized_value"], 1400000)
            self.assertEqual(typed[2]["unit"], "kHz")
            for original, datum, raw in zip(artifacts, typed, originals):
                self.assertEqual(datum["evidence_refs"], [original.evidence_id])
                self.assertEqual(datum["source_attempt_ids"], ["SRC-07-01"])
                self.assertEqual((folder / original.private_relative_path).read_bytes(), raw)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), original.sha256)

    def test_lexicographic_cpu_directory_order_not_numeric(self):
        paths = (ROOT + "cpu10/topology/core_id",
                 ROOT + "cpu2/topology/core_id")
        with self.captured((b"10\n", b"2\n"), paths) as (folder, engine, artifacts):
            build_canonical(folder, engine)
            observations = json.loads((folder / "private/system.json").read_text())["observations"]
            sem = [x for x in observations if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in sem], [
                "cpu.sysfs.cpu10.topology.core_id",
                "cpu.sysfs.cpu2.topology.core_id",
            ])
            self.assertEqual([x["normalized_value"] for x in sem], [10, 2])

    def test_optional_missing_cpufreq_is_not_fabricated(self):
        with self.captured(
            (b"0-3\n",), (ROOT + "possible",),
            unavailable=("FileNotFoundError[2]:" + ROOT +
                         "cpu0/cpufreq/scaling_cur_freq",)
        ) as (folder, engine, artifact):
            build_canonical(folder, engine)
            observations = json.loads((folder / "private/system.json").read_text())["observations"]
            sem = [x for x in observations if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in sem],
                             ["cpu.sysfs.global.possible"])
            attempt = json.loads((folder / "private/source_attempts.json").read_text())
            self.assertEqual(len(attempt["attempts"][0]["unavailable_fields"]), 1)

    def test_worker_order_item_ordinal_duplicate_count_and_root_after_cpu_fail(self):
        scenarios = (
            ((b"A\n",), (), None),
            ((b"A\n",), (ROOT + "online", ROOT + "possible"), None),
            ((b"1\n", b"0\n"), (ROOT + "possible", ROOT + "online"), None),
            ((b"1\n", b"0\n"), (ROOT + "online", ROOT + "online"), None),
            ((b"1\n", b"0\n"),
             (ROOT + "cpu2/topology/core_id", ROOT + "cpu10/topology/core_id"), None),
            ((b"1\n", b"0\n"),
             (ROOT + "cpu0/cpufreq/scaling_cur_freq",
              ROOT + "cpu0/topology/core_id"), None),
            ((b"1\n", b"0\n"),
             (ROOT + "cpu0/topology/core_id", ROOT + "possible"), None),
            ((b"1\n",), (ROOT + "online",), ("item0002",)),
        )
        for values, paths, names in scenarios:
            with self.subTest(paths=paths, names=names):
                with self.captured(values, paths, names=names) as (folder, engine, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, engine)
                    self.assertFalse((folder / "private/session_manifest.json").exists())

    def test_unsupported_path_fails_without_guessing_host_file(self):
        forged = (
            ROOT + "../cpu0/online", ROOT + "cpu0/../../etc/shadow",
            ROOT + "cpuX/topology/core_id",
            ROOT + "cpu0/topology/core_id_extra",
            ROOT + "cpu0/cpufreq/scaling_governor",
            ROOT + "cpu0/online/../topology/core_id",
            "/proc/cpuinfo",
            ROOT + "cpu0//online",
            ROOT + "cpu0/topology/core_id\x00",
        )
        for source_path in forged:
            with self.subTest(path=source_path):
                self.assertIsNone(cpu_sysfs_path_identity(source_path))
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-07", b"1\n",
                                            source_path=source_path)
                with self.captured((b"1\n",), (source_path,)) as (folder, engine, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, engine)
                    self.assertFalse((folder / "private/session_manifest.json").exists())

    def test_cross_run_reference_is_not_valid_original_evidence(self):
        with self.captured((b"1\n",), (ROOT + "cpu0/online",),
                           corrupt_run=True) as (folder, engine, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder, engine)
            self.assertFalse((folder / "private/session_manifest.json").exists())

    def test_cpu_list_not_expanded_and_invalid_ranges_rejected(self):
        valid = normalize_sealed_source("SRC-07", b"0-1023\n",
                                        source_path=ROOT + "present")
        self.assertEqual(valid.values[0].normalized_value,
                         {"ranges": [[0, 1023]]})
        for raw in (b"5-2\n", b"0-2,2-3\n", b"2,1\n",
                    b"0-2,\n", b"-1\n", b"0-2147483648\n"):
            with self.subTest(raw=raw), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-07", raw,
                                        source_path=ROOT + "present")

    def test_flag_and_topology_types_and_invalid_scalars(self):
        for raw, expected in ((b"0\n", False), (b"1\n", True)):
            datum = normalize_sealed_source(
                "SRC-07", raw, source_path=ROOT + "cpu0/online").values[0]
            self.assertEqual((datum.normalized_value, datum.value_type),
                             (expected, "BOOLEAN"))
        for raw in (b"2\n", b"-1\n", b"\xff\n", b"0\n1\n",
                    b"true\n", b"1\x00\n"):
            with self.subTest(raw=raw), self.assertRaises(SourceParseError):
                normalize_sealed_source(
                    "SRC-07", raw, source_path=ROOT + "cpu0/online")
        signed = normalize_sealed_source(
            "SRC-07", b"-1\n", source_path=ROOT +
            "cpu0/topology/physical_package_id").values[0]
        self.assertEqual(signed.normalized_value, -1)

    def test_invalid_captured_attribute_has_real_parse_error_and_fallback(self):
        with self.captured((b"bad-frequency\n",),
                           (ROOT + "cpu0/cpufreq/scaling_cur_freq",)) as (
                           folder, engine, originals):
            manifest = build_canonical(folder, engine)
            self.assertEqual(manifest["observation_count"], 1)
            obs = json.loads((folder / "private/system.json").read_text())["observations"]
            self.assertEqual(obs[0]["evidence_refs"], [originals[0].evidence_id])
            status = json.loads((folder / "private/status_records.json").read_text())
            self.assertEqual(status["status_records"][0]["reason_code"], "PARSE_FAILED")
            self.assertEqual(validate_canonical(folder), manifest)


if __name__ == "__main__":
    unittest.main()
