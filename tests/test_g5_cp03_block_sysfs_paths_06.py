"""CP-03 Increment 06: source-first SRC-12 block sysfs and provenance oracles.

Expectations specified independently in cp03_block_sysfs_oracle_06.json
from the G4-07 authorization and G5-03 passive worker path-order contract.
A passing fixture is scoped evidence, not a full requirements or gate PASS.
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
    block_sysfs_path_identity,
)
from lbt_g5.passive_worker import ATTRS, ROOTS
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
ROOT = "/sys/class/block/"
ATTRIBUTES = (
    "size", "ro", "removable", "queue/logical_block_size",
    "queue/physical_block_size", "device/vendor", "device/model",
    "device/rev",
)


class BlockSysfsOracles(unittest.TestCase):
    @contextmanager
    def recorded(self, data, paths, *, names=None, unavailable=(),
                 wrong_run=False):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / RUN
            directory.mkdir(mode=0o700)
            policy = {x.source_id: x for x in initial_source_policies()}["SRC-12"]
            writer = EvidenceWriter(str(directory), RUN)
            if names is None:
                names = ["item" + format(i, "04d") for i in range(1, len(data) + 1)]
            self.assertEqual(len(names), len(data))
            artifacts = []
            for name, original in zip(names, data):
                receipt = writer.seal_chunks(policy, "01", name, (original,)).receipt
                self.assertIsNotNone(receipt)
                artifacts.append(receipt)
            attempt = build_attempt(
                RUN, "SRC-12", "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
                evidence=tuple(artifacts),
                bytes_count=sum(x.byte_count for x in artifacts),
                source_paths=tuple(paths), unavailable_fields=tuple(unavailable))
            receipt_path = commit_attempt(str(directory), attempt)
            if wrong_run:
                artifacts[0] = replace(artifacts[0], run_id="run-2026305120001")
            obj = SimpleNamespace(
                receipt_private_path=receipt_path,
                outcome=SimpleNamespace(artifacts=tuple(artifacts)))
            engine = EngineRun(RUN, (CollectorRun("COL-BLOCK", (obj,)),))
            yield directory, engine, tuple(artifacts)

    def test_registered_worker_contract_and_parser(self):
        self.assertEqual(ROOTS["SRC-12"], ROOT.rstrip("/"))
        self.assertEqual(ATTRS["SRC-12"], ATTRIBUTES)
        self.assertTrue(parser_available("SRC-12"))
        self.assertFalse(parser_available("SRC-11"))

    def test_geometry_readonly_and_original_evidence_are_attributed(self):
        paths = (
            ROOT + "nvme0n1/size",
            ROOT + "nvme0n1/ro",
            ROOT + "nvme0n1/queue/logical_block_size",
            ROOT + "nvme0n1/queue/physical_block_size",
            ROOT + "sda/device/model",
        )
        data = (b"1953525168\n", b"0\n", b"512\n", b"4096\n", b" Demo Disk \n")
        with self.recorded(data, paths) as (directory, engine, artifacts):
            manifest = build_canonical(directory, engine)
            self.assertEqual(manifest["observation_count"], 10)
            self.assertEqual(validate_canonical(directory), manifest)
            records = json.loads((directory / "private/system.json").read_text())
            typed = [x for x in records["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in typed], [
                "storage.block.nvme0n1.size",
                "storage.block.nvme0n1.ro",
                "storage.block.nvme0n1.queue.logical_block_size",
                "storage.block.nvme0n1.queue.physical_block_size",
                "storage.block.sda.device.model",
            ])
            self.assertEqual(typed[0]["normalized_value"], 1953525168)
            self.assertEqual(typed[0]["unit"], "512-byte-sectors")
            self.assertEqual(typed[1]["normalized_value"], False)
            self.assertEqual([x["unit"] for x in typed[2:4]], ["bytes", "bytes"])
            self.assertEqual(typed[4]["normalized_value"], "Demo Disk")
            for obs, original, raw in zip(typed, artifacts, data):
                self.assertEqual(obs["evidence_refs"], [original.evidence_id])
                self.assertEqual(obs["source_attempt_ids"], ["SRC-12-01"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), original.sha256)
                self.assertEqual((directory / original.private_relative_path).read_bytes(), raw)
            self.assertNotIn("device_capacity_bytes",
                             [x["datum_path"] for x in typed])

    def test_worker_sort_is_lexical_not_numerical(self):
        paths = (ROOT + "loop10/size", ROOT + "loop2/size")
        with self.recorded((b"3\n", b"7\n"), paths) as (directory, engine, _):
            build_canonical(directory, engine)
            records = json.loads((directory / "private/system.json").read_text())
            typed = [x for x in records["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in typed],
                             ["storage.block.loop10.size", "storage.block.loop2.size"])

    def test_optional_unavailable_fields_are_not_synthesized(self):
        with self.recorded(
            (b"512\n", b"0\n"), (ROOT + "loop0/size", ROOT + "loop0/ro"),
            unavailable=("FileNotFoundError[2]:" + ROOT + "loop0/device/vendor",),
        ) as (directory, engine, _):
            build_canonical(directory, engine)
            records = json.loads((directory / "private/system.json").read_text())
            self.assertEqual(len(records["observations"]), 4)
            self.assertFalse(any(x["datum_path"].endswith("device.vendor")
                                 for x in records["observations"]))
            attempted = json.loads((directory / "private/source_attempts.json").read_text())
            self.assertEqual(len(attempted["attempts"][0]["unavailable_fields"]), 1)

    def test_path_count_and_order_and_artifact_ordinals_fail_closed(self):
        conditions = (
            ((b"1\n",), (), None),
            ((b"1\n",), (ROOT + "sda/size", ROOT + "sda/ro"), None),
            ((b"1\n", b"2\n"), (ROOT + "sda/ro", ROOT + "sda/size"), None),
            ((b"1\n", b"2\n"), (ROOT + "sda/size", ROOT + "sda/size"), None),
            ((b"1\n", b"2\n"), (ROOT + "sda/size", ROOT + "nvme0n1/size"), None),
            ((b"1\n",), (ROOT + "sda/size",), ("item0002",)),
        )
        for data, paths, names in conditions:
            with self.subTest(paths=paths, names=names):
                with self.recorded(data, paths, names=names) as (directory, engine, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(directory, engine)
                    self.assertFalse((directory / "private/session_manifest.json").exists())

    def test_unsafe_and_unregistered_paths_do_not_trigger_host_reads(self):
        paths = (
            ROOT + "../sda/size", ROOT + "sda/../../etc/shadow",
            ROOT + "sda/device/serial", ROOT + "sda/queue/scheduler",
            ROOT + "sda//size", ROOT + ".secret/size",
            ROOT + "sda/size ", "/dev/sda", "/sys/block/sda/size",
            ROOT + "sda/size\x00",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertIsNone(block_sysfs_path_identity(path))
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-12", b"123\n",
                                            source_path=path)
                with self.recorded((b"123\n",), (path,)) as (directory, engine, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(directory, engine)
                    self.assertFalse((directory / "private/session_manifest.json").exists())

    def test_cross_run_forgery_is_denied(self):
        with self.recorded((b"7\n",), (ROOT + "sda/size",),
                           wrong_run=True) as (directory, engine, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(directory, engine)

    def test_exact_flags_sector_units_and_zero_capacity(self):
        for raw, truth in ((b"0\n", False), (b"1\n", True)):
            result = normalize_sealed_source("SRC-12", raw, source_path=ROOT + "sda/ro")
            self.assertEqual((result.values[0].normalized_value,
                              result.values[0].value_type), (truth, "BOOLEAN"))
        empty = normalize_sealed_source("SRC-12", b"0\n", source_path=ROOT + "loop0/size")
        self.assertEqual(empty.values[0].normalized_value, 0)
        self.assertEqual(empty.values[0].unit, "512-byte-sectors")

    def test_malformed_scalars_are_evidenced_parser_failures(self):
        cases = (
            (b"-1\n", "sda/size"), (b"1.5\n", "sda/size"),
            (b"2\n", "sda/ro"), (b"0\n", "sda/queue/logical_block_size"),
            (b"\xff\n", "sda/device/model"),
            (b"Line1\nLine2\n", "sda/device/model"),
            (b"A\x00B", "sda/device/model"),
            (b"9" * 5000, "sda/size"),
        )
        for raw, attribute in cases:
            with self.subTest(attribute=attribute, raw=raw[:12]):
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-12", raw, source_path=ROOT + attribute)
        with self.recorded((b"\xff\n",), (ROOT + "sda/device/vendor",)) as (
            directory, engine, artifacts
        ):
            manifest = build_canonical(directory, engine)
            self.assertEqual(manifest["observation_count"], 1)
            statuses = json.loads((directory / "private/status_records.json").read_text())
            self.assertEqual(statuses["status_records"][0]["reason_code"], "PARSE_FAILED")
            self.assertEqual(validate_canonical(directory), manifest)
            self.assertEqual((directory / artifacts[0].private_relative_path).read_bytes(),
                             b"\xff\n")


if __name__ == "__main__":
    unittest.main()
