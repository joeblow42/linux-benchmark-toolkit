"""SRC-26 power sysfs source-first negative provenance and private-data tests.

The source-first oracle was registered before parser edits at
verification/g5_04/cp03_power_sysfs_oracle_12.json.
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
    power_sysfs_path_identity,
)
from lbt_g5.passive_worker import ROOTS, ATTRS
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
ROOT = "/sys/class/power_supply/"
FIELDS = ("type", "status", "capacity", "voltage_now", "current_now",
          "power_now", "energy_now", "energy_full", "energy_full_design",
          "charge_now", "charge_full", "charge_full_design", "manufacturer",
          "model_name", "serial_number", "technology", "cycle_count")


class PowerSysfsOracles(unittest.TestCase):
    @contextmanager
    def sealed(self, raws, paths, *, names=None, unavailable=(),
               wrong_run=False, outcome="CAPTURED", reason="BYTES_PRESERVED"):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / RUN
            directory.mkdir(mode=0o700)
            pol = {x.source_id:x for x in initial_source_policies()}["SRC-26"]
            writer = EvidenceWriter(str(directory), RUN)
            names = names if names is not None else [
                f"item{i:04d}" for i in range(1, len(raws)+1)]
            self.assertEqual(len(raws), len(names))
            artifacts = []
            for name, raw in zip(names, raws):
                receipt = writer.seal_chunks(pol, "01", name, (raw,)).receipt
                self.assertIsNotNone(receipt)
                artifacts.append(receipt)
            attempt = build_attempt(
                RUN, "SRC-26", "01", "ALLOW", outcome, reason,
                evidence=tuple(artifacts), bytes_count=sum(x.byte_count for x in artifacts),
                source_paths=tuple(paths), unavailable_fields=tuple(unavailable))
            location = commit_attempt(str(directory), attempt)
            if wrong_run:
                artifacts[0] = replace(artifacts[0], run_id="run-2026305120001")
            rec = SimpleNamespace(
                receipt_private_path=location,
                outcome=SimpleNamespace(artifacts=tuple(artifacts)))
            yield directory, EngineRun(
                RUN, (CollectorRun("COL-POWER", (rec,)),)), tuple(artifacts)

    def test_worker_fixed_tuple_and_parser(self):
        self.assertEqual(ROOTS["SRC-26"], ROOT.rstrip("/"))
        self.assertEqual(ATTRS["SRC-26"], FIELDS)
        self.assertTrue(parser_available("SRC-26"))
        self.assertFalse(parser_available("SRC-11"))

    def test_private_identity_and_signed_numeric_originals(self):
        attrs = ("type", "status", "capacity", "current_now",
                 "serial_number", "cycle_count")
        paths = tuple(ROOT + "BAT0/" + field for field in attrs)
        raws = (b"Battery\n", b"Discharging\n", b"67\n", b"-170000\n",
                b"PRIVATE123\n", b"400\n")
        with self.sealed(raws, paths) as (directory, run, originals):
            manifest = build_canonical(directory, run)
            self.assertEqual(manifest["observation_count"], 12)
            self.assertEqual(validate_canonical(directory), manifest)
            values = json.loads((directory / "private/system.json").read_text())
            typed = [x for x in values["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in typed],
                             ["power.supply.BAT0." + a for a in attrs])
            self.assertEqual([x["normalized_value"] for x in typed],
                             ["Battery", "Discharging", 67, -170000, "PRIVATE123", 400])
            self.assertTrue(all(x["unit"] is None for x in typed))
            for x, raw, item in zip(typed, raws, originals):
                self.assertEqual(x["evidence_refs"], [item.evidence_id])
                self.assertEqual(x["source_attempt_ids"], ["SRC-26-01"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item.sha256)
                self.assertEqual((directory / item.private_relative_path).read_bytes(), raw)

    def test_lexical_devices_and_optional_absent_are_not_fabricated(self):
        paths = (ROOT + "BAT10/type", ROOT + "BAT2/type")
        with self.sealed(
            (b"Battery\n", b"UPS\n"), paths,
            unavailable=("FileNotFoundError[2]:" + ROOT + "BAT2/cycle_count",)
        ) as (directory, run, _):
            build_canonical(directory, run)
            vals = json.loads((directory / "private/system.json").read_text())
            sem = [x for x in vals["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in sem],
                             ["power.supply.BAT10.type", "power.supply.BAT2.type"])
            attempts = json.loads((directory / "private/source_attempts.json").read_text())
            self.assertEqual(len(attempts["attempts"][0]["unavailable_fields"]), 1)

    def test_no_supply_does_not_invent_battery(self):
        with self.sealed((), (), outcome="UNAVAILABLE",
                         reason="SOURCE_ABSENT") as (directory, run, _):
            self.assertEqual(build_canonical(directory, run)["observation_count"], 0)
            self.assertEqual(validate_canonical(directory)["observation_count"], 0)

    def test_wrong_count_order_duplicate_and_artifact_index_fail_closed(self):
        cases = (
            ((b"1\n",), (), None),
            ((b"1\n",), (ROOT+"BAT0/type", ROOT+"BAT0/status"), None),
            ((b"1\n", b"2\n"),
             (ROOT+"BAT0/capacity", ROOT+"BAT0/type"), None),
            ((b"1\n", b"2\n"),
             (ROOT+"BAT0/type", ROOT+"BAT0/type"), None),
            ((b"1\n", b"2\n"),
             (ROOT+"BAT2/type", ROOT+"BAT10/type"), None),
            ((b"1\n",), (ROOT+"BAT0/type",), ("item0002",)),
        )
        for raws, paths, names in cases:
            with self.subTest(paths=paths, names=names):
                with self.sealed(raws, paths, names=names) as (directory, run, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(directory, run)
                    self.assertFalse((directory/"private/session_manifest.json").exists())

    def test_control_threshold_traversal_and_unregistered_files_rejected(self):
        bad = (ROOT+"BAT0/charge_control_end_threshold",
               ROOT+"BAT0/capacity_level", ROOT+"BAT0/device/serial",
               ROOT+"BAT0/../BAT1/type", ROOT+"BAT0//type",
               ROOT+".hidden/type", ROOT+"BAT0/type\x00",
               "/dev/BAT0", "/sys/class/hwmon/hwmon0/temp1_input")
        for path in bad:
            with self.subTest(path=path):
                self.assertIsNone(power_sysfs_path_identity(path))
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-26", b"1\n", source_path=path)
                with self.sealed((b"1\n",), (path,)) as (directory, run, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(directory, run)

    def test_unknown_status_large_signed_and_parser_failure_preserve_raw(self):
        x = normalize_sealed_source(
            "SRC-26", b"NovelState\n", source_path=ROOT+"BAT0/status").values[0]
        self.assertEqual(x.normalized_value, "NovelState")
        y = normalize_sealed_source(
            "SRC-26", b"-170000\n", source_path=ROOT+"BAT0/current_now").values[0]
        self.assertEqual(y.normalized_value, -170000)
        self.assertIsNone(y.unit)
        for raw, field in ((b"bad\n", "capacity"), (b"1.5\n", "power_now"),
                           (b"9223372036854775808\n", "energy_now"),
                           (b"\xff\n", "manufacturer"),
                           (b"x\nz\n", "status"), (b"1\x00\n", "cycle_count")):
            with self.subTest(raw=raw[:12]), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-26", raw,
                                        source_path=ROOT+"BAT0/"+field)
        with self.sealed((b"bad\n",), (ROOT+"BAT0/capacity",)) as (
            directory, run, original
        ):
            manifest = build_canonical(directory, run)
            self.assertEqual(manifest["observation_count"], 1)
            states = json.loads((directory/"private/status_records.json").read_text())
            self.assertEqual(states["status_records"][0]["reason_code"], "PARSE_FAILED")
            self.assertEqual((directory/original[0].private_relative_path).read_bytes(),
                             b"bad\n")
            self.assertEqual(validate_canonical(directory), manifest)
        with self.sealed((b"1\n",), (ROOT+"BAT0/capacity",),
                         wrong_run=True) as (directory, run, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(directory, run)


if __name__ == "__main__":
    unittest.main()
