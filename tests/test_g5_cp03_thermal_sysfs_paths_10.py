"""CP03-10: source-first SRC-24 thermal zone provenance/units/negative tests.

Oracles specified first in verification/g5_04/cp03_thermal_sysfs_oracle_10.json.
Fixtures are sealed original bytes, not host probing or cooling policy changes.
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
    thermal_sysfs_path_identity,
)
from lbt_g5.passive_worker import ROOTS, ATTRS
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
ROOT = "/sys/class/thermal/"
THERM_ATTRS = ("type", "temp")


class ThermalSourceFirstOracles(unittest.TestCase):
    @contextmanager
    def originals(self, data, paths, *, names=None, unavailable=(),
                  wrong_run=False, outcome="CAPTURED", reason="BYTES_PRESERVED"):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / RUN
            folder.mkdir(mode=0o700)
            policy = {p.source_id:p for p in initial_source_policies()}["SRC-24"]
            writer = EvidenceWriter(str(folder), RUN)
            if names is None:
                names = [f"item{i:04d}" for i in range(1, len(data)+1)]
            self.assertEqual(len(names), len(data))
            sealed = []
            for name, raw in zip(names, data):
                item = writer.seal_chunks(policy, "01", name, (raw,)).receipt
                self.assertIsNotNone(item)
                sealed.append(item)
            attempt = build_attempt(
                RUN, "SRC-24", "01", "ALLOW", outcome, reason,
                evidence=tuple(sealed),
                bytes_count=sum(x.byte_count for x in sealed),
                source_paths=tuple(paths), unavailable_fields=tuple(unavailable))
            path = commit_attempt(str(folder), attempt)
            if wrong_run:
                sealed[0] = replace(sealed[0], run_id="run-2026305120001")
            record = SimpleNamespace(
                receipt_private_path=path,
                outcome=SimpleNamespace(artifacts=tuple(sealed)))
            run = EngineRun(RUN, (CollectorRun("COL-THERM", (record,)),))
            yield folder, run, tuple(sealed)

    def test_registered_worker_scope_and_parser_available(self):
        self.assertEqual(ROOTS["SRC-24"], ROOT.rstrip("/"))
        self.assertEqual(ATTRS["SRC-24"], THERM_ATTRS)
        self.assertTrue(parser_available("SRC-24"))
        self.assertTrue(parser_available("SRC-13"))  # CP03-17 verified O1 stdout

    def test_one_thermal_zone_type_and_temperature_cite_original_bytes(self):
        paths = (ROOT + "thermal_zone0/type", ROOT + "thermal_zone0/temp")
        raw = (b"x86_pkg_temp\n", b"45000\n")
        with self.originals(raw, paths) as (folder, run, sealed):
            manifest = build_canonical(folder, run)
            self.assertEqual(manifest["observation_count"], 4)
            self.assertEqual(validate_canonical(folder), manifest)
            sys = json.loads((folder / "private/system.json").read_text())
            typed = [x for x in sys["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in typed],
                             ["thermal.sysfs.thermal_zone0.type",
                              "thermal.sysfs.thermal_zone0.temp"])
            self.assertEqual([x["normalized_value"] for x in typed],
                             ["x86_pkg_temp", 45000])
            self.assertEqual(typed[1]["unit"], "millidegrees Celsius")
            self.assertEqual(typed[1]["value_type"], "INTEGER")
            self.assertNotIn("health", typed[1]["datum_path"])
            for item, artifact, datum in zip(raw, sealed, typed):
                self.assertEqual(datum["evidence_refs"], [artifact.evidence_id])
                self.assertEqual(datum["source_attempt_ids"], ["SRC-24-01"])
                self.assertEqual(hashlib.sha256(item).hexdigest(), artifact.sha256)
                self.assertEqual((folder / artifact.private_relative_path).read_bytes(), item)

    def test_lexical_zone10_precedes_zone2(self):
        paths = (ROOT + "thermal_zone10/temp", ROOT + "thermal_zone2/temp")
        with self.originals((b"2000\n", b"-2500\n"), paths) as (folder, run, _):
            build_canonical(folder, run)
            typed = [x for x in json.loads((folder / "private/system.json").read_text())
                     ["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in typed],
                             ["thermal.sysfs.thermal_zone10.temp",
                              "thermal.sysfs.thermal_zone2.temp"])
            self.assertEqual([x["normalized_value"] for x in typed], [2000, -2500])

    def test_missing_optional_temperature_is_not_synthesized(self):
        with self.originals(
            (b"acpitz\n",), (ROOT + "thermal_zone1/type",),
            unavailable=("FileNotFoundError[2]:" + ROOT + "thermal_zone1/temp",)
        ) as (folder, run, _):
            build_canonical(folder, run)
            sys = json.loads((folder / "private/system.json").read_text())
            self.assertEqual(len(sys["observations"]), 2)
            self.assertFalse(any(x["datum_path"].endswith(".temp")
                                 for x in sys["observations"]))
            attempts = json.loads((folder / "private/source_attempts.json").read_text())
            self.assertEqual(len(attempts["attempts"][0]["unavailable_fields"]), 1)

    def test_absent_thermal_source_does_not_invent_zone(self):
        with self.originals((), (), outcome="UNAVAILABLE", reason="SOURCE_ABSENT"
        ) as (folder, run, _):
            manifest = build_canonical(folder, run)
            self.assertEqual(manifest["observation_count"], 0)
            self.assertEqual(validate_canonical(folder), manifest)

    def test_swapped_duplicate_missing_paths_and_item_ordinals_rejected(self):
        fixtures = (
            ((b"a\n",), (), None),
            ((b"a\n",), (ROOT + "thermal_zone0/type",
                          ROOT + "thermal_zone0/temp"), None),
            ((b"a\n", b"123\n"),
             (ROOT + "thermal_zone0/temp", ROOT + "thermal_zone0/type"), None),
            ((b"a\n", b"b\n"),
             (ROOT + "thermal_zone0/type", ROOT + "thermal_zone0/type"), None),
            ((b"1\n", b"2\n"),
             (ROOT + "thermal_zone2/temp", ROOT + "thermal_zone10/temp"), None),
            ((b"1\n",), (ROOT + "thermal_zone0/temp",), ("item0002",)),
        )
        for data, paths, names in fixtures:
            with self.subTest(paths=paths, names=names):
                with self.originals(data, paths, names=names) as (folder, run, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, run)
                    self.assertFalse((folder / "private/session_manifest.json").exists())

    def test_cooling_trip_writes_hidden_and_traversal_paths_denied(self):
        for source_path in (
            "/sys/class/thermal/cooling_device0/cur_state",
            ROOT + "thermal_zone0/trip_point_0_temp",
            ROOT + "thermal_zone0/policy", ROOT + "thermal_zoneX/temp",
            ROOT + "../thermal_zone0/temp",
            ROOT + "thermal_zone0/../thermal_zone1/temp",
            ROOT + "thermal_zone0//temp", ROOT + ".hidden/temp",
            "/sys/devices/platform/thermal_zone0/temp",
            ROOT + "thermal_zone0/temp\x00",
        ):
            with self.subTest(path=source_path):
                self.assertIsNone(thermal_sysfs_path_identity(source_path))
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-24", b"25000\n",
                                            source_path=source_path)
                with self.originals((b"25000\n",), (source_path,)) as (folder, run, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, run)

    def test_signed_millidegree_boundary_and_unfamiliar_type(self):
        for raw, expected in ((b"-5000\n", -5000), (b"0\n", 0),
                              (b"87000\n", 87000)):
            item = normalize_sealed_source(
                "SRC-24", raw,
                source_path=ROOT + "thermal_zone0/temp").values[0]
            self.assertEqual(item.normalized_value, expected)
            self.assertEqual(item.unit, "millidegrees Celsius")
        novel = normalize_sealed_source(
            "SRC-24", b"unknown_driver\n",
            source_path=ROOT + "thermal_zone0/type").values[0]
        self.assertEqual(novel.normalized_value, "unknown_driver")

    def test_invalid_temperature_parse_failed_and_raw_retained(self):
        for raw, attr in (
            (b"17.2\n", "temp"), (b"NaN\n", "temp"),
            (b"2147483648\n", "temp"), (b"-2147483649\n", "temp"),
            (b"1\n2\n", "temp"), (b"\xff\n", "type"),
            (b"abc\x00\n", "type"), (b"9"*5000, "temp"),
        ):
            with self.subTest(raw=raw[:15], attr=attr), self.assertRaises(SourceParseError):
                normalize_sealed_source(
                    "SRC-24", raw,
                    source_path=ROOT + "thermal_zone0/" + attr)
        with self.originals(
            (b"NaN\n",), (ROOT + "thermal_zone0/temp",)
        ) as (folder, run, artifacts):
            manifest = build_canonical(folder, run)
            self.assertEqual(manifest["observation_count"], 1)
            statuses = json.loads((folder / "private/status_records.json").read_text())
            self.assertEqual(statuses["status_records"][0]["reason_code"], "PARSE_FAILED")
            self.assertEqual((folder / artifacts[0].private_relative_path).read_bytes(),
                             b"NaN\n")
            self.assertEqual(validate_canonical(folder), manifest)

    def test_wrong_run_original_cannot_be_verified(self):
        with self.originals((b"23000\n",), (ROOT + "thermal_zone0/temp",),
                            wrong_run=True) as (folder, run, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder, run)
            self.assertFalse((folder / "private/session_manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
