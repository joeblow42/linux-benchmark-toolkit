"""SRC-25 contract-derived hwmon original-path and conservative-unit oracles.

Expected outputs were specified before implementation in
verification/g5_04/cp03_hwmon_sysfs_oracle_11.json. No device I/O.
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
    hwmon_sysfs_path_identity,
)
from lbt_g5.passive_worker import ROOTS, HWMON
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
ROOT = "/sys/class/hwmon/"


class HwmonOriginalPathOracles(unittest.TestCase):
    @contextmanager
    def sealed(self, originals, paths, *, names=None, unavailable=(),
               cross_run=False, outcome="CAPTURED", reason="BYTES_PRESERVED"):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / RUN
            folder.mkdir(mode=0o700)
            pol = {x.source_id: x for x in initial_source_policies()}["SRC-25"]
            writer = EvidenceWriter(str(folder), RUN)
            names = names or [f"item{i:04d}" for i in range(1, len(originals)+1)]
            self.assertEqual(len(originals), len(names))
            artifacts = []
            for name, raw in zip(names, originals):
                receipt = writer.seal_chunks(pol, "01", name, (raw,)).receipt
                self.assertIsNotNone(receipt)
                artifacts.append(receipt)
            attempt = build_attempt(
                RUN, "SRC-25", "01", "ALLOW", outcome, reason,
                evidence=tuple(artifacts), bytes_count=sum(x.byte_count for x in artifacts),
                source_paths=tuple(paths), unavailable_fields=tuple(unavailable))
            loc = commit_attempt(str(folder), attempt)
            if cross_run:
                artifacts[0] = replace(artifacts[0], run_id="run-2026305120001")
            recorded = SimpleNamespace(
                receipt_private_path=loc,
                outcome=SimpleNamespace(artifacts=tuple(artifacts)))
            yield folder, EngineRun(
                RUN, (CollectorRun("COL-THERM", (recorded,)),)), tuple(artifacts)

    def test_source_allowlist_corresponds_to_g5_worker(self):
        self.assertEqual(ROOTS["SRC-25"], ROOT.rstrip("/"))
        self.assertTrue(parser_available("SRC-25"))
        self.assertFalse(parser_available("SRC-11"))
        for field in ("name", "temp1_input", "temp1_label", "fan1_input",
                      "in0_input", "power1_input"):
            self.assertIsNotNone(HWMON.fullmatch(field))
            self.assertEqual(hwmon_sysfs_path_identity(ROOT + "hwmon0/" + field)[2], field)

    def test_exact_worker_order_original_evidence_and_units_unclassified(self):
        attrs = ("fan1_input", "in0_input", "name", "power1_input",
                 "temp1_input", "temp1_label")
        paths = tuple(ROOT + "hwmon0/" + attr for attr in attrs)
        raws = (b"1200\n", b"999\n", b"some_chip\n", b"100000\n",
                b"-2500\n", b"Probe A\n")
        with self.sealed(raws, paths) as (folder, run, originals):
            manifest = build_canonical(folder, run)
            self.assertEqual(manifest["observation_count"], 12)
            self.assertEqual(validate_canonical(folder), manifest)
            vals = json.loads((folder / "private/system.json").read_text())
            typed = [x for x in vals["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in typed],
                             ["thermal.hwmon.hwmon0." + attr for attr in attrs])
            self.assertEqual([x["normalized_value"] for x in typed],
                             [1200, 999, "some_chip", 100000, -2500, "Probe A"])
            for raw, datum, original in zip(raws, typed, originals):
                self.assertIsNone(datum["unit"])
                self.assertEqual(datum["evidence_refs"], [original.evidence_id])
                self.assertEqual((folder / original.private_relative_path).read_bytes(), raw)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), original.sha256)

    def test_hwmon10_before_hwmon2_and_missing_optional_attr(self):
        p=(ROOT+"hwmon10/temp1_input", ROOT+"hwmon2/temp1_input")
        with self.sealed(
            (b"100\n", b"200\n"), p,
            unavailable=("FileNotFoundError[2]:" + ROOT + "hwmon2/temp2_input",)
        ) as (folder, run, originals):
            build_canonical(folder, run)
            typed = [x for x in json.loads((folder/"private/system.json").read_text())
                     ["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in typed],
                             ["thermal.hwmon.hwmon10.temp1_input",
                              "thermal.hwmon.hwmon2.temp1_input"])
            att = json.loads((folder/"private/source_attempts.json").read_text())
            self.assertEqual(len(att["attempts"][0]["unavailable_fields"]), 1)

    def test_no_chip_does_not_fabricate_a_sensor(self):
        with self.sealed((), (), outcome="UNAVAILABLE",
                         reason="SOURCE_ABSENT") as (folder, run, _):
            self.assertEqual(build_canonical(folder, run)["observation_count"], 0)
            self.assertEqual(validate_canonical(folder)["observation_count"], 0)

    def test_duplicate_swapped_count_and_ordinal_rejected(self):
        scenarios = (
            ((b"1\n",), (), None),
            ((b"1\n",), (ROOT+"hwmon0/name", ROOT+"hwmon0/temp1_input"), None),
            ((b"1\n", b"2\n"),
             (ROOT+"hwmon0/temp1_input", ROOT+"hwmon0/name"), None),
            ((b"1\n", b"2\n"),
             (ROOT+"hwmon0/name", ROOT+"hwmon0/name"), None),
            ((b"1\n", b"2\n"),
             (ROOT+"hwmon2/name", ROOT+"hwmon10/name"), None),
            ((b"1\n",), (ROOT+"hwmon0/name",), ("item0002",)),
        )
        for raw, paths, names in scenarios:
            with self.subTest(paths=paths, names=names):
                with self.sealed(raw, paths, names=names) as (folder, run, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, run)
                    self.assertFalse((folder/"private/session_manifest.json").exists())

    def test_forbidden_control_or_traversal_path_rejected(self):
        paths = (
            ROOT+"hwmon0/pwm1", ROOT+"hwmon0/fan1_target",
            ROOT+"hwmon0/temp1_max", ROOT+"hwmon0/temp1_crit",
            ROOT+"hwmonX/temp1_input", ROOT+"hwmon0/../hwmon1/name",
            ROOT+"hwmon0//name", ROOT+"hwmon0/name\x00",
            "/sys/class/thermal/thermal_zone0/temp", "/dev/hwmon0",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertIsNone(hwmon_sysfs_path_identity(path))
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-25", b"1\n", source_path=path)
                with self.sealed((b"1\n",), (path,)) as (folder, run, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, run)

    def test_bad_numeric_utf8_multiline_and_cross_run_fail_closed(self):
        for raw in (b"1.3\n", b"bad\n", b"9223372036854775808\n",
                    b"\xff\n", b"1\n2\n", b"1\x00\n"):
            with self.subTest(raw=raw[:16]), self.assertRaises(SourceParseError):
                normalize_sealed_source(
                    "SRC-25", raw, source_path=ROOT+"hwmon0/temp1_input")
        with self.sealed((b"invalid\n",), (ROOT+"hwmon0/temp1_input",)) as (
            folder, run, originals
        ):
            result = build_canonical(folder, run)
            self.assertEqual(result["observation_count"], 1)
            statuses = json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual(statuses["status_records"][0]["reason_code"], "PARSE_FAILED")
            self.assertEqual((folder/originals[0].private_relative_path).read_bytes(),
                             b"invalid\n")
            self.assertEqual(validate_canonical(folder), result)
        with self.sealed((b"42\n",), (ROOT+"hwmon0/temp1_input",),
                         cross_run=True) as (folder, run, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder, run)


if __name__ == "__main__":
    unittest.main()
