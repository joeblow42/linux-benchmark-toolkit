"""G5-04 CP-03 Increment 07 SRC-17 optical sysfs source-first oracles.

Expected behavior was specified before code in cp03_optical_sysfs_oracle_07.json.
This suite validates sealed original binding, not physical DVD/media operation.
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
    optical_sysfs_path_identity,
)
from lbt_g5.passive_worker import ATTRS, ROOTS
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
ROOT = "/sys/class/block/"
OPTICAL_FIELDS = ("removable", "device/type", "device/vendor", "device/model")


class OpticalSysfsOracles(unittest.TestCase):
    @contextmanager
    def recorded(self, originals, paths, *, names=None, unavailable=(),
                 wrong_run=False, outcome="CAPTURED", reason="BYTES_PRESERVED"):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / RUN
            directory.mkdir(mode=0o700)
            policy = {p.source_id: p for p in initial_source_policies()}["SRC-17"]
            writer = EvidenceWriter(str(directory), RUN)
            if names is None:
                names = ["item" + format(i, "04d") for i in range(1, len(originals) + 1)]
            self.assertEqual(len(names), len(originals))
            artifacts = []
            for name, raw in zip(names, originals):
                receipt = writer.seal_chunks(policy, "01", name, (raw,)).receipt
                self.assertIsNotNone(receipt)
                artifacts.append(receipt)
            attempt = build_attempt(
                RUN, "SRC-17", "01", "ALLOW", outcome, reason,
                evidence=tuple(artifacts),
                bytes_count=sum(x.byte_count for x in artifacts),
                source_paths=tuple(paths), unavailable_fields=tuple(unavailable))
            rec_path = commit_attempt(str(directory), attempt)
            if wrong_run:
                artifacts[0] = replace(artifacts[0], run_id="run-2026305120001")
            recorded = SimpleNamespace(
                receipt_private_path=rec_path,
                outcome=SimpleNamespace(artifacts=tuple(artifacts)))
            engine = EngineRun(RUN, (CollectorRun("COL-OPTICAL", (recorded,)),))
            yield directory, engine, tuple(artifacts)

    def test_source_authorization_matches_g5_03_worker(self):
        self.assertEqual(ROOTS["SRC-17"], ROOT.rstrip("/"))
        self.assertEqual(ATTRS["SRC-17"], OPTICAL_FIELDS)
        self.assertTrue(parser_available("SRC-17"))
        self.assertFalse(parser_available("SRC-26"))

    def test_optical_identity_preserves_each_sealed_original(self):
        paths = tuple(ROOT + "sr0/" + x for x in OPTICAL_FIELDS)
        originals = (b"1\n", b"5\n", b"HL-DT-ST \n", b"DVDRAM GH24 \n")
        with self.recorded(originals, paths) as (directory, engine, artifacts):
            manifest = build_canonical(directory, engine)
            self.assertEqual(manifest["observation_count"], 8)
            self.assertEqual(validate_canonical(directory), manifest)
            sys = json.loads((directory / "private/system.json").read_text())
            self.assertIn("Registered semantic parsers: ", sys["limitations"][1])
            self.assertIn(" of 28 source families", sys["limitations"][1])
            sem = [o for o in sys["observations"] if o["transformation_ids"]]
            self.assertEqual([o["datum_path"] for o in sem], [
                "optical.sysfs.sr0.removable",
                "optical.sysfs.sr0.device.type",
                "optical.sysfs.sr0.device.vendor",
                "optical.sysfs.sr0.device.model",
            ])
            self.assertEqual([x["normalized_value"] for x in sem],
                             [True, 5, "HL-DT-ST", "DVDRAM GH24"])
            self.assertEqual([x["value_type"] for x in sem],
                             ["BOOLEAN", "INTEGER", "STRING", "STRING"])
            self.assertNotIn("media_verified", [x["datum_path"] for x in sem])
            for original, obs, raw in zip(artifacts, sem, originals):
                self.assertEqual(obs["evidence_refs"], [original.evidence_id])
                self.assertEqual(obs["source_attempt_ids"], ["SRC-17-01"])
                self.assertEqual((directory / original.private_relative_path).read_bytes(), raw)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), original.sha256)

    def test_lexical_sr10_before_sr2_does_not_reassign_original(self):
        paths = (ROOT + "sr10/removable", ROOT + "sr2/removable")
        with self.recorded((b"1\n", b"0\n"), paths) as (directory, engine, _):
            build_canonical(directory, engine)
            sem = [o for o in json.loads(
                (directory / "private/system.json").read_text()
            )["observations"] if o["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in sem],
                             ["optical.sysfs.sr10.removable",
                              "optical.sysfs.sr2.removable"])
            self.assertEqual([x["normalized_value"] for x in sem],
                             [True, False])

    def test_optional_unavailable_does_not_synthesize_model(self):
        with self.recorded(
            (b"1\n",), (ROOT + "sr0/removable",),
            unavailable=("FileNotFoundError[2]:" + ROOT + "sr0/device/model",),
        ) as (directory, engine, _):
            build_canonical(directory, engine)
            obs = json.loads((directory / "private/system.json").read_text())
            self.assertEqual(len(obs["observations"]), 2)
            self.assertFalse(any(x["datum_path"].endswith(".device.model")
                                 for x in obs["observations"]))
            attempts = json.loads((directory / "private/source_attempts.json").read_text())
            self.assertEqual(len(attempts["attempts"][0]["unavailable_fields"]), 1)

    def test_absent_optical_source_does_not_invent_a_drive(self):
        with self.recorded((), (), outcome="UNAVAILABLE", reason="SOURCE_ABSENT"
        ) as (directory, engine, _):
            manifest = build_canonical(directory, engine)
            self.assertEqual(manifest["observation_count"], 0)
            self.assertEqual(validate_canonical(directory), manifest)
            statuses = json.loads((directory / "private/status_records.json").read_text())
            self.assertEqual(statuses["status_records"][0]["reason_code"], "SOURCE_ABSENT")

    def test_mismatch_reordering_duplicates_and_ordinal_tampering_fail_closed(self):
        cases = (
            ((b"1\n",), (), None),
            ((b"1\n",), (ROOT + "sr0/removable", ROOT + "sr0/device/type"), None),
            ((b"1\n", b"5\n"), (ROOT + "sr0/device/type", ROOT + "sr0/removable"), None),
            ((b"1\n", b"5\n"), (ROOT + "sr0/removable", ROOT + "sr0/removable"), None),
            ((b"1\n", b"5\n"), (ROOT + "sr2/removable", ROOT + "sr10/removable"), None),
            ((b"1\n",), (ROOT + "sr0/removable",), ("item0002",)),
        )
        for original, paths, names in cases:
            with self.subTest(paths=paths, names=names):
                with self.recorded(original, paths, names=names) as (directory, engine, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(directory, engine)
                    self.assertFalse((directory / "private/session_manifest.json").exists())

    def test_unsafe_paths_and_unapproved_attrs_are_rejected_without_host_access(self):
        invalid = (
            "/dev/sr0", "/sys/block/sr0/removable",
            ROOT + "sda/removable", ROOT + "srX/removable",
            ROOT + "sr0/device/serial", ROOT + "sr0/size",
            ROOT + "sr0/../sr1/removable", ROOT + "../sr0/removable",
            ROOT + "sr0//removable", ROOT + "sr0/removable\x00",
        )
        for path in invalid:
            with self.subTest(path=path):
                self.assertIsNone(optical_sysfs_path_identity(path))
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-17", b"1\n", source_path=path)
                with self.recorded((b"1\n",), (path,)) as (directory, engine, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(directory, engine)
                    self.assertFalse((directory / "private/session_manifest.json").exists())

    def test_forged_evidence_run_and_unchanged_original(self):
        with self.recorded((b"1\n",), (ROOT + "sr0/removable",),
                           wrong_run=True) as (directory, engine, originals):
            with self.assertRaises(CanonicalContractError):
                build_canonical(directory, engine)
            self.assertFalse((directory / "private/session_manifest.json").exists())

    def test_malformed_codes_flags_and_bytes_are_parser_failures(self):
        malformed = (
            (b"2\n", "removable"), (b"-1\n", "device/type"),
            (b"NaN\n", "device/type"), (b"2.0\n", "device/type"),
            (b"18446744073709551616\n", "device/type"),
            (b"\xff\n", "device/model"), (b"line1\nline2\n", "device/vendor"),
            (b"f\x00x\n", "device/model"), (b"9" * 5000, "device/type"),
        )
        for raw, attr in malformed:
            with self.subTest(attr=attr, raw=raw[:12]), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-17", raw,
                                        source_path=ROOT + "sr0/" + attr)
        with self.recorded((b"\xff\n",), (ROOT + "sr0/device/model",)
        ) as (directory, engine, artifacts):
            manifest = build_canonical(directory, engine)
            self.assertEqual(manifest["observation_count"], 1)
            status = json.loads((directory / "private/status_records.json").read_text())
            self.assertEqual(status["status_records"][0]["reason_code"], "PARSE_FAILED")
            self.assertEqual(validate_canonical(directory), manifest)
            self.assertEqual((directory / artifacts[0].private_relative_path).read_bytes(),
                             b"\xff\n")

    def test_padded_empty_device_identity_and_numeric_type_are_not_media_test(self):
        vendor = normalize_sealed_source(
            "SRC-17", b"   \n", source_path=ROOT + "sr0/device/vendor").values[0]
        self.assertEqual(vendor.normalized_value, "")
        kind = normalize_sealed_source(
            "SRC-17", b"5\n", source_path=ROOT + "sr0/device/type").values[0]
        self.assertEqual(kind.normalized_value, 5)
        self.assertNotIn("media", kind.datum_path)


if __name__ == "__main__":
    unittest.main()
