"""Independent contract-first CP-03 increment 04 path-aware sysfs tests.

Oracle: approved G4-07 SRC-04 scope + accepted G5-03 passive worker ordering,
sealed item IDs and private attempt receipts. This challenge suite is separate
from the parser implementation; it does not imply owner gate acceptance.
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
)
from lbt_g5.passive_worker import DMI
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
ROOT = "/sys/class/dmi/id/"
APPROVED_DMI = frozenset((
    "sys_vendor", "product_name", "product_version", "product_family",
    "board_vendor", "board_name", "board_version",
    "bios_vendor", "bios_version", "bios_date",
    "chassis_type", "chassis_vendor", "chassis_version",
))


class G504DmiSourcePathOracles(unittest.TestCase):
    @contextmanager
    def recorded(self, values, paths, *, names=None, unavailable=(), tamper_run=False):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / RUN
            folder.mkdir(mode=0o700)
            writer = EvidenceWriter(str(folder), RUN)
            pol = {p.source_id: p for p in initial_source_policies()}["SRC-04"]
            if names is None:
                names = ["item" + format(i, "04d") for i in range(1, len(values) + 1)]
            original = []
            for name, raw in zip(names, values):
                sealed = writer.seal_chunks(pol, "01", name, (raw,)).receipt
                self.assertIsNotNone(sealed)
                original.append(sealed)
            attempt = build_attempt(
                RUN, "SRC-04", "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
                evidence=tuple(original),
                bytes_count=sum(x.byte_count for x in original),
                source_paths=tuple(paths), unavailable_fields=tuple(unavailable))
            location = commit_attempt(str(folder), attempt)
            if tamper_run:
                original[0] = replace(original[0], run_id="run-2026305120001")
            stored = SimpleNamespace(
                outcome=SimpleNamespace(artifacts=tuple(original)),
                receipt_private_path=location)
            engine = EngineRun(RUN, (CollectorRun("COL-OS", (stored,)),))
            yield folder, engine, tuple(original)

    def test_approved_dmi_allowlist_cross_checks_worker(self):
        self.assertEqual(DMI, APPROVED_DMI)
        self.assertTrue(parser_available("SRC-04"))
        self.assertTrue(parser_available("SRC-13"))  # CP03-17 O1 verified stdout

    def test_source_path_required_and_values_never_define_field_identity(self):
        path = ROOT + "product_name"
        got = normalize_sealed_source("SRC-04", b"Example workstation\n",
                                      source_path=path)
        self.assertEqual(got.parser_id, "linux-sysfs-dmi-public-v1")
        self.assertEqual(got.values[0].datum_path, "platform.dmi.product_name")
        self.assertEqual(got.values[0].observed_value, "Example workstation\n")
        self.assertEqual(got.values[0].normalized_value, "Example workstation")
        self.assertEqual(got.values[0].value_type, "STRING")
        with self.assertRaises(SourceParseError):
            normalize_sealed_source("SRC-04", b"product_name\n")
        # An identical byte sequence at a different authorized path
        # must have that different path's datum identity.
        other = normalize_sealed_source("SRC-04", b"Example workstation\n",
                                         source_path=ROOT + "sys_vendor")
        self.assertEqual(other.values[0].datum_path, "platform.dmi.sys_vendor")

    def test_two_source_artifacts_have_distinct_verified_original_bindings(self):
        paths = (ROOT + "product_name", ROOT + "sys_vendor")
        values = (b"Sample computer\n", b"Sample manufacturer\n")
        with self.recorded(values, paths) as (folder, engine, originals):
            manifest = build_canonical(folder, engine)
            self.assertEqual(manifest["observation_count"], 4)
            self.assertEqual(validate_canonical(folder), manifest)
            obs = json.loads((folder / "private/system.json").read_text())["observations"]
            sem = [x for x in obs if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in sem],
                             ["platform.dmi.product_name", "platform.dmi.sys_vendor"])
            for entry, original, raw in zip(sem, originals, values):
                self.assertEqual(entry["evidence_refs"], [original.evidence_id])
                self.assertEqual(entry["source_attempt_ids"], ["SRC-04-01"])
                self.assertEqual((folder / original.private_relative_path).read_bytes(), raw)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), original.sha256)
            statuses = json.loads((folder / "private/status_records.json").read_text())
            self.assertEqual(statuses["status_records"][0]["reason_code"], "OK")

    def test_optional_unavailable_attribute_does_not_create_fictional_value(self):
        with self.recorded(
            (b"Vendor\n",), (ROOT + "sys_vendor",),
            unavailable=("FileNotFoundError[2]:" + ROOT + "product_family",)
        ) as (folder, engine, original):
            build_canonical(folder, engine)
            obs = json.loads((folder / "private/system.json").read_text())["observations"]
            self.assertEqual(len(obs), 2)
            self.assertNotIn("platform.dmi.product_family",
                             [x["datum_path"] for x in obs])
            attempts = json.loads((folder / "private/source_attempts.json").read_text())
            self.assertEqual(len(attempts["attempts"][0]["unavailable_fields"]), 1)
            self.assertEqual(validate_canonical(folder)["original_byte_count"], 7)

    def test_mismatched_path_count_order_duplicate_and_identity_fail_closed(self):
        cases = [
            ((b"A\n",), (), None),
            ((b"A\n",), (ROOT + "product_name", ROOT + "sys_vendor"), None),
            ((b"A\n", b"B\n"), (ROOT + "sys_vendor", ROOT + "product_name"), None),
            ((b"A\n", b"B\n"), (ROOT + "product_name", ROOT + "product_name"), None),
            ((b"A\n",), (ROOT + "product_name",), ("item0002",)),
        ]
        for values, paths, names in cases:
            with self.subTest(values=values, paths=paths, names=names):
                with self.recorded(values, paths, names=names) as (folder, engine, originals):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, engine)
                    self.assertFalse((folder / "private/session_manifest.json").exists())

    def test_forged_or_unsafe_paths_are_rejected_without_host_io(self):
        invalid = (
            ROOT + "product_serial",
            ROOT + "../product_name",
            ROOT + "product_name/../sys_vendor",
            "/etc/os-release",
            "/sys/class/dmi/id//product_name",
            "/sys/class/dmi/id/product_name ",
            "/sys/class/dmi/id/product_name\x00",
            "TOOL_RESOLVER/product_name",
        )
        for path in invalid:
            with self.subTest(path=path):
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-04", b"known value\n",
                                            source_path=path)
                with self.recorded((b"known value\n",), (path,)) as (folder, engine, original):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, engine)
                    self.assertFalse((folder / "private/session_manifest.json").exists())

    def test_cross_run_forgery_is_rejected(self):
        with self.recorded((b"A\n",), (ROOT + "sys_vendor",),
                           tamper_run=True) as (folder, engine, original):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder, engine)
            self.assertFalse((folder / "private/session_manifest.json").exists())

    def test_actual_parser_error_preserves_original_and_has_evidenced_status(self):
        for value in (b"\xff", b"a\x00b", b"a\nb\n", b"x" * 5000):
            with self.subTest(value=value[:15]):
                with self.recorded((value,), (ROOT + "board_name",)) as (folder, engine, original):
                    manifest = build_canonical(folder, engine)
                    self.assertEqual(manifest["observation_count"], 1)
                    statuses = json.loads((folder / "private/status_records.json").read_text())
                    self.assertEqual(statuses["status_records"][0]["reason_code"],
                                     "PARSE_FAILED")
                    self.assertEqual((folder / original[0].private_relative_path).read_bytes(),
                                     value)
                    self.assertEqual(validate_canonical(folder), manifest)

    def test_empty_value_is_not_fabricated_as_hardware_identity(self):
        with self.recorded((b"\n",), (ROOT + "product_name",)) as (folder, engine, original):
            build_canonical(folder, engine)
            obs = json.loads((folder / "private/system.json").read_text())["observations"]
            semantic = [x for x in obs if x["transformation_ids"]][0]
            self.assertEqual(semantic["normalized_value"], "")
            self.assertEqual(semantic["observed_value"], "\n")


if __name__ == "__main__":
    unittest.main()
