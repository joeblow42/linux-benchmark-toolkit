"""CP-03 Increment 08: SRC-19 source-first DRM/PCI provenance oracles.

Contract-first expected outcomes: verification/g5_04/cp03_drm_sysfs_oracle_08.json.
Pure synthetic sealed originals, no DRM/device/GPU workload.
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
    SourceParseError, drm_sysfs_path_identity,
    normalize_sealed_source, parser_available,
)
from lbt_g5.passive_worker import ATTRS, ROOTS
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
ROOT = "/sys/class/drm/"
ATTRIBUTES = (
    "device/vendor", "device/device", "device/subsystem_vendor",
    "device/subsystem_device", "device/revision",
)


class DRMSourceFirstOracles(unittest.TestCase):
    @contextmanager
    def saved(self, raw_items, paths, *, names=None, unavailable=(),
              wrong_run=False, outcome="CAPTURED", reason="BYTES_PRESERVED"):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / RUN
            directory.mkdir(mode=0o700)
            pol = {p.source_id:p for p in initial_source_policies()}["SRC-19"]
            writer = EvidenceWriter(str(directory), RUN)
            names = names if names is not None else [
                f"item{i:04d}" for i in range(1, len(raw_items)+1)]
            self.assertEqual(len(names), len(raw_items))
            artifacts = []
            for name, raw in zip(names, raw_items):
                a = writer.seal_chunks(pol, "01", name, (raw,)).receipt
                self.assertIsNotNone(a)
                artifacts.append(a)
            attempt = build_attempt(
                RUN, "SRC-19", "01", "ALLOW", outcome, reason,
                evidence=tuple(artifacts), bytes_count=sum(x.byte_count for x in artifacts),
                source_paths=tuple(paths), unavailable_fields=tuple(unavailable))
            receipt_path = commit_attempt(str(directory), attempt)
            if wrong_run:
                artifacts[0] = replace(artifacts[0], run_id="run-2026305120001")
            record = SimpleNamespace(
                receipt_private_path=receipt_path,
                outcome=SimpleNamespace(artifacts=tuple(artifacts)))
            engine = EngineRun(RUN, (CollectorRun("COL-GPU", (record,)),))
            yield directory, engine, tuple(artifacts)

    def test_allowed_source_fields_and_unregistered_guard(self):
        self.assertEqual(ROOTS["SRC-19"], ROOT.rstrip("/"))
        self.assertEqual(ATTRS["SRC-19"], ATTRIBUTES)
        self.assertTrue(parser_available("SRC-19"))
        self.assertTrue(parser_available("SRC-13"))  # CP03-17 O1 verified stdout

    def test_sealed_identity_and_observation_provenance(self):
        paths = (ROOT + "card0/device/vendor", ROOT + "card0/device/device",
                 ROOT + "card0/device/subsystem_vendor", ROOT + "card1/device/revision")
        raws = (b"0x8086\n", b"0xA7a1\n", b"0x103C\n", b"0x02\n")
        with self.saved(raws, paths) as (directory, engine, artifacts):
            manifest = build_canonical(directory, engine)
            self.assertEqual(manifest["observation_count"], 8)
            self.assertEqual(validate_canonical(directory), manifest)
            sys = json.loads((directory / "private/system.json").read_text())
            sem = [x for x in sys["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in sem], [
                "gpu.drm.card0.pci.vendor", "gpu.drm.card0.pci.device",
                "gpu.drm.card0.pci.subsystem_vendor", "gpu.drm.card1.pci.revision"])
            self.assertEqual([x["normalized_value"] for x in sem],
                             ["0x8086", "0xa7a1", "0x103c", "0x02"])
            self.assertTrue(all(x["value_type"] == "STRING" for x in sem))
            self.assertFalse(any("capability" in x["datum_path"] or
                                 "gpu.model" in x["datum_path"] for x in sem))
            for raw, artifact, datum in zip(raws, artifacts, sem):
                self.assertEqual(datum["evidence_refs"], [artifact.evidence_id])
                self.assertEqual(datum["source_attempt_ids"], ["SRC-19-01"])
                self.assertEqual((directory / artifact.private_relative_path).read_bytes(), raw)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), artifact.sha256)

    def test_lexical_card10_before_card2_and_unavailable_attribute(self):
        paths = (ROOT + "card10/device/vendor", ROOT + "card2/device/vendor")
        with self.saved((b"0x1234\n", b"0x9999\n"), paths,
             unavailable=("FileNotFoundError[2]:" + ROOT + "card2/device/model",)
        ) as (directory, engine, _):
            build_canonical(directory, engine)
            records = json.loads((directory / "private/system.json").read_text())
            typed = [x for x in records["observations"] if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in typed],
                             ["gpu.drm.card10.pci.vendor", "gpu.drm.card2.pci.vendor"])
            attempts = json.loads((directory / "private/source_attempts.json").read_text())
            self.assertEqual(len(attempts["attempts"][0]["unavailable_fields"]), 1)

    def test_missing_source_is_not_fabricated(self):
        with self.saved((), (), outcome="UNAVAILABLE", reason="SOURCE_ABSENT"
        ) as (directory, engine, _):
            manifest = build_canonical(directory, engine)
            self.assertEqual(manifest["observation_count"], 0)
            self.assertEqual(validate_canonical(directory), manifest)

    def test_reordered_duplicate_count_and_artifact_ordinal_are_rejected(self):
        fixtures = (
            ((b"0x8086\n",), (), None),
            ((b"0x8086\n",), (ROOT + "card0/device/vendor",
                              ROOT + "card0/device/device"), None),
            ((b"0x8086\n", b"0x1234\n"),
             (ROOT + "card0/device/device", ROOT + "card0/device/vendor"), None),
            ((b"0x8086\n", b"0x1234\n"),
             (ROOT + "card0/device/vendor", ROOT + "card0/device/vendor"), None),
            ((b"0x8086\n", b"0x1234\n"),
             (ROOT + "card2/device/vendor", ROOT + "card10/device/vendor"), None),
            ((b"0x8086\n",), (ROOT + "card0/device/vendor",), ("item0002",)),
        )
        for raw, path, names in fixtures:
            with self.subTest(paths=path, names=names):
                with self.saved(raw, path, names=names) as (directory, engine, originals):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(directory, engine)
                    self.assertFalse((directory / "private/session_manifest.json").exists())

    def test_traversal_unapproved_card_and_render_paths_fail_closed(self):
        for path in (ROOT + "renderD128/device/vendor",
                     ROOT + "cardX/device/vendor",
                     ROOT + "card0/device/driver",
                     ROOT + "card0/device/../device/vendor",
                     ROOT + "../card0/device/vendor",
                     ROOT + "card0/device//vendor",
                     ROOT + "card0/device/vendor\x00",
                     "/dev/dri/renderD128", "/sys/class/block/card0/device/vendor"):
            with self.subTest(path=path):
                self.assertIsNone(drm_sysfs_path_identity(path))
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-19", b"0x1234\n", source_path=path)
                with self.saved((b"0x1234\n",), (path,)) as (directory, engine, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(directory, engine)

    def test_unknown_hex_syntax_only_and_invalid_parser_fallback(self):
        good = normalize_sealed_source("SRC-19", b"0xABCD\n",
               source_path=ROOT + "card0/device/device").values[0]
        self.assertEqual(good.normalized_value, "0xabcd")
        self.assertNotIn("model", good.datum_path)
        for value in (b"Intel\n", b"1234\n", b"0xGG\n", b"\xff\n",
                      b"0x1234\n0x5678\n", b"0x" + b"F"*5000):
            with self.subTest(value=value[:12]), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-19", value,
                  source_path=ROOT + "card0/device/vendor")
        with self.saved((b"\xff\n",), (ROOT + "card0/device/vendor",)
        ) as (directory, engine, originals):
            manifest = build_canonical(directory, engine)
            self.assertEqual(manifest["observation_count"], 1)
            status = json.loads((directory / "private/status_records.json").read_text())
            self.assertEqual(status["status_records"][0]["reason_code"], "PARSE_FAILED")
            self.assertEqual((directory / originals[0].private_relative_path).read_bytes(),
                             b"\xff\n")
            self.assertEqual(validate_canonical(directory), manifest)

    def test_cross_run_artifact_forgery_fails_before_manifest(self):
        with self.saved((b"0x8086\n",), (ROOT + "card0/device/vendor",),
                        wrong_run=True) as (directory, engine, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(directory, engine)
            self.assertFalse((directory / "private/session_manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
