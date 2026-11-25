"""RP-03.3 Increment 53: real unprivileged Linux host lifecycle smoke.

Only existing G5-03 D0 memory procfs sources, in a disposable local run
directory. No sudo, network, O1 device, disk benchmark or public report.
CI-host smoke is NOT physical Bodhi 7 first-article acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import UnifiedCollectorEngine
from lbt_g5.private_inventory import read_private_inventory

RUN = "run-2026320223348"
SELECTED = ("SRC-08", "SRC-09", "SRC-10")
EXPECTED_PLAN = ("SRC-08-01", "SRC-09-01", "SRC-10-01")


@unittest.skipIf(os.geteuid() == 0, "G4-07 prohibits root acquisition")
class RealLinuxLifecycle53(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name) / RUN
        self.folder.mkdir(mode=0o700)

    def acquire(self, *, cancel_requested=None):
        engine = UnifiedCollectorEngine(str(self.folder), RUN)
        return engine.run(("COL-MEM",), cancel_requested=cancel_requested)

    def materialize(self, run):
        with patch("subprocess.run", side_effect=AssertionError(
                "private canonicalization must not issue a host command")):
            manifest = build_canonical(self.folder, run)
            self.assertEqual(validate_canonical(self.folder), manifest)
            view = read_private_inventory(self.folder)
        system = json.loads((self.folder / "private/system.json").read_text())
        statuses = json.loads((self.folder / "private/status_records.json").read_text())["status_records"]
        session = next(s for s in statuses if s["domain"] == "orchestration")
        acquisitions = [s for s in statuses if s["domain"] == "acquisition"]
        return manifest, system, session, acquisitions, view

    def test_53_01_actual_memory_sources_reconcile_with_factual_statuses(self):
        run = self.acquire()
        self.assertEqual(run.execution.terminal_state, "FINISHED")
        self.assertEqual(run.execution.planned_attempt_ids, EXPECTED_PLAN)
        self.assertEqual(run.source_attempt_count, 3)
        manifest, system, session, acquisitions, view = self.materialize(run)
        self.assertEqual(manifest["counts"]["attempts"], 3)
        self.assertEqual([s["subject_id"] for s in acquisitions], list(SELECTED))
        all_captured = all(s["status"] == "COMPLETE" and
                           s["reason_code"] == "OK" for s in acquisitions)
        expected = (("COMPLETE", "COMMITTED", "COMPLETE", "ALL_REQUIRED_COMPLETE")
                    if all_captured else
                    ("PARTIAL", "INCOMPLETE", "PARTIAL", "MINIMUM_WITH_GAPS"))
        self.assertEqual((manifest["completion_state"],
                          system["header"]["lifecycle_state"],
                          session["status"], session["reason_code"]), expected)
        self.assertEqual(session["source_attempt_ids"], list(EXPECTED_PLAN))
        self.assertEqual(view["completion_state"], manifest["completion_state"])
        self.assertEqual(len(view["source_outcomes"]), 3)
        self.assertTrue(view["minimum_usable"])
        mem = next(s for s in view["source_outcomes"] if s["source_id"] == "SRC-08")
        self.assertEqual(mem["status"], "COMPLETE")
        total = [f for f in view["facts"]
                 if f["datum_path"] == "memory.meminfo.MemTotal"]
        self.assertEqual(len(total), 1)
        self.assertEqual(total[0]["unit"], "bytes")
        self.assertGreater(total[0]["normalized_value"], 0)
        self.assertFalse((self.folder / "public").exists())
        self.assertFalse((self.folder / "benchmarks.json").exists())
        for source in run.collectors[0].source_attempts:
            receipt = json.loads((self.folder / source.receipt_private_path).read_text())
            for item in source.outcome.artifacts:
                raw = (self.folder / item.private_relative_path).read_bytes()
                self.assertEqual(len(raw), item.byte_count)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item.sha256)
                self.assertIn(item.evidence_id, receipt["evidence_ids"])

    def test_53_02_actual_one_source_then_cooperative_interrupt_is_not_complete(self):
        attempts_checked = []
        def stop():
            attempts_checked.append(True)
            return len(attempts_checked) > 1
        run = self.acquire(cancel_requested=stop)
        self.assertEqual(run.execution.terminal_state, "INTERRUPTED")
        self.assertEqual(run.execution.planned_attempt_ids, EXPECTED_PLAN)
        self.assertEqual(run.source_attempt_count, 1)
        manifest, system, session, acquisitions, view = self.materialize(run)
        self.assertEqual(manifest["completion_state"], "INTERRUPTED")
        self.assertEqual(system["header"]["lifecycle_state"], "INTERRUPTED")
        self.assertEqual((session["status"], session["reason_code"]),
                         ("INTERRUPTED", "RUN_INTERRUPTED"))
        self.assertEqual([s["subject_id"] for s in acquisitions], ["SRC-08"])
        self.assertEqual(session["source_attempt_ids"], ["SRC-08-01"])
        self.assertEqual({s["source_id"] for s in view["source_outcomes"]}, {"SRC-08"})
        self.assertEqual(manifest["counts"]["sources"], 1)
        self.assertTrue(view["minimum_usable"])
        self.assertFalse((self.folder / "public").exists())

    def test_53_03_run_and_originals_removed_by_disposable_test_root(self):
        with tempfile.TemporaryDirectory() as workspace:
            path = Path(workspace) / RUN
            path.mkdir(mode=0o700)
            run = UnifiedCollectorEngine(str(path), RUN).run(
                ("COL-MEM",), cancel_requested=lambda: True)
            self.assertEqual(run.source_attempt_count, 0)
            manifest = build_canonical(path, run)
            self.assertEqual(validate_canonical(path), manifest)
            self.assertEqual(manifest["completion_state"], "INTERRUPTED")
            self.assertFalse((path / "private/evidence").exists())
            self.assertFalse((path / "public").exists())
            private_dir = path / "private"
            self.assertEqual(private_dir.stat().st_mode & 0o077, 0)
            self.assertEqual((private_dir / "source_attempt_records").stat().st_mode & 0o077, 0)
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
