"""RP-03.3 Increment 52: actual witnessed plan -> D-02 lifecycle integration.

Sealed G5-03 source bytes/receipts from a mocked fixed dispatcher, real
UnifiedCollectorEngine selection, approved canonical producer, validator and
private consumer. No physical collection, device/probe, sudo or benchmark.
"""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import UnifiedCollectorEngine, CollectorRun, EngineRun
from lbt_g5.private_inventory import read_private_inventory
from lbt_g5.receipt_dispatch import RecordedOutcome
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies
from lbt_g5.session_lifecycle import (
    reconcile_execution, validate_persisted_lifecycle,
)

RUN = "run-2026320223348"
P = {s.source_id: s for s in initial_source_policies()}
BYTES = {
    "SRC-08": b"MemTotal: 1024 kB\nMemFree: 128 kB\n",
    "SRC-09": b"Filename Type Size Used Priority\n/swapfile file 1024 16 -2\n",
    "SRC-10": (b"some avg10=0.01 avg60=0.02 avg300=0.03 total=123\n"
               b"full avg10=0.00 avg60=0.04 avg300=0.05 total=456\n"),
}


class CanonicalLifecycle52(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name) / RUN
        self.folder.mkdir(mode=0o700)
        self.events = []
        self.originals = []

    def dispatch(self, request, attempt, writer, *rest, unavailable=(), **kw):
        sid = request.source_id
        self.events.append(sid)
        missing = sid in unavailable
        artifacts = ()
        if not missing:
            art = writer.seal_chunks(P[sid], attempt, "item0001", (BYTES[sid],)).receipt
            self.assertIsNotNone(art)
            self.originals.append((art, BYTES[sid]))
            artifacts = (art,)
        record = build_attempt(
            RUN, sid, attempt, "ALLOW",
            "UNAVAILABLE" if missing else "CAPTURED",
            "SOURCE_ABSENT" if missing else "BYTES_PRESERVED",
            evidence=artifacts,
            bytes_count=sum(item.byte_count for item in artifacts))
        return RecordedOutcome(
            SimpleNamespace(artifacts=artifacts),
            commit_attempt(str(self.folder), record))

    def acquire(self, *, missing=(), stop_after=None):
        engine = UnifiedCollectorEngine(str(self.folder), RUN)
        def fake(request, attempt, writer, *args, **kwargs):
            return self.dispatch(request, attempt, writer, *args,
                                 unavailable=missing, **kwargs)
        callback = (None if stop_after is None else
                    lambda: len(self.events) >= stop_after)
        with patch("lbt_g5.engine.capture_and_record", side_effect=fake):
            return engine.run(("COL-MEM",), cancel_requested=callback)

    def finalize(self, run):
        with patch("subprocess.run", side_effect=AssertionError("no new probes")):
            manifest = build_canonical(self.folder, run)
            self.assertEqual(validate_canonical(self.folder), manifest)
            view = read_private_inventory(self.folder)
        header = json.loads(
            (self.folder / "private/system.json").read_text())["header"]
        statuses = json.loads(
            (self.folder / "private/status_records.json").read_text())["status_records"]
        session = next(s for s in statuses if s["domain"] == "orchestration")
        return manifest, header, session, view

    def test_52_01_all_selected_source_attempts_complete(self):
        run = self.acquire()
        manifest, header, session, view = self.finalize(run)
        self.assertEqual(self.events, ["SRC-08", "SRC-09", "SRC-10"])
        self.assertEqual(manifest["completion_state"], "COMPLETE")
        self.assertEqual(header["lifecycle_state"], "COMMITTED")
        self.assertEqual((session["status"], session["reason_code"]),
                         ("COMPLETE", "ALL_REQUIRED_COMPLETE"))
        self.assertEqual(view["completion_state"], "COMPLETE")
        self.assertTrue(view["minimum_usable"])
        self.assertEqual(session["source_attempt_ids"],
                         ["SRC-08-01", "SRC-09-01", "SRC-10-01"])
        self.assertIsNotNone(manifest["finalized_utc"])
        self.assertEqual(header["started_utc"], session["started_utc"])
        self.assertEqual(header["completed_utc"], session["completed_utc"])
        self.assertEqual(session["elapsed_ms"], run.execution.elapsed_ms)
        self.assertTrue(all(src["status"] == "COMPLETE"
                            for src in view["source_outcomes"]))
        self.assertNotIn("benchmark", " ".join(f["datum_path"]
                                            for f in view["facts"]))
        for artifact, raw in self.originals:
            self.assertEqual((self.folder / artifact.private_relative_path).read_bytes(), raw)

    def test_52_02_finished_with_missing_source_is_only_partial(self):
        run = self.acquire(missing=("SRC-09",))
        manifest, header, session, view = self.finalize(run)
        self.assertEqual(run.execution.terminal_state, "FINISHED")
        self.assertEqual((header["lifecycle_state"], manifest["completion_state"]),
                         ("INCOMPLETE", "PARTIAL"))
        self.assertEqual((session["status"], session["reason_code"]),
                         ("PARTIAL", "MINIMUM_WITH_GAPS"))
        missing = next(s for s in view["source_outcomes"] if s["source_id"] == "SRC-09")
        self.assertEqual((missing["status"], missing["reason_code"]),
                         ("UNAVAILABLE", "SOURCE_ABSENT"))
        self.assertFalse(any(f["datum_path"] == "memory.swap.entries"
                             for f in view["facts"]))

    def test_52_03_interrupt_after_one_actual_source_not_success(self):
        run = self.acquire(stop_after=1)
        self.assertEqual(run.execution.terminal_state, "INTERRUPTED")
        self.assertEqual(run.source_attempt_count, 1)
        manifest, header, session, view = self.finalize(run)
        self.assertEqual(self.events, ["SRC-08"])
        self.assertEqual((header["lifecycle_state"], manifest["completion_state"]),
                         ("INTERRUPTED", "INTERRUPTED"))
        self.assertEqual((session["status"], session["reason_code"]),
                         ("INTERRUPTED", "RUN_INTERRUPTED"))
        self.assertEqual(session["source_attempt_ids"], ["SRC-08-01"])
        self.assertTrue(all(f["source_id"] == "SRC-08" for f in view["facts"]))
        self.assertEqual(view["sealed_original_artifact_count"], 1)
        self.assertIn("SRC-10-01", session["detail"])

    def test_52_04_cancel_before_source_zero_observations_allowed(self):
        run = self.acquire(stop_after=0)
        self.assertEqual(run.source_attempt_count, 0)
        manifest, header, session, view = self.finalize(run)
        self.assertEqual(manifest["counts"]["observations"], 0)
        self.assertTrue(manifest["minimum_usable"])
        self.assertEqual(manifest["completion_state"], "INTERRUPTED")
        self.assertEqual(header["collector_ids"], ["COL-MEM"])
        self.assertEqual(session["status"], "INTERRUPTED")
        self.assertEqual(session["source_attempt_ids"], [])
        self.assertEqual(view["facts"], [])

    def test_52_05_missing_recorded_attempt_cannot_be_completed(self):
        run = self.acquire()
        dropped = replace(run, collectors=(CollectorRun(
            "COL-MEM", run.collectors[0].source_attempts[:-1]),))
        with self.assertRaises(CanonicalContractError):
            build_canonical(self.folder, dropped)
        self.assertFalse((self.folder / "private/session_manifest.json").exists())

    def test_52_06_out_of_order_recorded_attempt_cannot_be_completed(self):
        run = self.acquire()
        records = run.collectors[0].source_attempts
        scrambled = replace(run, collectors=(CollectorRun(
            "COL-MEM", (records[1], records[0], records[2])),))
        with self.assertRaises(CanonicalContractError):
            build_canonical(self.folder, scrambled)
        self.assertFalse((self.folder / "private/session_manifest.json").exists())

    def test_52_07_no_witness_preserves_conservative_incomplete(self):
        run = self.acquire()
        legacy = replace(run, execution=None)
        manifest, header, session, view = self.finalize(legacy)
        self.assertEqual(manifest["completion_state"], "INCOMPLETE")
        self.assertEqual(header["lifecycle_state"], "INCOMPLETE")
        self.assertEqual((session["status"], session["reason_code"]),
                         ("PARTIAL", "MINIMUM_WITH_GAPS"))
        self.assertIsNone(header["started_utc"])
        self.assertIsNone(manifest["finalized_utc"])

    def test_52_08_pure_persisted_contradiction_rejected(self):
        run = self.acquire()
        manifest, header, session, view = self.finalize(run)
        raw_attempts = json.loads(
            (self.folder / "private/source_attempts.json").read_text())["attempts"]
        raw_statuses = json.loads(
            (self.folder / "private/status_records.json").read_text())["status_records"]
        bad_session = dict(session, reason_code="MINIMUM_WITH_GAPS")
        with self.assertRaises(CanonicalContractError):
            validate_persisted_lifecycle(header, manifest, bad_session,
                                         raw_attempts, raw_statuses)
        bad_manifest = dict(manifest, completion_state="PARTIAL")
        with self.assertRaises(CanonicalContractError):
            validate_persisted_lifecycle(header, bad_manifest, session,
                                         raw_attempts, raw_statuses)


if __name__ == "__main__":
    unittest.main()
