"""RP-03.3 Increment 51: witnessed engine plan, normal and cancelled terminal.

No host probes or command execution. A FINISHED traversal only establishes
attempt coverage, never successful acquisition, benchmark or publication.
"""
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from lbt_g5.engine import UnifiedCollectorEngine
from lbt_g5.catalog import initial_catalog
from lbt_g5.safety import SourceRequest, initial_source_policies

RUN = "run-2026320223348"


def dummy():
    return SimpleNamespace(outcome=SimpleNamespace(
        disposition="DENIED", source_paths=(), artifacts=()))


class SessionExecutionWitness51(unittest.TestCase):
    def setUp(self):
        self.calls = []

    def engine(self):
        # The source dispatcher is mocked: no EvidenceWriter, subprocess,
        # privileged helper or physical host collection is touched.
        return UnifiedCollectorEngine("/tmp/lbt-increment51-unused", RUN)

    def record(self, request, attempt, *args, **kwargs):
        self.calls.append((request.source_id, attempt, kwargs["subcall"]))
        return dummy()

    def test_51_01_finished_selected_scope_and_monotonic_session_clock(self):
        with patch("lbt_g5.engine.capture_and_record", side_effect=self.record):
            run = self.engine().run(("COL-MEM",))
        ex = run.execution
        self.assertEqual(ex.terminal_state, "FINISHED")
        self.assertEqual(ex.selected_collector_ids, ("COL-MEM",))
        self.assertEqual(ex.selected_source_ids, ("SRC-08", "SRC-09", "SRC-10"))
        self.assertEqual(ex.planned_attempt_ids,
                         ("SRC-08-01", "SRC-09-01", "SRC-10-01"))
        self.assertEqual(run.source_attempt_count, 3)
        self.assertEqual([x[0] for x in self.calls], list(ex.selected_source_ids))
        a = datetime.fromisoformat(ex.started_utc.replace("Z", "+00:00"))
        b = datetime.fromisoformat(ex.completed_utc.replace("Z", "+00:00"))
        self.assertLessEqual(a, b)
        self.assertGreaterEqual(ex.elapsed_ms, 0)
        self.assertTrue(run.canonical_status_pending)

    def test_51_02_real_planned_count_accounts_for_fixed_two_call_d1(self):
        pol = {x.source_id: x for x in initial_source_policies()}
        cid = pol["SRC-23"].collector_id
        with patch("lbt_g5.engine.capture_and_record", side_effect=self.record):
            run = self.engine().run((cid,))
        self.assertEqual(
            [aid for aid in run.execution.planned_attempt_ids
             if aid.startswith("SRC-23-")], ["SRC-23-01", "SRC-23-02"])
        self.assertEqual(
            [sid for sid, attempt, call in self.calls if sid == "SRC-23"],
            ["SRC-23", "SRC-23"])
        self.assertEqual(run.execution.terminal_state, "FINISHED")

    def test_51_03_optional_o1_multi_target_has_exact_selected_attempts(self):
        pol = {p.source_id: p for p in initial_source_policies()}["SRC-13"]
        targets = ("/dev/sda", "/dev/sdb")
        requests = tuple(SourceRequest(RUN, "SRC-13", pol.operation_id,
                                       target=target) for target in targets)
        with patch("lbt_g5.engine.capture_and_record", side_effect=self.record):
            run = self.engine().run(("COL-BLOCK",),
                                    o1_requests={"SRC-13": requests})
        self.assertEqual(
            [x for x in run.execution.planned_attempt_ids
             if x.startswith("SRC-13-")], ["SRC-13-01", "SRC-13-02"])
        self.assertEqual(
            [(sid, attempt) for sid, attempt, _ in self.calls
             if sid == "SRC-13"], [("SRC-13", "01"), ("SRC-13", "02")])
        self.assertEqual(run.source_attempt_count,
                         len(run.execution.planned_attempt_ids))

    def test_51_04_cancel_before_first_attempt_keeps_full_plan(self):
        with patch("lbt_g5.engine.capture_and_record", side_effect=self.record):
            run = self.engine().run(("COL-MEM",), cancel_requested=lambda: True)
        self.assertEqual(run.execution.terminal_state, "INTERRUPTED")
        self.assertEqual(run.execution.planned_attempt_ids,
                         ("SRC-08-01", "SRC-09-01", "SRC-10-01"))
        self.assertEqual(run.source_attempt_count, 0)
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(len(run.collectors), 1)
        self.assertEqual(run.collectors[0].source_attempts, ())

    def test_51_05_cancel_after_one_call_keeps_only_actual_receipts(self):
        with patch("lbt_g5.engine.capture_and_record", side_effect=self.record):
            run = self.engine().run(("COL-MEM",),
                                    cancel_requested=lambda: len(self.calls) > 0)
        self.assertEqual(run.execution.terminal_state, "INTERRUPTED")
        self.assertEqual(run.source_attempt_count, 1)
        self.assertEqual(self.calls, [("SRC-08", "01", 0)])
        self.assertEqual(len(run.execution.planned_attempt_ids), 3)
        self.assertEqual(len(run.collectors[0].source_attempts), 1)

    def test_51_06_finishing_a_denied_call_does_not_mean_success(self):
        with patch("lbt_g5.engine.capture_and_record", side_effect=self.record):
            run = self.engine().run(("COL-VAAPI",))
        self.assertEqual(run.execution.terminal_state, "FINISHED")
        self.assertEqual(run.source_attempt_count, 1)
        self.assertEqual(run.execution.planned_attempt_ids, ("SRC-21-01",))
        self.assertEqual(run.collectors[0].source_attempts[0].outcome.disposition,
                         "DENIED")

    def test_51_07_bad_cancellation_api_is_not_silently_treated_as_true(self):
        with self.assertRaises(TypeError):
            self.engine().run(("COL-MEM",), cancel_requested=object())
        with patch("lbt_g5.engine.capture_and_record", side_effect=self.record):
            with self.assertRaises(TypeError):
                self.engine().run(("COL-MEM",), cancel_requested=lambda: "yes")
        self.assertEqual(self.calls, [])

    def test_51_08_exception_does_not_issue_a_finished_witness(self):
        def fail(*args, **kwargs):
            raise OSError("ordinary source adapter error")
        with patch("lbt_g5.engine.capture_and_record", side_effect=fail):
            with self.assertRaisesRegex(OSError, "adapter error"):
                self.engine().run(("COL-MEM",))
        # An exception is never converted into FINISHED or INTERRUPTED by
        # the new witness feature. Already persisted source receipts remain.
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
