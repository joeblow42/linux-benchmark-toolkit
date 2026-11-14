"""RP-02 Increment 42: O1 time/count/helper cumulative-limit feasibility.

Source-first negative and boundary oracles only. No devices, sudo, real helper
process, or changes to protected limit/protocol/consent/command contracts.
These are candidate fixtures, not independent CP-02 or FAT acceptance.
"""
import json
import unittest
from unittest.mock import patch

import test_g5_cp03_rp02_o1_writer_39 as prior
import test_g5_root_helper as root_tests
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical
from lbt_g5.evidence import EvidenceWriter, RunMeter
from lbt_g5.o1 import OptionalSourcePlan
from lbt_g5.o1_execution import execute_optional
from lbt_g5.records import build_attempt
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceConsent, SourceRequest, initial_source_policies
from datetime import datetime, timezone
from pathlib import Path
import tempfile

POL = {p.source_id: p for p in initial_source_policies()}
RUN = prior.RUN
O1 = ("SRC-13", "SRC-18", "SRC-21")


class O1TimeCountAndHelperOracles(unittest.TestCase):
    def request_plan(self, source):
        upstream, path, data, target, argv = prior.SOURCES[source]
        op = POL[source].operation_id
        consent = SourceConsent(RUN, source, op, target,
                                datetime.now(timezone.utc), True)
        request = SourceRequest(RUN, source, op, target=target,
                                consent=consent,
                                trusted_targets=frozenset((target,)))
        plan = OptionalSourcePlan(
            source, op, target, argv,
            POL[source].per_target_bytes or POL[source].max_bytes,
            POL[source].per_target_seconds or POL[source].max_seconds,
            "registered source impact")
        return request, plan

    def denied_without_execution(self, source, calls, subcall):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        folder = Path(tmp.name) / RUN
        folder.mkdir(mode=0o700)
        writer = EvidenceWriter(str(folder), RUN, RunMeter())
        request, plan = self.request_plan(source)
        with patch("lbt_g5.o1_execution.plan_optional",
                   return_value=plan), \
             patch("lbt_g5.o1_execution._resolve_executable",
                   side_effect=AssertionError("no binary may resolve")), \
             patch("lbt_g5.o1_execution._capture_child",
                   side_effect=AssertionError("no direct child may run")):
            outcome = execute_optional(request, "%02d" % (subcall + 1),
                                       subcall, writer, ProbeSlots(), calls)
        self.assertEqual((outcome["disposition"], outcome["reason"]),
                         ("DENIED", "SOURCE_CALL_LIMIT"))
        self.assertEqual(outcome["receipts"], ())
        self.assertNotIn("limit_witnesses", outcome)

    def test_42_01_exact_call_count_and_next_nonexecuted_attempt(self):
        for source in O1:
            with self.subTest(source=source):
                calls = SourceCallBudget()
                count = POL[source].max_entries
                self.assertEqual(count, {"SRC-13": 32, "SRC-18": 4,
                                         "SRC-21": 1}[source])
                for i in range(count):
                    self.assertTrue(calls.begin(RUN, source, i))
                    calls.end(RUN, source, 0.0)
                self.assertFalse(calls.begin(RUN, source, count))
                self.denied_without_execution(source, calls, count)

    def test_42_02_cumulative_elapsed_does_not_create_executed_limit(self):
        for source in O1:
            with self.subTest(source=source):
                calls = SourceCallBudget()
                self.assertTrue(calls.begin(RUN, source, 0))
                calls.end(RUN, source, float(POL[source].max_seconds))
                self.assertEqual(calls.remaining(RUN, source), 0.0)
                self.denied_without_execution(source, calls, 1)

    def test_42_03_timeout_is_not_applied_threshold_attestation(self):
        for source in O1:
            with self.subTest(source=source):
                seconds = (POL[source].per_target_seconds or
                           POL[source].max_seconds)
                captured = TransportCapture(b"RAW", b"", None,
                                            float(seconds), True, False, 0, 0)
                folder, receipt, run, recorded, _ = (
                    prior.O1RunWriterOracles.fixture(
                        self, source, retained=5, captured=captured,
                        helper=(source == "SRC-13")))
                self.assertEqual(receipt["reason"], "TIME_BUDGET_EXCEEDED")
                self.assertTrue(receipt["timed_out"])
                self.assertEqual(receipt["acquired_bytes"], 3)
                self.assertNotIn("limit_witnesses", receipt)
                self.assertEqual(recorded.outcome["limit_witnesses"], ())
                with self.assertRaisesRegex(CanonicalContractError,
                                            "dimension not evidenced"):
                    build_canonical(folder, run)

    def test_42_04_helper_effective_remaining_bounds_are_private(self):
        helper = root_tests.helper
        original = json.loads(root_tests.msg())
        usage = {original["run_id"]: (helper.MAX_RUN_BYTES - 7,
                       helper.MAX_RUN_SECONDS - 0.5)}
        bounded = helper._limit_run_request(original, usage)
        self.assertEqual((bounded["max_bytes"], bounded["max_seconds"]),
                         (7, 0.5))
        self.assertEqual((original["max_bytes"], original["max_seconds"]),
                         (4096, 2.0))
        self.assertEqual((helper.MAX_RUN_BYTES, helper.MAX_RUN_SECONDS),
                         (32 * 1024 * 1024, 60.0))

    def test_42_05_helper_exhaustion_is_denial_not_capture(self):
        helper = root_tests.helper
        original = json.loads(root_tests.msg())
        for consumed in ((helper.MAX_RUN_BYTES, 0.0),
                         (0, helper.MAX_RUN_SECONDS),
                         (helper.MAX_RUN_BYTES, helper.MAX_RUN_SECONDS)):
            with self.subTest(consumed=consumed):
                with self.assertRaisesRegex(
                    helper.Rejected, "RUN_BUDGET_EXHAUSTED"
                ):
                    helper._limit_run_request(original, {original["run_id"]: consumed})

    def test_42_06_shortened_helper_byte_cap_cannot_be_inferred(self):
        captured = TransportCapture(b"H" * 7, b"", 0, 0.1,
                                    False, True, 1, 0)
        folder, receipt, run, _, _ = prior.O1RunWriterOracles.fixture(
            self, "SRC-13", retained=7, captured=captured, helper=True)
        self.assertEqual(receipt["reason"], "CAPTURE_LIMIT")
        self.assertEqual(receipt["missing_extent_known_at_least"], 1)
        self.assertNotIn("limit_witnesses", receipt)
        with self.assertRaisesRegex(CanonicalContractError,
                                    "dimension not evidenced"):
            build_canonical(folder, run)

    def test_42_07_shortened_helper_time_cap_cannot_be_inferred(self):
        captured = TransportCapture(b"T", b"", None, 0.5,
                                    True, False, 0, 0)
        folder, receipt, run, _, _ = prior.O1RunWriterOracles.fixture(
            self, "SRC-13", retained=5, captured=captured, helper=True)
        self.assertEqual(receipt["reason"], "TIME_BUDGET_EXCEEDED")
        self.assertTrue(receipt["timed_out"])
        self.assertNotIn("limit_witnesses", receipt)
        with self.assertRaisesRegex(CanonicalContractError,
                                    "dimension not evidenced"):
            build_canonical(folder, run)

    def test_42_08_unexecuted_call_or_source_time_fact_rejected(self):
        for unit, scope, reason, missing in (
            ("entries", "source:entries", "CAPTURE_LIMIT", None),
            ("seconds", "source:time", "TIME_BUDGET_EXCEEDED", None),
        ):
            fact = dict(unit=unit, threshold=4 if unit=="entries" else 20,
                        observed_extent=4 if unit=="entries" else 20,
                        missing_extent=missing,
                        affected_scope="SRC-18:call0001:" + scope,
                        reason=reason)
            with self.subTest(unit=unit), self.assertRaises(ValueError):
                build_attempt(RUN, "SRC-18", "01", "ALLOW", "PARTIAL",
                              reason, timed_out=(unit=="seconds"),
                              capture_limited=(unit=="entries"),
                              limit_witnesses=(fact,))

    def test_42_09_no_applied_cap_attestation_in_helper_response(self):
        from lbt_g5.runtime import TransportCapture
        self.assertNotIn("applied_max_seconds",
                         TransportCapture.__dataclass_fields__)
        self.assertNotIn("applied_max_bytes",
                         TransportCapture.__dataclass_fields__)
        self.assertNotIn("source_call_count",
                         TransportCapture.__dataclass_fields__)


if __name__ == "__main__":
    unittest.main()
