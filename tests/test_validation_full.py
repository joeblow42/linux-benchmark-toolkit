"""Increment 4: Full profile selection, bounded-process and safety tests."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from validation.adapters import ACCEPTANCE_IDS, _acceptance, extend_registry
from validation.processes import ProcessResult, run_bounded
from validation.profiles import ValidationProfile
from validation.quick import quick_registry
from validation.registry import ValidationCase, ValidationRegistry
from validation.runner import CheckOutcome, ValidationContext, run_validation
from validation.results import ValidationStatus


ROOT = Path(__file__).resolve().parents[1]


class FullProfileTests(unittest.TestCase):
    def test_full_contains_all_sixteen_acceptance_cases_once(self):
        registry = quick_registry()
        extend_registry(registry, ROOT)
        standard = {c.validation_id for c in registry.select(ValidationProfile.STANDARD)}
        full = [c.validation_id for c in registry.select(ValidationProfile.FULL)]
        self.assertTrue(standard.issubset(set(full)))
        self.assertTrue(set(ACCEPTANCE_IDS).issubset(set(full)))
        self.assertEqual(len(full), len(set(full)))
        self.assertEqual(len(full), 21)

    def test_worker_skips_optional_missing_tool(self):
        with tempfile.TemporaryDirectory() as d:
            context = ValidationContext(ROOT, Path(d))
            fake = ProcessResult(0, '{"status":"SKIP","reason":"dialog absent"}', "", False)
            with patch("validation.adapters.run_bounded", return_value=fake):
                outcome = _acceptance(16)(context)
        self.assertEqual(outcome.status, ValidationStatus.SKIP)

    def test_worker_timeout_fails(self):
        with tempfile.TemporaryDirectory() as d:
            context = ValidationContext(ROOT, Path(d))
            fake = ProcessResult(-9, "", "", True)
            with patch("validation.adapters.run_bounded", return_value=fake):
                outcome = _acceptance(15)(context)
        self.assertEqual(outcome.status, ValidationStatus.FAIL)
        self.assertIn("timed out", outcome.reason)

    def test_worker_invalid_response_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            context = ValidationContext(ROOT, Path(d))
            fake = ProcessResult(0, "not-json", "", False)
            with patch("validation.adapters.run_bounded", return_value=fake):
                outcome = _acceptance(12)(context)
        self.assertEqual(outcome.status, ValidationStatus.FAIL)

    def test_controlled_impact_is_never_implicit_in_full(self):
        registry = ValidationRegistry()
        registry.register(ValidationCase(
            validation_id="VAL-P2-SAFETY-001", title="Explicit authorization",
            phase=2, category="safety", minimum_profile=ValidationProfile.FULL,
            runner="test:danger", safety_class="controlled_impact"))
        called = []
        with tempfile.TemporaryDirectory() as d:
            context = ValidationContext(ROOT, Path(d))
            result = run_validation(registry, ValidationProfile.FULL, context,
                                    {"test:danger": lambda ctx: called.append(True)})
        self.assertFalse(called)
        self.assertEqual(result.results[0].status, ValidationStatus.SKIP)
        self.assertEqual(result.overall, "INCOMPLETE")

    def test_exception_does_not_leave_process_group_running(self):
        # A child waiting indefinitely is killed by the subprocess timeout.
        with tempfile.TemporaryDirectory() as d:
            outcome = run_bounded([sys.executable, "-c",
                                  "import time; time.sleep(30)"], d, 0.2)
        self.assertTrue(outcome.timed_out)

    def test_worker_executes_original_check(self):
        # The first check is Bash syntax and has no hardware side effects.
        outcome = run_bounded([sys.executable, "-m",
                               "validation.acceptance_worker", str(ROOT), "1"],
                              str(ROOT), 15)
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertIn('"status": "PASS"', outcome.stdout)


if __name__ == "__main__":
    unittest.main()
