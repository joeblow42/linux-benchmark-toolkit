"""Unit-level checks for legacy adapter registration and once-only invocation."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from validation.adapters import ACCEPTANCE_IDS, UNIT_ID, extend_registry
from validation.profiles import ValidationProfile
from validation.quick import quick_registry
from validation.runner import CheckOutcome, ValidationContext, run_validation
from validation.results import ValidationStatus


ROOT = Path(__file__).resolve().parents[1]


class AdapterTests(unittest.TestCase):
    def test_all_sixteen_original_checks_are_registered(self):
        registry = quick_registry()
        runners = extend_registry(registry, ROOT)
        ids = {case.validation_id for case in registry.all_cases()}
        self.assertEqual(len(ACCEPTANCE_IDS), 16)
        self.assertTrue(set(ACCEPTANCE_IDS).issubset(ids))
        self.assertIn(UNIT_ID, ids)
        self.assertEqual(len(runners), 17)
        self.assertEqual(len(registry.select(ValidationProfile.QUICK)), 4)
        self.assertEqual(len(registry.select(ValidationProfile.STANDARD)), 16)
        self.assertEqual(len(registry.select(ValidationProfile.FULL)), 21)

    def test_unit_test_alias_never_invokes_unit_function_again(self):
        registry = quick_registry()
        runners = extend_registry(registry, ROOT)
        seen = []
        def fake_unit(context):
            seen.append("unit")
            return CheckOutcome(ValidationStatus.PASS)
        # Keep only the suite and alias to isolate the adapter contract.
        from validation.registry import ValidationRegistry
        filtered = ValidationRegistry()
        for item in registry.all_cases():
            if item.validation_id in (UNIT_ID, ACCEPTANCE_IDS[1]):
                filtered.register(item)
        runners["legacy:unittest"] = fake_unit
        with tempfile.TemporaryDirectory() as d:
            result = run_validation(
                filtered, ValidationProfile.FULL,
                ValidationContext(ROOT, Path(d)), runners)
        self.assertEqual(seen, ["unit"])
        self.assertEqual([r.status for r in result.results],
                         [ValidationStatus.PASS, ValidationStatus.PASS])
        self.assertIn(f"delegated-to:{UNIT_ID}", result.results[1].evidence)

    def test_failure_blocks_alias_without_reexecution(self):
        from validation.registry import ValidationRegistry
        registry = quick_registry()
        runners = extend_registry(registry, ROOT)
        filtered = ValidationRegistry()
        for item in registry.all_cases():
            if item.validation_id in (UNIT_ID, ACCEPTANCE_IDS[1]):
                filtered.register(item)
        seen = []
        def fail(context):
            seen.append(True)
            return CheckOutcome(ValidationStatus.FAIL, "simulated suite failure")
        runners["legacy:unittest"] = fail
        with tempfile.TemporaryDirectory() as d:
            result = run_validation(filtered, ValidationProfile.STANDARD,
                                    ValidationContext(ROOT, Path(d)), runners)
        self.assertEqual(len(seen), 1)
        self.assertEqual([r.status for r in result.results],
                         [ValidationStatus.FAIL, ValidationStatus.BLOCKED])


if __name__ == "__main__":
    unittest.main()
