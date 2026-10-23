"""Increment 2 controller and Quick-profile regression tests."""
from pathlib import Path
import tempfile
import time
import unittest

from validation import ValidationCase, ValidationProfile, ValidationRegistry, ValidationStatus
from validation.runner import CheckOutcome, ValidationContext, run_validation
from validation.quick import RUNNERS, quick_registry


def make_case(cid, runner="test:pass", **kw):
    settings = dict(validation_id=cid, title=cid, phase=1, category="test",
                    minimum_profile=ValidationProfile.QUICK, runner=runner)
    settings.update(kw)
    return ValidationCase(**settings)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name)
        self.context = ValidationContext(root=path, results_dir=path / "results")

    def test_order_and_exactly_once(self):
        reg = ValidationRegistry()
        reg.register(make_case("VAL-P1-B", dependencies=("VAL-P1-A",)))
        reg.register(make_case("VAL-P1-A"))
        called = []
        def success(context):
            called.append(True)
        result = run_validation(reg, ValidationProfile.FULL, self.context, {"test:pass": success})
        self.assertEqual(result.overall, "PASS")
        self.assertEqual([r.validation_id for r in result.results], ["VAL-P1-A", "VAL-P1-B"])
        self.assertEqual(len(called), 2)

    def test_missing_prerequisite_blocks(self):
        reg = ValidationRegistry()
        reg.register(make_case("VAL-P1-A", prerequisites=("missing-tool",)))
        outcome = run_validation(reg, ValidationProfile.QUICK, self.context, {"test:pass": lambda _: None},
                                 prerequisite_available=lambda _: False)
        self.assertEqual(outcome.results[0].status, ValidationStatus.BLOCKED)
        self.assertEqual(outcome.overall, "INCOMPLETE")

    def test_failures_isolated_and_dependency_blocked(self):
        reg = ValidationRegistry()
        reg.register(make_case("VAL-P1-A", runner="test:fail"))
        reg.register(make_case("VAL-P1-B", dependencies=("VAL-P1-A",)))
        reg.register(make_case("VAL-P1-C"))
        seen = []
        def fail(_):
            raise RuntimeError("fixture failure")
        def passed(_):
            seen.append("pass")
        out = run_validation(reg, ValidationProfile.QUICK, self.context,
                             {"test:fail": fail, "test:pass": passed})
        self.assertEqual([r.status for r in out.results], [
            ValidationStatus.FAIL, ValidationStatus.BLOCKED, ValidationStatus.PASS])
        self.assertEqual(seen, ["pass"])
        self.assertEqual(out.overall, "FAIL")

    def test_safety_and_applicability(self):
        reg = ValidationRegistry()
        reg.register(make_case("VAL-P1-A", safety_class="controlled_impact"))
        reg.register(make_case("VAL-P1-B", applicability="never"))
        out = run_validation(reg, ValidationProfile.QUICK, self.context,
                             {"test:pass": lambda _: None})
        self.assertEqual([r.status for r in out.results], [
            ValidationStatus.SKIP, ValidationStatus.NOT_APPLICABLE])
        self.assertEqual(out.overall, "INCOMPLETE")

    def test_advisory_timeout_metadata_marks_overrun(self):
        reg = ValidationRegistry()
        reg.register(make_case("VAL-P1-TIMING-001", timeout_seconds=0.001))
        def slow(_):
            time.sleep(0.015)
        out = run_validation(reg, ValidationProfile.QUICK, self.context,
                             {"test:pass": slow})
        self.assertEqual(out.results[0].status, ValidationStatus.FAIL)
        self.assertEqual(out.overall, "FAIL")

    def test_unknown_runner_blocks(self):
        reg = ValidationRegistry()
        reg.register(make_case("VAL-P1-A", runner="unregistered"))
        out = run_validation(reg, ValidationProfile.QUICK, self.context, {})
        self.assertEqual(out.results[0].status, ValidationStatus.BLOCKED)

    def test_explicit_nonpass_outcome(self):
        reg = ValidationRegistry()
        reg.register(make_case("VAL-P1-A"))
        out = run_validation(reg, ValidationProfile.QUICK, self.context,
                             {"test:pass": lambda _: CheckOutcome(
                                 ValidationStatus.NOT_APPLICABLE, "fixture not applicable")})
        self.assertEqual(out.results[0].status, ValidationStatus.NOT_APPLICABLE)
        self.assertEqual(out.overall, "INCOMPLETE")

    def test_standard_includes_quick_once(self):
        reg = ValidationRegistry()
        reg.register(make_case("VAL-P1-A"))
        reg.register(make_case("VAL-P2-B", minimum_profile=ValidationProfile.STANDARD))
        reg.register(make_case("VAL-P2-C", minimum_profile=ValidationProfile.FULL))
        out = run_validation(reg, ValidationProfile.STANDARD, self.context,
                             {"test:pass": lambda _: None})
        self.assertEqual(len(out.results), 2)
        self.assertEqual(len({r.validation_id for r in out.results}), 2)


class QuickTests(unittest.TestCase):
    def test_quick_on_repository_fixture(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            out = run_validation(
                quick_registry(), ValidationProfile.QUICK,
                ValidationContext(root=root, results_dir=Path(temp)), RUNNERS)
            self.assertEqual(out.overall, "PASS",
                             [(r.validation_id, r.reason) for r in out.results])
            self.assertEqual(len(out.results), 4)


if __name__ == "__main__":
    unittest.main()
