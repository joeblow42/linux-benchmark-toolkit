"""Increment 1 registry/profile/result contract tests; no host probes are run."""

import unittest

from validation import (
    RegistryError, ValidationCase, ValidationProfile, ValidationRegistry,
    ValidationResult, ValidationStatus,
)


def case(cid="VAL-P1-CLI-001", profile=ValidationProfile.QUICK, **changes):
    fields = dict(validation_id=cid, title="CLI smoke check", phase=1,
                  category="cli", minimum_profile=profile,
                  runner="acceptance:cli_checks")
    fields.update(changes)
    return ValidationCase(**fields)


class ProfileTests(unittest.TestCase):
    def test_profile_parsing_and_order(self):
        self.assertEqual(ValidationProfile.parse(" standard "), ValidationProfile.STANDARD)
        self.assertTrue(ValidationProfile.FULL.includes(ValidationProfile.QUICK))
        self.assertFalse(ValidationProfile.QUICK.includes(ValidationProfile.FULL))

    def test_unknown_profile(self):
        with self.assertRaises(ValueError):
            ValidationProfile.parse("benchmark")


class RegistryTests(unittest.TestCase):
    def test_unique_registration_and_order(self):
        registry = ValidationRegistry()
        registry.register(case())
        registry.register(case("VAL-P2-INTEG-001", ValidationProfile.STANDARD,
                               dependencies=("VAL-P1-CLI-001",)))
        registry.register(case("VAL-P2-FULL-001", ValidationProfile.FULL))
        self.assertEqual(len(registry.select(ValidationProfile.QUICK)), 1)
        self.assertEqual(len(registry.select(ValidationProfile.STANDARD)), 2)
        self.assertEqual(len(registry.select(ValidationProfile.FULL)), 3)
        self.assertEqual([c.validation_id for c in registry.select(ValidationProfile.FULL)],
                         ["VAL-P1-CLI-001", "VAL-P2-FULL-001", "VAL-P2-INTEG-001"])
        self.assertEqual(registry.select(ValidationProfile.FULL),
                         registry.select(ValidationProfile.FULL))

    def test_duplicate_registration(self):
        registry = ValidationRegistry()
        registry.register(case())
        with self.assertRaises(RegistryError):
            registry.register(case())

    def test_invalid_requirements_and_safety(self):
        with self.assertRaises(RegistryError):
            case(requirement_ids=("WRONG-001",))
        with self.assertRaises(RegistryError):
            case(safety_class="root")
        with self.assertRaises(RegistryError):
            case(timeout_seconds=0)

    def test_missing_dependency(self):
        registry = ValidationRegistry()
        registry.register(case(dependencies=("VAL-P2-MISSING-001",)))
        with self.assertRaises(RegistryError):
            registry.validate()

    def test_cycle(self):
        registry = ValidationRegistry()
        registry.register(case("VAL-P1-A", dependencies=("VAL-P1-B",)))
        registry.register(case("VAL-P1-B", dependencies=("VAL-P1-A",)))
        with self.assertRaises(RegistryError):
            registry.select(ValidationProfile.FULL)

    def test_dependency_from_higher_profile(self):
        registry = ValidationRegistry()
        registry.register(case("VAL-P1-A", dependencies=("VAL-P1-B",)))
        registry.register(case("VAL-P1-B", ValidationProfile.FULL))
        with self.assertRaises(RegistryError):
            registry.validate()

    def test_registry_does_not_import_runner(self):
        registry = ValidationRegistry()
        registry.register(case(runner="nonexistent.module:nonexistent"))
        self.assertEqual(len(registry.select(ValidationProfile.QUICK)), 1)


class ResultTests(unittest.TestCase):
    def test_pass(self):
        result = ValidationResult("VAL-P1-CLI-001", ValidationStatus.PASS, 0.1)
        self.assertEqual(result.status, ValidationStatus.PASS)

    def test_nonpassing_requires_reason(self):
        with self.assertRaises(ValueError):
            ValidationResult("VAL-P1-CLI-001", ValidationStatus.BLOCKED, 0.0)


if __name__ == "__main__":
    unittest.main()
