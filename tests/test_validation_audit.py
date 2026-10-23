"""Targeted regression evidence for integration-review findings FIR-01..FIR-06."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from validation.evidence import private_diagnostic
from validation.quick import quick_registry
from validation.adapters import extend_registry, UNIT_ID, ACCEPTANCE_IDS
from validation.profiles import ValidationProfile
from validation.requirements import APPROVED_IDS, DEFERRED_IDS, BASELINE, links_for
from validation.reporting import build_record, write_reports, regenerate_reports, validate_record, MANIFEST
from validation.results import ValidationResult, ValidationStatus
from validation.runner import ValidationRun


ROOT = Path(__file__).resolve().parents[1]


def fixture():
    registry = quick_registry()
    selected = registry.select(ValidationProfile.QUICK)
    results = tuple(ValidationResult(case.validation_id, ValidationStatus.PASS, .01)
                    for case in selected)
    record = build_record(ValidationRun(ValidationProfile.QUICK, results, "PASS"),
                          registry, session_id="validation_audit_fixture")
    return registry, record


class RequirementAuditTests(unittest.TestCase):
    def test_authoritative_baseline_identity(self):
        self.assertEqual(len(APPROVED_IDS), 256)
        self.assertIn("LBT-FR-190", APPROVED_IDS)
        self.assertIn("LBT-NFR-066", APPROVED_IDS)
        self.assertEqual(len(DEFERRED_IDS), 7)
        self.assertTrue(DEFERRED_IDS.issubset(APPROVED_IDS))

    def test_coverage_is_explicitly_partial(self):
        _, record = fixture()
        coverage = record["requirements_coverage"]
        self.assertEqual(coverage["total"], 256)
        self.assertEqual(coverage["fully_verified"], [])
        self.assertEqual(coverage["linked"] + len(coverage["unlinked"]), 256)
        self.assertIn("LBT-FR-001", coverage["unlinked"])
        self.assertIn("LBT-FR-128", coverage["linked_tests"])

    def test_original_checks_have_conservative_links(self):
        reg = quick_registry()
        extend_registry(reg, ROOT)
        all_ids = {case.validation_id for case in reg.all_cases()}
        self.assertTrue(set(ACCEPTANCE_IDS).issubset(all_ids))
        self.assertTrue(any(reg_case.requirement_ids for reg_case in reg.all_cases()))
        self.assertTrue(all(set(reg_case.requirement_ids) <= APPROVED_IDS
                            for reg_case in reg.all_cases()))


class InterruptionAndCiTests(unittest.TestCase):
    def test_interrupted_validation_returns_130(self):
        from validation.suites import main
        with patch("validation.suites.run_validation", side_effect=KeyboardInterrupt):
            self.assertEqual(main(["quick"]), 130)

    def test_ci_never_uploads_local_private_logs(self):
        workflow = (ROOT / ".github/workflows/test.yml").read_text()
        self.assertIn("validation.manifest.json", workflow)
        self.assertNotIn("path: validation-results/ci/\\n", workflow)


class PrivacyAndIntegrityTests(unittest.TestCase):
    def test_private_log_references_do_not_expose_content(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            contents = "account=user /home/privateuser/example 192.168.51.206"
            ref = private_diagnostic(root, "VAL-P1-UNIT-001", contents)
            self.assertEqual(ref, "log:VAL-P1-UNIT-001")
            target = root / "logs" / "VAL-P1-UNIT-001.log"
            self.assertIn(contents, target.read_text())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / "logs").stat().st_mode & 0o777, 0o700)

    def test_private_title_and_unsupported_evidence_rejected(self):
        _, record = fixture()
        record["results"][0]["title"] = "alice@example.com /home/alice"
        with self.assertRaises(ValueError):
            validate_record(record)
        _, record = fixture()
        record["results"][0]["evidence"] = ["/home/alice"]
        with self.assertRaises(ValueError):
            validate_record(record)

    def test_bare_network_address_cannot_be_evidence_reference(self):
        _, record = fixture()
        record["results"][0]["evidence"] = ["192.168.51.206"]
        with self.assertRaises(ValueError):
            validate_record(record)

    def test_host_identifiers_in_safe_pattern_reasons_rejected(self):
        _, record = fixture()
        record["results"][0]["status"] = "BLOCKED"
        record["results"][0]["reason"] = "missing prerequisites: 192.168.51.206"
        record["counts"]["PASS"] -= 1
        record["counts"]["BLOCKED"] += 1
        record["overall"] = "INCOMPLETE"
        with self.assertRaises(ValueError):
            validate_record(record)

    def test_unrecognized_requirement_link_rejected(self):
        _, record = fixture()
        record["results"][0]["requirement_ids"].append("LBT-FR-999")
        with self.assertRaises(ValueError):
            validate_record(record)

    def test_recomputed_coverage_cannot_be_forged(self):
        _, record = fixture()
        record["requirements_coverage"]["fully_verified"].append("LBT-FR-128")
        with self.assertRaises(ValueError):
            validate_record(record)

    def test_unknown_canonical_fields_are_rejected(self):
        _, record = fixture()
        record["results"][0]["private_mount"] = "/home/test/private"
        with self.assertRaises(ValueError):
            validate_record(record)
        _, record = fixture()
        record["unexpected_private_value"] = "test"
        with self.assertRaises(ValueError):
            validate_record(record)

    def test_duplicate_json_keys_rejected_during_regeneration(self):
        _, record = fixture()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write_reports(record, root)
            canonical = root / "validation.json"
            old = canonical.read_text()
            canonical.write_text(old.replace('"schema_version":', '"schema_version": "1.0.0", "schema_version":', 1))
            with self.assertRaises(ValueError):
                regenerate_reports(root)

    def test_precoverage_record_regenerates_without_changing_json(self):
        _, record = fixture()
        record.pop("requirements_coverage")
        record["schema_version"] = "1.0.0"
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / "validation.json"
            source.write_text(json.dumps(record, sort_keys=True))
            before = source.read_bytes()
            paths = regenerate_reports(root)
            self.assertEqual(len(paths), 3)
            self.assertEqual(source.read_bytes(), before)
            self.assertTrue((root / MANIFEST).is_file())
            self.assertIn("Linked approved requirement", (root / "validation.md").read_text())

    def test_manifest_blocks_tampered_canonical(self):
        _, record = fixture()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write_reports(record, root)
            manifest = json.loads((root / MANIFEST).read_text())
            self.assertTrue(manifest["complete"])
            original = (root / "validation.json").read_bytes()
            regenerate_reports(root)
            self.assertEqual(original, (root / "validation.json").read_bytes())
            (root / "validation.json").write_bytes(original + b" ")
            with self.assertRaises(ValueError):
                regenerate_reports(root)


if __name__ == "__main__":
    unittest.main()
