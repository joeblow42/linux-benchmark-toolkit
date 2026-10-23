"""Increment 5 validation report consistency, privacy, and offline tests."""
import csv
import json
from pathlib import Path
import tempfile
import unittest

from validation.profiles import ValidationProfile
from validation.quick import quick_registry
from validation.reporting import (
    FORMATS, build_record, regenerate_reports, validate_record, write_reports,
)
from validation.results import ValidationResult, ValidationStatus
from validation.runner import ValidationRun


def sample():
    registry = quick_registry()
    cases = registry.select(ValidationProfile.QUICK)
    results = tuple(ValidationResult(item.validation_id, ValidationStatus.PASS, .125)
                    for item in cases)
    return build_record(ValidationRun(ValidationProfile.QUICK, results, "PASS"),
                        registry, revision="3ee5b730",
                        timestamp="2026-10-23T12:00:00+00:00",
                        session_id="validation_fixture")


class ReportingTests(unittest.TestCase):
    def test_four_formats_and_consistent_counts(self):
        record = sample()
        with tempfile.TemporaryDirectory() as temp:
            paths = write_reports(record, Path(temp))
            self.assertEqual({p.name for p in paths}, set(FORMATS))
            self.assertEqual(json.loads((Path(temp) / "validation.json").read_text()), record)
            with (Path(temp) / "validation.csv").open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), record["counts"]["PASS"])
            page = (Path(temp) / "validation.html").read_text()
            self.assertIn("<!DOCTYPE html>", page)
            self.assertNotIn("https://", page)
            self.assertNotIn("http://", page)

    def test_regeneration_preserves_canonical_and_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_reports(sample(), path)
            before = {name: (path / name).read_bytes() for name in FORMATS}
            for name in FORMATS[1:]:
                (path / name).unlink()
            regenerate_reports(path)
            self.assertEqual(before, {name: (path / name).read_bytes() for name in FORMATS})

    def test_corrupted_counts_rejected(self):
        record = sample()
        record["counts"]["PASS"] = 900
        with self.assertRaises(ValueError):
            validate_record(record)

    def test_duplicate_cases_rejected(self):
        record = sample()
        record["results"].append(dict(record["results"][0]))
        record["selected"] += 1
        record["registered"] += 1
        record["counts"]["PASS"] += 1
        with self.assertRaises(ValueError):
            validate_record(record)

    def test_sensitive_reasons_and_evidence_not_persisted(self):
        registry = quick_registry()
        cases = registry.select(ValidationProfile.QUICK)
        results = [ValidationResult(case.validation_id, ValidationStatus.PASS, 0.01)
                   for case in cases]
        secret = "username=alice /home/alice/private 192.168.51.123"
        results[0] = ValidationResult(cases[0].validation_id,
                                      ValidationStatus.FAIL, 0.02, secret,
                                      evidence=(secret, "unit-suite:fixture"))
        run = ValidationRun(ValidationProfile.QUICK, tuple(results), "FAIL")
        record = build_record(run, registry)
        with tempfile.TemporaryDirectory() as temp:
            write_reports(record, Path(temp))
            for filename in FORMATS:
                data = (Path(temp) / filename).read_text()
                self.assertNotIn("alice", data)
                self.assertNotIn("192.168.51.123", data)
                self.assertNotIn("/home/alice", data)
            self.assertEqual(record["results"][0]["evidence"], ["unit-suite:fixture"])

    def test_html_escapes_untrusted_case_title(self):
        record = sample()
        record["results"][0]["title"] = "<script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as temp:
            write_reports(record, Path(temp))
            page = (Path(temp) / "validation.html").read_text()
            self.assertNotIn("<script>", page)
            self.assertIn("&lt;script&gt;", page)

    def test_regenerate_rejects_corrupted_canonical(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            write_reports(sample(), path)
            original = (path / "validation.html").read_bytes()
            record = sample()
            record["overall"] = "FAIL"
            (path / "validation.json").write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                regenerate_reports(path)
            self.assertEqual((path / "validation.html").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
