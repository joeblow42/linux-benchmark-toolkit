"""IC-04 T01–T22: synthetic, unprivileged status-contract acceptance.

These tests verify typed interfaces, not physical benchmark measurements.
"""
from copy import deepcopy
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from discovery.core import (
    CollectionStatus, CollectorResult, DiscoveryContext, run_collector,
)
from reporting.session_schema import SessionSchemaError, validate_system_document
from reporting.status_contract import (
    AssessmentConfidence, BenchmarkContractError, BenchmarkExecutionStatus,
    WorkloadSuitability, normalize_benchmark_result, validate_benchmark_record,
)
from validation.results import ValidationResult, ValidationStatus


def complete(**kwargs):
    return normalize_benchmark_result(
        "JF-02", BenchmarkExecutionStatus.COMPLETE,
        parameters={"input_codec": "h264", "output_codec": "h264",
                    "width": 1920, "height": 1080},
        metrics={"realtime_ratio": {"value": 1.64, "unit": "x"},
                 "elapsed_seconds": {"value": 73.0, "unit": "s"}},
        evidence=["measurement:JF02-observed01"],
        tool={"name": "ffmpeg", "version": "7.0"},
        fixture_id="h264_1080p_reference_v1",
        log_ref="logs/JF-02.log",
        **kwargs,
    )


def noncomplete(status, reason="Prerequisite absent", **kwargs):
    return normalize_benchmark_result(
        "JF-02", status, parameters={}, metrics={},
        reason=reason, evidence=["preflight:JF02"], **kwargs,
    )


class IC04StatusContractTests(unittest.TestCase):
    def test_ic04_t01_existing_six_collector_statuses_unchanged(self):
        self.assertEqual({x.value for x in CollectionStatus}, {
            "COMPLETE", "UNAVAILABLE", "UNSUPPORTED",
            "PERMISSION_DENIED", "TOOL_MISSING", "FAILED"})

    def test_ic04_t02_existing_five_software_statuses_unchanged(self):
        self.assertEqual({x.value for x in ValidationStatus}, {
            "PASS", "FAIL", "SKIP", "BLOCKED", "NOT_APPLICABLE"})

    def test_ic04_t03_five_benchmark_statuses_are_separate(self):
        self.assertEqual({x.value for x in BenchmarkExecutionStatus}, {
            "COMPLETE", "SKIPPED", "UNAVAILABLE", "FAILED", "INTERRUPTED"})
        self.assertNotIn("PARTIAL", [s.value for s in BenchmarkExecutionStatus])
        self.assertNotIn("RESUMED", [s.value for s in BenchmarkExecutionStatus])

    def test_ic04_t04_reject_foreign_domain_status_objects(self):
        for label in (
            CollectionStatus.COMPLETE,
            CollectionStatus.UNAVAILABLE,
            ValidationStatus.PASS,
            ValidationStatus.FAIL,
            WorkloadSuitability.GOOD,
            "COMPLETE",
        ):
            with self.subTest(label=label), self.assertRaises(BenchmarkContractError):
                normalize_benchmark_result(
                    "JF-02", label, parameters={}, metrics={}, reason="Not run")

    def test_ic04_t05_missing_optical_not_software_failure(self):
        collector = CollectorResult("optical", CollectionStatus.UNAVAILABLE,
                                    reason="No optical drive")
        benchmark = noncomplete(BenchmarkExecutionStatus.UNAVAILABLE,
                                "No optical drive")
        verifier = ValidationResult("VAL-OPT-001", ValidationStatus.PASS, 0.02)
        self.assertEqual(collector.status, CollectionStatus.UNAVAILABLE)
        self.assertEqual(benchmark["execution_status"], "UNAVAILABLE")
        self.assertEqual(verifier.status, ValidationStatus.PASS)
        self.assertEqual(WorkloadSuitability.NOT_TESTED.value, "NOT_TESTED")

    def test_ic04_t06_missing_vainfo_means_unavailable_benchmark(self):
        collector = CollectorResult("vaapi", CollectionStatus.TOOL_MISSING,
                                    reason="vainfo absent")
        benchmark = noncomplete(BenchmarkExecutionStatus.UNAVAILABLE, "vainfo absent")
        self.assertEqual(collector.status, CollectionStatus.TOOL_MISSING)
        self.assertEqual(benchmark["metrics"], {})
        self.assertEqual(benchmark["execution_status"], "UNAVAILABLE")

    def test_ic04_t07_denial_remains_distinct_from_missing_tool(self):
        denied = CollectorResult("storage", CollectionStatus.PERMISSION_DENIED,
                                 reason="Source inaccessible")
        missing = CollectorResult("vaapi", CollectionStatus.TOOL_MISSING,
                                  reason="Utility unavailable")
        self.assertNotEqual(denied.status, missing.status)
        self.assertEqual(denied.to_dict()["status"], "PERMISSION_DENIED")

    def test_ic04_t08_collector_exception_isolated(self):
        def failure(context):
            raise RuntimeError("example")
        def healthy(context):
            return CollectorResult("cpu", CollectionStatus.COMPLETE,
                                   data={"architecture": "x86_64"})
        bad = run_collector("gpu", failure, DiscoveryContext())
        good = run_collector("cpu", healthy, DiscoveryContext())
        self.assertEqual(bad.status, CollectionStatus.FAILED)
        self.assertEqual(good.status, CollectionStatus.COMPLETE)
        self.assertEqual(good.data["architecture"], "x86_64")

    def test_ic04_t09_schema_error_does_not_rewrite_collector(self):
        record = CollectorResult("system", CollectionStatus.COMPLETE, data={"os": "Linux"})
        original = deepcopy(record.to_dict())
        with self.assertRaises(SessionSchemaError):
            validate_system_document({"schema_version": "2.0.0", "session_id": "bad"})
        self.assertEqual(record.to_dict(), original)

    def test_ic04_t10_blocked_ci_fixture_not_false_pass(self):
        blocked = ValidationResult("VAL-HW-001", ValidationStatus.BLOCKED,
                                   0.0, reason="Physical fixture absent on CI")
        not_applicable = ValidationResult("VAL-HW-002",
                                          ValidationStatus.NOT_APPLICABLE,
                                          0.0, reason="Device class not present")
        self.assertNotEqual(blocked.status, ValidationStatus.PASS)
        self.assertNotEqual(not_applicable.status, ValidationStatus.PASS)

    def test_ic04_t11_explicit_benchmark_skip(self):
        record = noncomplete(BenchmarkExecutionStatus.SKIPPED, "Operator did not select test")
        self.assertEqual(record["execution_status"], "SKIPPED")
        self.assertEqual(record["metrics"], {})
        validate_benchmark_record(record)
        with self.assertRaises(BenchmarkContractError):
            noncomplete(BenchmarkExecutionStatus.SKIPPED, "")

    def test_ic04_t12_attempted_benchmark_failure_safe_diagnostics(self):
        rec = noncomplete(BenchmarkExecutionStatus.FAILED,
                          "ffmpeg exited with an error", log_ref="logs/JF-02.log")
        self.assertEqual(rec["execution_status"], "FAILED")
        self.assertEqual(rec["log_ref"], "logs/JF-02.log")
        self.assertEqual(rec["metrics"], {})
        validate_benchmark_record(rec)

    def test_ic04_t13_completed_benchmark_requires_provenance_and_metrics(self):
        data = complete()
        self.assertEqual(data["execution_status"], "COMPLETE")
        self.assertEqual(data["metrics"]["realtime_ratio"]["unit"], "x")
        validate_benchmark_record(data)
        for changed in ("metrics", "evidence", "parameters", "tool"):
            args = {"test_id": "JF-02",
                    "execution_status": BenchmarkExecutionStatus.COMPLETE,
                    "parameters": {"codec": "h264"},
                    "metrics": {"speed": {"value": 2.0, "unit": "x"}},
                    "evidence": ["measurement:abc"],
                    "tool": {"name": "ffmpeg", "version": "7.0"}}
            args[changed] = {} if changed in ("metrics", "parameters") else (
                [] if changed == "evidence" else None)
            with self.subTest(changed=changed), self.assertRaises(BenchmarkContractError):
                normalize_benchmark_result(**args)

    def test_ic04_t14_interruption_never_promoted_to_complete(self):
        interrupted = noncomplete(BenchmarkExecutionStatus.INTERRUPTED,
                                  "Operator cancelled", log_ref="logs/JF-02.log")
        self.assertEqual(interrupted["execution_status"], "INTERRUPTED")
        self.assertFalse(interrupted["metrics"])
        self.assertNotIn("checkpoint", interrupted)
        self.assertNotIn("resume_cursor", interrupted)

    def test_ic04_t15_fresh_attempt_from_beginning_no_resume_state(self):
        first = normalize_benchmark_result(
            "JF-02", BenchmarkExecutionStatus.INTERRUPTED,
            parameters={"attempt_number": 1},
            metrics={}, reason="Operator cancelled")
        later = normalize_benchmark_result(
            "JF-02", BenchmarkExecutionStatus.COMPLETE,
            parameters={"attempt_number": 2, "codec": "h264"},
            metrics={"elapsed_seconds": {"value": 5.0, "unit": "s"}},
            tool={"name": "ffmpeg", "version": "7.0"},
            evidence=["measurement:fresh02"])
        self.assertEqual(first["execution_status"], "INTERRUPTED")
        self.assertEqual(later["execution_status"], "COMPLETE")
        self.assertNotEqual(first["parameters"], later["parameters"])
        self.assertFalse(first["metrics"])
        for key in ("checkpoint", "resume_cursor", "resumed_from", "recovery_state"):
            with self.subTest(key=key), self.assertRaises(BenchmarkContractError):
                normalize_benchmark_result(
                    "JF-02", BenchmarkExecutionStatus.INTERRUPTED,
                    parameters={key: "previous"}, metrics={},
                    reason="Operator cancelled")

    def test_ic04_t16_untested_workload_and_insufficient_data(self):
        self.assertEqual({x.value for x in WorkloadSuitability}, {
            "GOOD", "MARGINAL", "POOR", "NOT_TESTED"})
        self.assertEqual({x.value for x in AssessmentConfidence}, {
            "HIGH", "MEDIUM", "LOW", "INSUFFICIENT_DATA"})
        self.assertEqual(WorkloadSuitability.NOT_TESTED.value, "NOT_TESTED")
        self.assertEqual(AssessmentConfidence.INSUFFICIENT_DATA.value, "INSUFFICIENT_DATA")

    def test_ic04_t17_vaapi_advertisement_not_measurement(self):
        advertisement = CollectorResult(
            "vaapi", CollectionStatus.COMPLETE,
            data={"advertisement_only": True, "functional_test": False,
                  "profiles": [{"profile": "VAProfileH264High"}]})
        self.assertFalse(advertisement.data["functional_test"])
        with self.assertRaises(BenchmarkContractError):
            normalize_benchmark_result(
                "JF-02", BenchmarkExecutionStatus.COMPLETE,
                parameters={"codec": "h264"}, metrics={},
                evidence=["advertised:VAProfileH264High"],
                tool={"name": "vainfo", "version": "1.0"})

    def test_ic04_t18_invalid_domain_labels_rejected(self):
        for label in ("PASS", "PARTIAL", "TOOL_MISSING", "PERMISSION_DENIED",
                      "NOT_TESTED", "BOGUS", "RESUMED", "CHECKPOINTED"):
            with self.subTest(label=label), self.assertRaises(BenchmarkContractError):
                validate_benchmark_record({
                    "test_id": "JF-02", "execution_status": label,
                    "parameters": {}, "metrics": {}, "evidence": [],
                    "reason": "Unexecuted"})

    def test_ic04_t19_factory_does_not_collect_or_write_files(self):
        with tempfile.TemporaryDirectory(prefix="lbt-ic04-") as directory:
            where = Path(directory)
            with patch("discovery.orchestrator.collect_inventory",
                       side_effect=AssertionError("collection prohibited")):
                before = list(where.iterdir())
                data = noncomplete(BenchmarkExecutionStatus.UNAVAILABLE, "No fixture")
                self.assertEqual(list(where.iterdir()), before)
                self.assertNotIn("session_id", data)

    def test_ic04_t21_numeric_payload_finite_and_units_required(self):
        for invalid in (
            {"value": float("nan"), "unit": "x"},
            {"value": float("inf"), "unit": "x"},
            {"value": float("-inf"), "unit": "x"},
            {"value": 2.0},
            {"value": 2.0, "unit": ""},
            {"value": True, "unit": "s"},
            {"value": "2.0", "unit": "x"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(BenchmarkContractError):
                normalize_benchmark_result(
                    "JF-02", BenchmarkExecutionStatus.COMPLETE,
                    parameters={"codec": "h264"},
                    metrics={"realtime_ratio": invalid},
                    evidence=["measurement:test01"],
                    tool={"name": "ffmpeg", "version": "7.0"})
        with self.assertRaises(BenchmarkContractError):
            normalize_benchmark_result("JF-02", BenchmarkExecutionStatus.UNAVAILABLE,
                parameters={}, metrics={"fps": {"value": 9000, "unit": "fps"}},
                reason="Fixture absent")

    def test_ic04_t22_diagnostics_and_metadata_are_privacy_safe(self):
        for secret in ("error /home/alice/secret", "host 192.168.51.206",
                       "mac aa:bb:cc:dd:ee:ff", "C:\\Users\\alice\\file"):
            with self.subTest(secret=secret), self.assertRaises(BenchmarkContractError):
                noncomplete(BenchmarkExecutionStatus.FAILED, secret)
        for key in ("hostname", "password", "resume_cursor", "checkpoint"):
            with self.subTest(key=key), self.assertRaises(BenchmarkContractError):
                normalize_benchmark_result(
                    "JF-02", BenchmarkExecutionStatus.UNAVAILABLE,
                    parameters={key: "sensitive"}, metrics={}, reason="Fixture absent")
        for bad in ("../myhome.log", "/home/alice/private.log", "logs/../sensitive"):
            with self.subTest(bad=bad), self.assertRaises(BenchmarkContractError):
                noncomplete(BenchmarkExecutionStatus.FAILED, "Run failed", log_ref=bad)

    def test_defensive_copy_and_strict_json(self):
        parameters = {"width": 1920, "modes": ["h264", "hevc"]}
        metrics = {"elapsed_seconds": {"value": 1.0, "unit": "s"}}
        evidence = ["measurement:sample01"]
        original = normalize_benchmark_result(
            "JF-02", BenchmarkExecutionStatus.COMPLETE,
            parameters=parameters, metrics=metrics, evidence=evidence,
            tool={"name": "ffmpeg", "version": "7.0"})
        parameters["modes"].append("mpeg4")
        metrics["elapsed_seconds"]["value"] = 9999
        evidence.append("measurement:fabricated")
        self.assertEqual(original["parameters"]["modes"], ["h264", "hevc"])
        self.assertEqual(original["metrics"]["elapsed_seconds"]["value"], 1.0)
        self.assertEqual(original["evidence"], ["measurement:sample01"])
        self.assertEqual(original, json.loads(json.dumps(original)))
        validate_benchmark_record(original)

    def test_missing_optional_preflight_evidence_kept_distinct(self):
        record = normalize_benchmark_result(
            "DVD-01", BenchmarkExecutionStatus.UNAVAILABLE,
            parameters={"reader": "sr0"}, metrics={}, reason="No inserted media",
            evidence=["preflight:reader-empty"],
            tool={"name": "ddrescue", "version": "1.0"})
        self.assertEqual(record["evidence"], ["preflight:reader-empty"])
        self.assertEqual(record["metrics"], {})
        validate_benchmark_record(record)

    def test_unknown_top_level_fields_and_resume_metadata_rejected(self):
        record = complete()
        for field in ("status", "checkpoint", "resume_token", "assessment"):
            modified = {**record, field: "any"}
            with self.subTest(field=field), self.assertRaises(BenchmarkContractError):
                validate_benchmark_record(modified)

    def test_invalid_id_and_json_domain_validation(self):
        for invalid in ("", "JF02", "JF 02", "../JF-02", "jF-02", "JF-02\\n"):
            with self.subTest(invalid=invalid), self.assertRaises(BenchmarkContractError):
                normalize_benchmark_result(
                    invalid, BenchmarkExecutionStatus.UNAVAILABLE,
                    parameters={}, metrics={}, reason="Fixture missing")


if __name__ == "__main__":
    unittest.main()
