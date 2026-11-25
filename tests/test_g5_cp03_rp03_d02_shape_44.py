"""Source-first RP-03 Increment 44 strict D-02 field/type/enum oracles.

The approved §6 annex was independently recovered and hashed before these tests.
They MUST fail before the candidate validator is implemented; they do not
assert that the current canonical producer emits production-conformant files.
"""
import copy
import json
from pathlib import Path
import unittest

from lbt_g5.d02_schema import validate_d02_entity, validate_d02_file, D02_FILES, D02_ENTITIES
from lbt_g5.canonical_contract import new_status, CanonicalContractError

ROOT = Path(__file__).resolve().parents[1]
CONTROL = json.loads((ROOT / "verification/g5_04/rp03_cp01_d02_approved_contract_43.json").read_text())
RUN = "run-2026318180000"
SHA = "a" * 64

def sample():
    header = {
        "started_utc": None, "completed_utc": None, "platform_scope": "Linux-AMD64",
        "requested_mode": "ACQUISITION", "lifecycle_state": "INCOMPLETE",
        "collector_ids": [], "created_by_version": None,
    }
    source = {
        "attempt_id": "SRC-02-01", "source_id": "SRC-02",
        "collector_id": "COL-OS", "operation_id": "FILE_READ",
        "authorization_class": "D0", "authorization_decision": "ALLOW",
        "operator_consent": None, "invocation": {}, "safety_bounds": [],
        "started_utc": None, "completed_utc": None, "elapsed_ms": None,
        "tool_version": None, "exit_code": None, "errno": None,
        "capture_bytes": 3, "evidence_ids": ["ev1"],
        "status_record_id": "st:SRC-02-01", "limit_record_ids": [],
        "receipt_private_path": "private/source_attempt_records/SRC-02-01.json",
        "receipt_sha256": SHA, "receipt_byte_count": 32,
        "errors": [], "unavailable_fields": [],
    }
    evidence = {
        "evidence_id": "ev1", "source_attempt_id": "SRC-02-01",
        "representation": "FILE_BYTES", "restricted_relative_path": "private/evidence/ev1",
        "sha256": SHA, "byte_count": 3, "sealed_utc": None,
        "completeness": "COMPLETE", "encoding": None,
        "limit_record_ids": [], "limit_applied": False, "omitted_at_least": 0,
    }
    obs = {
        "observation_id": "obs:ev1", "collector_id": "COL-OS",
        "datum_path": "unclassified.source.SRC-02.item0001",
        "instance_key": "ev1", "ordinal": 0, "observed_value": "abc",
        "normalized_value": None, "value_type": "STRING", "unit": None,
        "evidence_refs": ["ev1"], "source_attempt_ids": ["SRC-02-01"],
        "transformation_ids": [], "acquired_utc": None, "capture_limit_ids": [],
        "status_record_id": "st:SRC-02-01",
        "parser_findings": ["ORIGINAL_PRESERVED"], "limitations": [],
    }
    limit = {
        "limit_id": "limit:SRC-02-01", "source_attempt_id": "SRC-02-01",
        "approved_rule_id": "G4-07:SRC-02",
        "threshold": 1024, "unit": "bytes", "observed_extent": 1024,
        "missing_extent": 2, "affected_scope": "SRC-02:call0001:transport",
        "reason": "CAPTURE_LIMIT",
    }
    status = new_status(
        record_id="st:SRC-02-01", domain="acquisition",
        component_id="COL-OS", subject_id="SRC-02",
        status="COMPLETE", reason_code="OK", detail="evidenced capture",
        evidence_refs=["ev1"], source_attempt_ids=["SRC-02-01"])
    counts = {
        "attempts": 0, "sources": 0, "observations": 0,
        "evidence_artifacts": 0, "original_bytes": 0,
        "statuses": 0, "capture_limits": 0,
    }
    manifest = {
        "schema_version": "1.0.0", "manifest_version": "1.0", "run_id": RUN,
        "completion_state": "INCOMPLETE", "integrity_verified": True,
        "minimum_usable": False, "finalized_utc": None, "counts": counts,
        "files": {"system.json": {"sha256": SHA, "byte_count": 256}},
        "evidence": {}, "source_receipts": {}, "observation_ids": [],
        "source_attempt_ids": [], "status_record_ids": [],
        "limit_record_ids": [], "limitations": ["NO_COMPLETED_SOURCES"],
    }
    files = {
        "system.json": {"schema_version": "1.0.0", "run_id": RUN,
                        "header": header, "observations": [],
                        "capture_limits": [], "limitations": []},
        "source_attempts.json": {"schema_version": "1.0.0", "run_id": RUN,
                                 "attempts": [source]},
        "status_records.json": {"schema_version": "1.0.0", "run_id": RUN,
                                "status_records": [status]},
        "session_manifest.json": manifest,
    }
    return locals()


class D02StrictShape(unittest.TestCase):
    def test_44_01_exact_fields_mirror_independent_approved_authority(self):
        self.assertEqual(D02_FILES, CONTROL["files"])
        self.assertEqual(D02_ENTITIES, CONTROL["entities"])

    def test_44_02_all_four_files_and_nested_entities_positive(self):
        f = sample()
        for name, payload in f["files"].items():
            with self.subTest(name=name):
                self.assertEqual(validate_d02_file(name, payload), payload)
        for kind in ("SessionHeader", "SourceAttempt", "EvidenceArtifact",
                     "CanonicalObservation", "CaptureLimit", "StatusRecord",
                     "Counts", "FileDigest", "ReceiptDigest"):
            payload = ({
                "SessionHeader": f["header"], "SourceAttempt": f["source"],
                "EvidenceArtifact": f["evidence"], "CanonicalObservation": f["obs"],
                "CaptureLimit": f["limit"], "StatusRecord": f["status"],
                "Counts": f["counts"],
                "FileDigest": {"sha256": SHA, "byte_count": 1},
                "ReceiptDigest": {"sha256": SHA, "byte_count": 32,
                                  "attempt_id": "SRC-02-01",
                                  "restricted_relative_path": "private/source_attempt_records/SRC-02-01.json"}
            })[kind]
            with self.subTest(entity=kind):
                self.assertEqual(validate_d02_entity(kind, payload), payload)

    def test_44_03_unknown_and_missing_required_fields_rejected(self):
        f = sample()
        for filename in f["files"]:
            for operation in ("extra", "missing"):
                value = copy.deepcopy(f["files"][filename])
                if operation == "extra":
                    value["invented"] = 1
                else:
                    del value[next(iter(value))]
                with self.subTest(file=filename, action=operation), self.assertRaises(
                    CanonicalContractError
                ):
                    validate_d02_file(filename, value)
        for name, payload in (("SessionHeader", f["header"]), ("SourceAttempt", f["source"]),
                              ("EvidenceArtifact", f["evidence"]),
                              ("CanonicalObservation", f["obs"])):
            value = copy.deepcopy(payload)
            value["invented"] = True
            with self.subTest(entity=name), self.assertRaises(CanonicalContractError):
                validate_d02_entity(name, value)

    def test_44_04_required_nullable_fields_not_omittable(self):
        f = sample()
        for name, key in (("SessionHeader", "created_by_version"),
                          ("SourceAttempt", "operator_consent"),
                          ("EvidenceArtifact", "sealed_utc"),
                          ("CanonicalObservation", "acquired_utc")):
            value = copy.deepcopy(f[{"SessionHeader":"header","SourceAttempt":"source",
                                     "EvidenceArtifact":"evidence",
                                     "CanonicalObservation":"obs"}[name]])
            del value[key]
            with self.subTest(entity=name, field=key), self.assertRaises(CanonicalContractError):
                validate_d02_entity(name, value)

    def test_44_05_negative_counts_numeric_bounds_digest_and_utc(self):
        f = sample()
        for key, value in (("attempts", True), ("observations", -1)):
            item = dict(f["counts"], **{key: value})
            with self.subTest(key=key), self.assertRaises(CanonicalContractError):
                validate_d02_entity("Counts", item)
        for bad in ("X" * 64, "bad", "a"*63):
            with self.subTest(sha=bad), self.assertRaises(CanonicalContractError):
                validate_d02_entity("FileDigest", {"sha256": bad, "byte_count": 1})
        for bad in ("2026-11-14T13:00:00-07:00", "garbage"):
            value = dict(f["header"], started_utc=bad)
            with self.subTest(utc=bad), self.assertRaises(CanonicalContractError):
                validate_d02_entity("SessionHeader", value)

    def test_44_06_enumerations_and_41_status_pairs(self):
        f = sample()
        for kind, payload, key, bad in (
            ("SourceAttempt", f["source"], "authorization_class", "X"),
            ("SourceAttempt", f["source"], "authorization_decision", "UNKNOWN"),
            ("EvidenceArtifact", f["evidence"], "representation", "IMAGE"),
            ("EvidenceArtifact", f["evidence"], "completeness", "EXACT"),
            ("SessionHeader", f["header"], "lifecycle_state", "STARTED"),
            ("CanonicalObservation", f["obs"], "value_type", "DATUM"),
        ):
            with self.subTest(kind=kind, key=key), self.assertRaises(CanonicalContractError):
                validate_d02_entity(kind, dict(payload, **{key: bad}))
        bad_status = dict(f["status"], domain="acquisition", status="BLOCKED",
                          reason_code="UNCLASSIFIED_PUBLIC_FIELD")
        with self.assertRaises(CanonicalContractError):
            validate_d02_entity("StatusRecord", bad_status)

    def test_44_07_observation_contributors_must_be_nonempty(self):
        f = sample()
        for key in ("evidence_refs", "source_attempt_ids"):
            item = dict(f["obs"], **{key: []})
            with self.subTest(key=key), self.assertRaises(CanonicalContractError):
                validate_d02_entity("CanonicalObservation", item)

    def test_44_08_unknown_acquired_json_is_not_unknown_schema_key(self):
        f = sample()
        item = dict(f["obs"], observed_value={
            "unknown_source_key": {"unclassified": [1, "as-is", None, False]}
        }, value_type="OBJECT")
        self.assertEqual(validate_d02_entity("CanonicalObservation", item), item)

    def test_44_09_manifest_unknown_digest_and_numeric_nan_fail_closed(self):
        f = sample()
        item = copy.deepcopy(f["manifest"])
        item["files"]["system.json"]["unapproved_digest_attr"] = "x"
        with self.assertRaises(CanonicalContractError):
            validate_d02_file("session_manifest.json", item)
        limit = dict(f["limit"], threshold=float("nan"))
        with self.assertRaises(CanonicalContractError):
            validate_d02_entity("CaptureLimit", limit)


if __name__ == "__main__":
    unittest.main()
