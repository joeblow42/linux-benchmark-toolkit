"""G5-04 strict private 14-field and 41-pair contract fixtures."""
import unittest

from lbt_g5.canonical_contract import (
    CANONICAL_SCHEMA_VERSION, STATUS_SCHEMA_VERSION, STATUS_PAIRS,
    STATUS_FIELDS, CanonicalContractError, new_status,
    validate_status_record,
)


class G504StatusContracts(unittest.TestCase):
    def base(self):
        return new_status(record_id="status-01", domain="acquisition",
                          component_id="COL-OS", subject_id="SRC-01",
                          status="PARTIAL", reason_code="PARSE_FAILED",
                          detail="Original bytes retained, no parser result",
                          evidence_refs=("evidence-01",),
                          source_attempt_ids=("SRC-01-01",))

    def test_exact_forward_authorized_vocabulary(self):
        self.assertEqual(CANONICAL_SCHEMA_VERSION, "1.0.0")
        self.assertEqual(STATUS_SCHEMA_VERSION, "1.0")
        self.assertEqual(len(STATUS_FIELDS), 14)
        self.assertEqual(len(STATUS_PAIRS), 41)
        self.assertIn(("publication", "BLOCKED", "UNCLASSIFIED_PUBLIC_FIELD"),
                      STATUS_PAIRS)
        self.assertNotIn(("publication", "BLOCKED", "POLICY_CHANGED_DURING_BATCH"),
                         STATUS_PAIRS)

    def test_cross_domain_status_fails(self):
        item = self.base().copy()
        item["domain"] = "validation"
        with self.assertRaises(CanonicalContractError):
            validate_status_record(item)

    def test_unapproved_status_fails(self):
        item = self.base().copy()
        item["reason_code"] = "SOURCE_NOT_RECORDED"
        with self.assertRaises(CanonicalContractError):
            validate_status_record(item)

    def test_missing_or_unknown_field_fails_closed(self):
        item = self.base().copy()
        item.pop("elapsed_ms")
        with self.assertRaises(CanonicalContractError):
            validate_status_record(item)
        item = self.base().copy()
        item["raw_path"] = "/proc/cpuinfo"
        with self.assertRaises(CanonicalContractError):
            validate_status_record(item)

    def test_dangling_reference_rejected(self):
        with self.assertRaises(CanonicalContractError):
            validate_status_record(
                self.base(), evidence_ids={"wrong"},
                attempt_ids={"SRC-01-01"}, limit_ids=set())
        validate_status_record(
            self.base(), evidence_ids={"evidence-01"},
            attempt_ids={"SRC-01-01"}, limit_ids=set())

    def test_duplicate_refs_or_wrong_types_rejected(self):
        item = self.base().copy()
        item["evidence_refs"] = ["evidence-01", "evidence-01"]
        with self.assertRaises(CanonicalContractError):
            validate_status_record(item)
        item = self.base().copy()
        item["elapsed_ms"] = True
        with self.assertRaises(CanonicalContractError):
            validate_status_record(item)

    def test_timestamps_must_be_utc_ordered(self):
        item = self.base().copy()
        item.update(started_utc="2026-11-02T12:00:00Z",
                    completed_utc="2026-11-02T11:59:00Z", elapsed_ms=12)
        with self.assertRaises(CanonicalContractError):
            validate_status_record(item)
        item.update(completed_utc="2026-11-02T12:00:01Z")
        validate_status_record(item)

    def test_record_detail_bounded(self):
        item = self.base().copy()
        item["detail"] = "x" * 1025
        with self.assertRaises(CanonicalContractError):
            validate_status_record(item)

    def test_zero_ref_denial_is_valid(self):
        item = new_status(record_id="st-deny", domain="acquisition",
                          component_id="COL-BLOCK", subject_id="SRC-13",
                          status="UNAUTHORIZED",
                          reason_code="OPERATOR_AUTH_REQUIRED",
                          evidence_refs=[], source_attempt_ids=["SRC-13-01"])
        validate_status_record(
            item, evidence_ids=set(), attempt_ids={"SRC-13-01"},
            limit_ids=set())

    def test_field_blocking_specific_pair(self):
        item = new_status(record_id="field-01", domain="publication",
                          component_id="PUB-ENGINE", subject_id="PUB-01",
                          status="BLOCKED",
                          reason_code="UNCLASSIFIED_PUBLIC_FIELD")
        self.assertEqual(item["reason_code"], "UNCLASSIFIED_PUBLIC_FIELD")


if __name__ == "__main__":
    unittest.main()
