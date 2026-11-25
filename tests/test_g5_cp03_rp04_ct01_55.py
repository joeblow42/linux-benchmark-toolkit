"""RP-04 Increment 55: independent-source exact CT-01 candidate verifications.

Exercises CT-01-P1/N1/N2 against controlled frozen CSV and real production
status validators. A passing test is candidate evidence, NOT formal CP-02
acceptance, requirement verification, physical FAT or independent review.
No host reads, acquisition, privileges, networking or persistent test data.
"""
import csv
import hashlib
from pathlib import Path
import unittest

from lbt_g5.canonical_contract import (
    CanonicalContractError, STATUS_PAIRS, validate_status_record,
)
from lbt_g5.d02_schema import validate_d02_entity, validate_d02_file

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "verification/g5_04/status_pair_keys_rev0_2.csv"
SPEC = ROOT / "verification/g5_04/cp02_independent_contract_cases.json"
PINNED_AUTHORITY_GIT_BLOB = "500a189c150beacd80d73f9bffaf82900e2a1965"
FORWARD_KEY = ("publication", "BLOCKED", "UNCLASSIFIED_PUBLIC_FIELD")


def frozen_keys():
    """Load a separately pinned approved CSV, never from the implementation."""
    content = AUTHORITY.read_bytes()
    git_object = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    digest = hashlib.sha1(git_object).hexdigest()
    if digest != PINNED_AUTHORITY_GIT_BLOB:
        raise AssertionError("approved source CSV Git-blob identity changed")
    with AUTHORITY.open(encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp)
        if reader.fieldnames != ["Domain", "Status", "Reason_Code"]:
            raise AssertionError("approved status CSV columns changed")
        keys = [(row["Domain"], row["Status"], row["Reason_Code"])
                for row in reader]
    if len(keys) != 41 or len(set(keys)) != 41:
        raise AssertionError("approved status keys must be 41 unique entries")
    return keys


def record_for(key):
    domain, status, reason = key
    return {
        "schema_version": "1.0",
        "record_id": "rp04.ct01.55",
        "domain": domain,
        "component_id": "RP04",
        "subject_id": "CT-01",
        "status": status,
        "reason_code": reason,
        "detail": "bounded status vocabulary candidate test",
        "started_utc": None,
        "completed_utc": None,
        "elapsed_ms": None,
        "evidence_refs": [],
        "limit_record_ids": [],
        "source_attempt_ids": [],
    }


class RP04CT01Candidate55(unittest.TestCase):
    def test_55_01_CT_01_P1_pinned_41_pair_acceptance(self):
        keys = frozen_keys()
        self.assertEqual(keys[-1], FORWARD_KEY)
        historical = keys[:-1]
        self.assertEqual(len(historical), 40)
        self.assertNotIn(FORWARD_KEY, historical)
        self.assertEqual(set(keys), STATUS_PAIRS)
        for key in keys:
            # Real independent validator and D-02 entity/file pathways.
            item = record_for(key)
            self.assertIs(validate_status_record(item), item)
            self.assertIs(validate_d02_entity("StatusRecord", item), item)
        collection = {"schema_version": "1.0.0", "run_id": "rp04-55",
                      "status_records": [record_for(key) for key in keys]}
        self.assertIs(validate_d02_file("status_records.json", collection), collection)

    def test_55_02_CT_01_N1_cross_domain_pair_is_rejected(self):
        frozen_keys()
        self.assertIn(FORWARD_KEY, STATUS_PAIRS)
        incorrect = record_for(FORWARD_KEY)
        incorrect["domain"] = "acquisition"  # exact controlled negative input
        self.assertNotIn((incorrect["domain"], incorrect["status"],
                          incorrect["reason_code"]), STATUS_PAIRS)
        with self.assertRaises(CanonicalContractError):
            validate_status_record(incorrect)
        with self.assertRaises(CanonicalContractError):
            validate_d02_entity("StatusRecord", incorrect)

    def test_55_03_CT_01_N2_unsupported_reason_is_rejected(self):
        keys = frozen_keys()
        self.assertIn(("publication", "BLOCKED", "POLICY_INVALID"), keys)
        incorrect = record_for(("publication", "BLOCKED", "POLICY_INVALID"))
        incorrect["reason_code"] = "POLICY_CHANGED_DURING_BATCH"
        self.assertNotIn((incorrect["domain"], incorrect["status"],
                          incorrect["reason_code"]), keys)
        with self.assertRaises(CanonicalContractError):
            validate_status_record(incorrect)
        with self.assertRaises(CanonicalContractError):
            validate_d02_entity("StatusRecord", incorrect)
        # The rejected candidate must not modify the authoritative vocabulary.
        self.assertEqual(set(frozen_keys()), STATUS_PAIRS)
        self.assertEqual(len(STATUS_PAIRS), 41)


if __name__ == "__main__":
    unittest.main()
