"""LBT RP-04 Increment 57: original CT-03 parser-error candidate verification.

Independent, disposable offline sealed-original fixtures; no host sources
collected. A parser error requires genuine parser invocation and an original
reference. Development evidence only, not formal CP-02 or FAT acceptance.
"""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lbt_g5 import canonical_session
from lbt_g5.canonical_contract import CanonicalContractError, validate_status_record
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import EngineRun, CollectorRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.normalization import PARSERS, SourceParseError, normalize_sealed_source
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026318185757"
RAW = b"ID=bodhi\nnot-an-assignment\n"
EXPECTED_PARSER_ERROR = "OS_RELEASE_MALFORMED_ASSIGNMENT"


class RP04CT03Candidate57(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / RUN
        self.folder.mkdir(mode=0o700)
        writer = EvidenceWriter(str(self.folder), RUN)
        policy = {x.source_id: x for x in initial_source_policies()}["SRC-02"]
        self.original = writer.seal_chunks(policy, "01", "item0001", (RAW,)).receipt
        self.assertIsNotNone(self.original)
        receipt = build_attempt(
            RUN, "SRC-02", "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=(self.original,), bytes_count=self.original.byte_count,
        )
        self.receipt_path = commit_attempt(str(self.folder), receipt)
        recorded = SimpleNamespace(
            receipt_private_path=self.receipt_path,
            outcome=SimpleNamespace(artifacts=(self.original,)))
        self.engine_run = EngineRun(RUN, (CollectorRun("COL-OS", (recorded,)),))

    def assert_original_preserved(self):
        original_path = self.folder / self.original.private_relative_path
        self.assertEqual(original_path.read_bytes(), RAW)
        self.assertEqual(hashlib.sha256(RAW).hexdigest(), self.original.sha256)
        receipt = json.loads((self.folder / self.receipt_path).read_text())
        self.assertEqual(receipt["outcome"], "CAPTURED")
        self.assertEqual(receipt["reason"], "BYTES_PRESERVED")
        self.assertEqual(receipt["evidence_ids"], [self.original.evidence_id])

    def produce_failed_parser_result(self):
        with patch("lbt_g5.canonical_session.normalize_sealed_source",
                   wraps=normalize_sealed_source) as invoked:
            manifest = build_canonical(self.folder, self.engine_run)
            self.assertGreaterEqual(invoked.call_count, 1)
            self.assertEqual(invoked.call_args_list[0].args[:2], ("SRC-02", RAW))
        self.assertEqual(validate_canonical(self.folder), manifest)
        self.assert_original_preserved()
        private = self.folder / "private"
        system = json.loads((private / "system.json").read_text())
        statuses = json.loads((private / "status_records.json").read_text())
        attempt = json.loads((private / "source_attempts.json").read_text())["attempts"][0]
        return manifest, system, statuses["status_records"], attempt

    def test_57_01_CT_03_P1_real_invocation_error_and_lossless_fallback(self):
        with self.assertRaises(SourceParseError) as caught:
            normalize_sealed_source("SRC-02", RAW)
        self.assertEqual(str(caught.exception), EXPECTED_PARSER_ERROR)
        manifest, system, statuses, attempt = self.produce_failed_parser_result()
        acquisition = next(x for x in statuses if x["domain"] == "acquisition")
        self.assertEqual((acquisition["status"], acquisition["reason_code"]),
                         ("PARTIAL", "PARSE_FAILED"))
        self.assertEqual(acquisition["evidence_refs"], [self.original.evidence_id])
        self.assertEqual(acquisition["source_attempt_ids"], ["SRC-02-01"])
        self.assertIn(EXPECTED_PARSER_ERROR, acquisition["detail"])
        self.assertEqual(attempt["evidence_ids"], acquisition["evidence_refs"])
        self.assertEqual(manifest["counts"]["evidence_artifacts"], 1)
        self.assertEqual(manifest["counts"]["observations"], 1)
        observations = system["observations"]
        self.assertEqual(len(observations), 1)
        self.assertIn("PARSER_FAILED:" + EXPECTED_PARSER_ERROR,
                      observations[0]["parser_findings"])
        self.assertEqual(observations[0]["evidence_refs"],
                         [self.original.evidence_id])
        self.assertEqual(observations[0]["observed_value"], RAW.decode("utf-8"))
        self.assertEqual(observations[0]["transformation_ids"], [])
        self.assertIsNone(observations[0]["normalized_value"])

    def test_57_02_CT_03_N1_never_invoked_must_not_claim_parser_failure(self):
        # Fail-closed behavior is explicitly checked at the actual canonical
        # producer, not inferred from a separate hand-crafted status record.
        with patch.dict(PARSERS, {}, clear=True), patch(
                "lbt_g5.canonical_session.normalize_sealed_source") as invoked:
            with self.assertRaisesRegex(CanonicalContractError,
                                        "NORMALIZATION_PENDING"):
                build_canonical(self.folder, self.engine_run)
            invoked.assert_not_called()
        self.assert_original_preserved()
        self.assertFalse((self.folder / "private/status_records.json").exists())
        self.assertFalse((self.folder / "private/session_manifest.json").exists())

    def test_57_03_CT_03_N2_missing_original_must_invalidate_parser_status(self):
        manifest, _, statuses, _ = self.produce_failed_parser_result()
        acquisition = next(x for x in statuses if x["domain"] == "acquisition")
        # An otherwise valid PARTIAL/PARSE_FAILED reference cannot be treated
        # as sufficient if its original does not resolve.
        with self.assertRaises(CanonicalContractError):
            validate_status_record(
                acquisition, evidence_ids=set(),
                attempt_ids={"SRC-02-01"}, limit_ids=set())
        self.assertEqual(validate_status_record(
            acquisition, evidence_ids={self.original.evidence_id},
            attempt_ids={"SRC-02-01"}, limit_ids=set()), acquisition)

        # Simulate an ordinary unavailable evidence read WITHOUT modifying,
        # deleting or rewriting immutable original bytes or receipts.
        real_read = canonical_session._read_restricted
        unavailable_path = self.folder / self.original.private_relative_path
        def missing_original(path, ceiling):
            if Path(path) == unavailable_path:
                raise FileNotFoundError("simulated unavailable original evidence")
            return real_read(path, ceiling)
        with patch("lbt_g5.canonical_session._read_restricted",
                   side_effect=missing_original):
            with self.assertRaises(FileNotFoundError):
                validate_canonical(self.folder)
        self.assert_original_preserved()
        self.assertEqual(validate_canonical(self.folder), manifest)


if __name__ == "__main__":
    unittest.main()
