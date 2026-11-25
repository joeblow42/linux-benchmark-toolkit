"""RP-04 Increment 56: exact CT-02 parser-not-run candidate evidence.

No new source, host probing or parser execution. Real G5-02 source receipt
and original evidence are sealed in a disposable private temp run.
Candidate verification only; independent CP-02 acceptance remains unexecuted.
"""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, _status_for
from lbt_g5.engine import EngineRun, CollectorRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.normalization import PARSERS
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026318180000"
RAW = b'ID=bodhi\nNAME="Bodhi Linux"\n'


class RP04CT02Candidate56(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / RUN
        self.folder.mkdir(mode=0o700)
        writer = EvidenceWriter(str(self.folder), RUN)
        policy = {p.source_id: p for p in initial_source_policies()}["SRC-02"]
        self.original = writer.seal_chunks(policy, "01", "item0001", (RAW,)).receipt
        self.assertIsNotNone(self.original)
        receipt = build_attempt(
            RUN, "SRC-02", "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=(self.original,), bytes_count=self.original.byte_count,
        )
        self.receipt_path = commit_attempt(str(self.folder), receipt)
        observed = SimpleNamespace(
            receipt_private_path=self.receipt_path,
            outcome=SimpleNamespace(artifacts=(self.original,)),
        )
        self.engine_run = EngineRun(RUN, (CollectorRun("COL-OS", (observed,)),))

    def run_without_parser(self):
        # A supported source and real sealed bytes, with its optional semantic
        # parser disabled in this deterministic candidate fixture only.
        with patch.dict(PARSERS, {}, clear=True), patch(
            "lbt_g5.canonical_session.normalize_sealed_source"
        ) as normalize:
            with self.assertRaises(CanonicalContractError) as raised:
                build_canonical(self.folder, self.engine_run)
            normalize.assert_not_called()
        return str(raised.exception)

    def assert_preserved_and_pending(self):
        metadata = json.loads((self.folder / self.receipt_path).read_text())
        self.assertTrue(metadata["status_record_pending"])
        self.assertEqual(metadata["outcome"], "CAPTURED")
        self.assertEqual(metadata["reason"], "BYTES_PRESERVED")
        self.assertEqual(metadata["evidence_ids"], [self.original.evidence_id])
        persisted = (self.folder / self.original.private_relative_path).read_bytes()
        self.assertEqual(persisted, RAW)
        self.assertEqual(hashlib.sha256(persisted).hexdigest(), self.original.sha256)
        self.assertFalse((self.folder / "private/session_manifest.json").exists())
        self.assertFalse((self.folder / "private/status_records.json").exists())

    def test_56_01_CT_02_P1_explicit_pending_private_diagnostic(self):
        error = self.run_without_parser()
        self.assertIn("NORMALIZATION_PENDING", error)
        self.assertIn("parser", error.lower())
        self.assert_preserved_and_pending()

    def test_56_02_CT_02_N1_no_unsubstantiated_parse_failure(self):
        error = self.run_without_parser()
        self.assertIn("NORMALIZATION_PENDING", error)
        with self.assertRaises(CanonicalContractError):
            _status_for(
                {"outcome": "CAPTURED", "reason": "BYTES_PRESERVED"},
                [self.original], parser_state="NOT_RUN")
        self.assert_preserved_and_pending()
        # No acquisition PARTIAL/PARSE_FAILED status was persisted.

    def test_56_03_CT_02_N2_no_unsupported_complete_status(self):
        error = self.run_without_parser()
        self.assertIn("NORMALIZATION_PENDING", error)
        with self.assertRaises(CanonicalContractError):
            _status_for(
                {"outcome": "CAPTURED", "reason": "BYTES_PRESERVED"},
                [self.original], parser_state="NOT_RUN")
        self.assert_preserved_and_pending()
        # No acquisition COMPLETE/OK status was persisted.


if __name__ == "__main__":
    unittest.main()
