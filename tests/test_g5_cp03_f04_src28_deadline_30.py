"""Source-first SRC-28 actual effective deadline oracles. Mock-only, CP-02 open."""
import json
import tempfile
import unittest
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lbt_g5.canonical_session import build_canonical, CanonicalContractError
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest, initial_source_policies

RUN = "run-2026313120000"
SRC = "SRC-28"
RAW = b"dpkg\t1.21.22\n"


class SRC28MeasuredDeadlineOracles(unittest.TestCase):
    def one(self, capture, *, writer_cap=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name) / RUN
        folder.mkdir(mode=0o700)
        writer = EvidenceWriter(str(folder), RUN)
        policy = {p.source_id: p for p in initial_source_policies()}[SRC]
        request = SourceRequest(RUN, SRC, "OFFLINE_METADATA")
        original_seal = writer.seal_chunks

        def second_limit(*args, **kwargs):
            result = original_seal(*args, **kwargs)
            return replace(result, receipt=replace(result.receipt,
                          limit_applied=True, omitted_at_least=1))

        with ExitStack() as stack:
            stack.enter_context(patch("lbt_g5.additional.decide_source",
                          return_value=SimpleNamespace(allowed=True, reason="APPROVED")))
            stack.enter_context(patch("lbt_g5.additional._resolve_executable",
                          return_value="/usr/bin/dpkg-query"))
            invoked = stack.enter_context(patch("lbt_g5.additional._capture_child",
                          return_value=capture))
            if writer_cap:
                stack.enter_context(patch.object(writer, "seal_chunks",
                                                side_effect=second_limit))
            recorded = capture_and_record(request, "01", writer,
                                          ProbeSlots(), SourceCallBudget())

        receipt = json.loads((folder / recorded.receipt_private_path).read_text())
        run = EngineRun(RUN, (CollectorRun(policy.collector_id, (recorded,)),))
        return folder, receipt, run, invoked

    def test_s28_t01_single_proven_timeout_yields_seconds_limit(self):
        capture = TransportCapture(RAW, b"", None, 8.031, True, False, 0, 0)
        folder, receipt, run, invoked = self.one(capture)
        limit = receipt["limit_witness"]
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.5")
        self.assertEqual(limit, {
            "unit": "seconds", "threshold": invoked.call_args.args[3],
            "observed_extent": 8.031, "missing_extent": None,
            "affected_scope": SRC + ":call0001:transport",
            "reason": "TIME_BUDGET_EXCEEDED"
        })
        self.assertTrue(receipt["timed_out"])
        self.assertEqual(receipt["execution_provenance"]["argv_executed"][0],
                         "/usr/bin/dpkg-query")
        build_canonical(folder, run)
        limit_rows = json.loads((folder / "private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limit_rows), 1)
        self.assertEqual((limit_rows[0]["unit"], limit_rows[0]["threshold"]),
                         ("seconds", invoked.call_args.args[3]))
        status = json.loads((folder / "private/status_records.json").read_text())
        self.assertIn(("PARTIAL", "CAPTURE_LIMIT"),
                      {(r["status"], r["reason_code"]) for r in status["status_records"]})

    def test_s28_t02_timeout_and_stream_overflow_do_not_claim_one_limit(self):
        capture = TransportCapture(RAW, b"", None, 8.031, True, True, 6, 0)
        folder, receipt, run, _ = self.one(capture)
        self.assertNotIn("limit_witness", receipt)
        self.assertTrue(receipt["timed_out"])
        self.assertTrue(receipt["capture_limited"])
        with self.assertRaisesRegex(CanonicalContractError, "dimension not evidenced"):
            build_canonical(folder, run)

    def test_s28_t03_writer_and_timeout_do_not_claim_one_limit(self):
        capture = TransportCapture(RAW, b"", None, 8.031, True, False, 0, 0)
        folder, receipt, run, _ = self.one(capture, writer_cap=True)
        self.assertNotIn("limit_witness", receipt)
        self.assertTrue(receipt["timed_out"])
        with self.assertRaisesRegex(CanonicalContractError, "dimension not evidenced"):
            build_canonical(folder, run)

    def test_s28_t04_completed_execution_retains_prior_provenance(self):
        capture = TransportCapture(RAW, b"", 0, .081, False, False, 0, 0)
        folder, receipt, run, _ = self.one(capture)
        self.assertNotIn("limit_witness", receipt)
        self.assertFalse(receipt["timed_out"])
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.4")
        build_canonical(folder, run)
        limit_rows = json.loads((folder / "private/system.json").read_text())["capture_limits"]
        self.assertEqual(limit_rows, [])


if __name__ == "__main__":
    unittest.main()
