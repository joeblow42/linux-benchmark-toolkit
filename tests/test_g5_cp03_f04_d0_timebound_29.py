"""Source-first D0 CT-05 timeout witness oracles; mock-only and not accepted CP-02 proof."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lbt_g5.evidence import EvidenceWriter
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest, initial_source_policies
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.canonical_session import build_canonical, CanonicalContractError

RUN = "run-2026313120000"
SRC = "SRC-02"


def transport_record(*, record_limited=False, end=False):
    value = b"NAME=Example\\n"
    record = {"path": "/etc/os-release",
              "bytes_b64": base64.b64encode(value).decode("ascii"),
              "limited": record_limited}
    lines = [record]
    if end:
        lines.append({"end": True, "entries": 1, "bytes": len(value), "limited": False})
    return b"".join((json.dumps(x, sort_keys=True) + "\\n").encode() for x in lines)


class D0ActualTimeoutLimitOracles(unittest.TestCase):
    def one(self, transport):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name) / RUN
        folder.mkdir(mode=0o700)
        policy = {p.source_id: p for p in initial_source_policies()}[SRC]
        request = SourceRequest(RUN, SRC, policy.operation_id)
        writer = EvidenceWriter(str(folder), RUN)
        with patch("lbt_g5.passive._resolve_executable", return_value="/usr/bin/python3"):
            with patch("lbt_g5.passive._capture_child", return_value=transport) as invoked:
                recorded = capture_and_record(request, "01", writer,
                                              ProbeSlots(), SourceCallBudget())
        raw = json.loads((folder / recorded.receipt_private_path).read_text())
        run = EngineRun(RUN, (CollectorRun(policy.collector_id, (recorded,)),))
        return folder, raw, run, invoked

    def test_t01_actual_d0_deadline_is_seconds_not_source_bytes(self):
        captured = TransportCapture(transport_record(), b"", None, 2.125,
                                    True, False, 0, 0)
        folder, receipt, run, called = self.one(captured)
        actual_cap = called.call_args.args[3]
        self.assertGreater(actual_cap, 0)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.5")
        self.assertEqual(receipt["limit_witness"], {
            "unit": "seconds", "threshold": actual_cap,
            "observed_extent": 2.125, "missing_extent": None,
            "affected_scope": SRC + ":call0001:transport",
            "reason": "TIME_BUDGET_EXCEEDED"
        })
        self.assertTrue(receipt["timed_out"])
        build_canonical(folder, run)
        limits = json.loads((folder / "private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0]["unit"], "seconds")
        self.assertEqual(limits[0]["threshold"], actual_cap)
        self.assertIsNone(limits[0]["missing_extent"])

    def test_t02_simultaneous_transport_time_and_bytes_cannot_claim_one(self):
        captured = TransportCapture(transport_record(), b"", None, 2.125,
                                    True, True, 4, 0)
        folder, receipt, run, _ = self.one(captured)
        self.assertNotIn("limit_witness", receipt)
        self.assertTrue(receipt["timed_out"])
        self.assertTrue(receipt["capture_limited"])
        with self.assertRaisesRegex(CanonicalContractError, "dimension not evidenced"):
            build_canonical(folder, run)

    def test_t03_worker_per_file_limit_and_timeout_cannot_claim_only_time(self):
        captured = TransportCapture(transport_record(record_limited=True), b"",
                                    None, 2.125, True, False, 0, 0)
        folder, receipt, run, _ = self.one(captured)
        self.assertNotIn("limit_witness", receipt)
        with self.assertRaisesRegex(CanonicalContractError, "dimension not evidenced"):
            build_canonical(folder, run)

    def test_t04_success_has_no_capture_limit(self):
        captured = TransportCapture(transport_record(end=True), b"",
                                    0, .07, False, False, 0, 0)
        folder, receipt, run, _ = self.one(captured)
        self.assertNotIn("limit_witness", receipt)
        build_canonical(folder, run)
        limits = json.loads((folder / "private/system.json").read_text())["capture_limits"]
        self.assertEqual(limits, [])


if __name__ == "__main__":
    unittest.main()
