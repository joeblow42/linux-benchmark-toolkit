"""SRC-15 cumulative wall-budget regression: never label exhausted time as invocation count."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lbt_g5.additional import acquire_additional
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest

RUN = "run-2026305120000"


class AdditionalBudgetRegression(unittest.TestCase):
    def test_exhausted_source_time_is_not_invocation_limit(self):
        if os.geteuid() == 0:
            self.skipTest("G4-07 execution prohibits root")
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / RUN
            directory.mkdir()
            writer = EvidenceWriter(str(directory), RUN)
            req = SourceRequest(RUN, "SRC-15", "FS_STAT")
            clock = [0.0]
            calls = []

            def simulated_worker(*args, **kwargs):
                calls.append(args)
                # Simulate observed cumulative wall clock running out after
                # a successful first device-stat operation.
                clock[0] = 16.0
                return TransportCapture(b"captured-original-bytes", b"", 0,
                                        0.1, False, False, 0, 0)

            with patch("lbt_g5.additional.eligible_mounts",
                       return_value=("/","/rofs","/cdrom")):
                with patch("lbt_g5.additional._resolve_executable",
                           return_value="/usr/bin/python3"):
                    with patch("lbt_g5.additional._capture_child",
                               side_effect=simulated_worker):
                        with patch("lbt_g5.additional.time.monotonic",
                                   side_effect=lambda: clock[0]):
                            result = acquire_additional(
                                req, "01", writer, ProbeSlots(),
                                SourceCallBudget(), source14_evidence=b"fixture")
            self.assertEqual(len(calls), 1)
            self.assertEqual(result.disposition, "PARTIAL")
            self.assertEqual(result.reason, "TIME_BUDGET_EXCEEDED")
            self.assertIn("TIME_BUDGET_EXCEEDED", result.errors)
            self.assertNotIn("INVOCATION_LIMIT", result.errors)
            self.assertTrue(result.artifacts)
            self.assertEqual(
                (directory / result.artifacts[0].private_relative_path).read_bytes(),
                b"captured-original-bytes")

    def test_disabled_preflight_does_not_probe_mounts(self):
        req=SourceRequest(RUN, "SRC-15", "FS_STAT", operator_disabled=True)
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)/RUN
            directory.mkdir()
            with patch("lbt_g5.additional.eligible_mounts") as mounted:
                result=acquire_additional(
                    req,"01",EvidenceWriter(str(directory),RUN),
                    ProbeSlots(),SourceCallBudget(),source14_evidence=b"fixture")
            self.assertEqual(result.disposition,"DENIED")
            mounted.assert_not_called()


if __name__ == "__main__":
    unittest.main()
