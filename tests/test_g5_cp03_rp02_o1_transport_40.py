"""Source-first Increment 40 O1 transport and helper-applied-cap evidence.

Synthetic only: NO devices, root helpers, sudo, or live commands are executed.
Candidate CI is not independent CP-02 acceptance.
"""
import json
import unittest
from pathlib import Path

import test_g5_cp03_rp02_o1_writer_39 as prior
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical
from lbt_g5.records import build_attempt
from lbt_g5.runtime import TransportCapture
from lbt_g5.safety import initial_source_policies

POL = {p.source_id: p for p in initial_source_policies()}
MIB = 1024 * 1024


class O1TransportAppliedOracles(unittest.TestCase):
    def fixture(self, source, captured, *, helper=False, retained=None,
                exclude_inventory=False):
        if retained is None:
            retained = len(captured.stdout) + len(captured.stderr)
        return prior.O1RunWriterOracles.fixture(
            self, source, retained=retained, raw=b"ignored",
            captured=captured, helper=helper,
            exclude_inventory=exclude_inventory)

    def proof(self, source, captured, *, helper=False):
        folder, receipt, run, recorded, _ = self.fixture(
            source, captured, helper=helper)
        cap = POL[source].per_target_bytes or POL[source].max_bytes
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        self.assertEqual(receipt["outcome"], "PARTIAL")
        self.assertEqual(receipt["reason"], "CAPTURE_LIMIT")
        self.assertEqual(receipt["limit_witnesses"], [{
            "unit": "bytes", "threshold": cap,
            "observed_extent": cap,
            "missing_extent": (captured.stdout_omitted_at_least +
                               captured.stderr_omitted_at_least),
            "affected_scope": source + ":call0001:transport",
            "reason": "CAPTURE_LIMIT"}])
        self.assertTrue(all(not x.limit_applied for x in recorded.outcome["receipts"]))
        self.assertEqual(sum(x.byte_count for x in recorded.outcome["receipts"]), cap)
        build_canonical(folder, run)
        canonical = json.loads((folder / "private/system.json").read_text())
        self.assertEqual(len(canonical["capture_limits"]), 1)
        self.assertEqual(canonical["capture_limits"][0]["threshold"], cap)
        self.assertEqual(canonical["capture_limits"][0]["affected_scope"],
                         source + ":call0001:transport")
        return folder, receipt, run, recorded

    def reject_unsupported(self, source, captured, *, helper=False,
                           retained=None):
        folder, receipt, run, _, _ = self.fixture(
            source, captured, helper=helper, retained=retained)
        self.assertNotIn("limit_witnesses", receipt)
        with self.assertRaisesRegex(CanonicalContractError,
                                   "dimension not evidenced"):
            build_canonical(folder, run)

    def test_40_01_src18_direct_unique_combined_cap(self):
        cap = POL["SRC-18"].per_target_bytes
        captured = TransportCapture(b"A" * (cap-7), b"B" * 7,
                                    0, .04, False, True, 0, 13)
        self.proof("SRC-18", captured)

    def test_40_02_src21_direct_unique_combined_cap(self):
        cap = POL["SRC-21"].max_bytes
        captured = TransportCapture(b"A" * (cap-5), b"B" * 5,
                                    0, .04, False, True, 0, 17)
        self.proof("SRC-21", captured)

    def test_40_03_src13_helper_full_per_request_cap(self):
        cap = POL["SRC-13"].per_target_bytes
        # A smaller internal helper cumulative remainder cannot have produced
        # this entire sealed original: the effective cap must have been 8 MiB.
        captured = TransportCapture(b"H" * cap, b"", 0, .04,
                                    False, True, 9, 0)
        self.proof("SRC-13", captured, helper=True)

    def test_40_04_helper_shorter_unknown_cumulative_cap_not_inferred(self):
        captured = TransportCapture(b"H" * 100, b"", 0, .04,
                                    False, True, 12, 0)
        self.reject_unsupported("SRC-13", captured, helper=True, retained=100)

    def test_40_05_direct_stream_combined_tie_not_promoted(self):
        cap = POL["SRC-18"].per_target_bytes
        captured = TransportCapture(b"A" * cap, b"", 0, .04,
                                    False, True, 9, 0)
        self.reject_unsupported("SRC-18", captured)

    def test_40_06_short_unknown_or_timeout_or_writer_conflict(self):
        cap = POL["SRC-18"].per_target_bytes
        samples = (
            (TransportCapture(b"A" * (cap-3), b"B", 0, .04,
                              False, True, 0, 5), cap-2),
            (TransportCapture(b"A" * (cap-3), b"B" * 3, None, 8.5,
                              True, True, 0, 5), cap),
            (TransportCapture(b"A" * (cap-3), b"B" * 3, 0, .04,
                              False, True, 0, 5), cap-1),
        )
        for capture, retained in samples:
            with self.subTest(retained=retained, timeout=capture.timed_out):
                self.reject_unsupported("SRC-18", capture, retained=retained)

    def test_40_07_exact_boundary_has_no_missing_original(self):
        cap = POL["SRC-18"].per_target_bytes
        captured = TransportCapture(b"A" * (cap-1), b"B", 0, .04,
                                    False, False, 0, 0)
        folder, receipt, run, _, _ = self.fixture("SRC-18", captured)
        self.assertNotIn("limit_witnesses", receipt)
        self.assertFalse(receipt["capture_limited"])
        build_canonical(folder, run)

    def test_40_08_missing_inventory_and_forged_threshold_rejected(self):
        cap = POL["SRC-18"].per_target_bytes
        captured = TransportCapture(b"A" * (cap-3), b"B" * 3, 0, .04,
                                    False, True, 0, 3)
        folder, receipt, run, _, _ = self.fixture(
            "SRC-18", captured, exclude_inventory=True)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder, run)
        for threshold, scope, omitted in (
            (cap-1, "transport", 3),
            (cap+1, "transport", 3),
            (cap, "stdout", 3),
            (cap, "transport", None),
            (cap, "transport", 0),
        ):
            fact = dict(unit="bytes", threshold=threshold,
                        observed_extent=threshold,
                        missing_extent=omitted,
                        affected_scope="SRC-18:call0001:" + scope,
                        reason="CAPTURE_LIMIT")
            with self.subTest(fact=fact), self.assertRaises(ValueError):
                build_attempt(prior.RUN, "SRC-18", "01", "ALLOW",
                              "PARTIAL", "CAPTURE_LIMIT",
                              capture_limited=True, limit_witnesses=(fact,))


if __name__ == "__main__":
    unittest.main()
