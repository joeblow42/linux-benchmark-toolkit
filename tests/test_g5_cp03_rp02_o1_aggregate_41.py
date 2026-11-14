"""RP-02 Increment 41 O1 source-wide original byte budget: source-first oracles.

No real devices or helper execution. Candidate only, CP-02 acceptance OPEN.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import tempfile
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter, RunMeter
from lbt_g5.o1 import OptionalSourcePlan
from lbt_g5.receipt_dispatch import RecordedOutcome, capture_and_record
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceConsent, SourceRequest, initial_source_policies

RUN = "run-2026318180000"
POL = {p.source_id: p for p in initial_source_policies()}
MIB = 1024 * 1024
SOURCE = "SRC-18"
UPSTREAM = "SRC-17"
TARGET = "/dev/sr0"
INVP = "/sys/class/block/sr0/removable"
INVRAW = b"1\n"
CAP = POL[SOURCE].per_target_bytes


class O1SourceAggregateOracles(unittest.TestCase):
    def fixture(self, *, missing_prior=False, unsealed_source_reservation=False):
        self.assertEqual(CAP, 4 * MIB)
        self.assertEqual(POL[SOURCE].max_bytes, 8 * MIB)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name) / RUN
        folder.mkdir(mode=0o700)
        writer = EvidenceWriter(str(folder), RUN, RunMeter(max_bytes=32 * MIB))
        inv = writer.seal_chunks(POL[UPSTREAM], "01", "item0001", (INVRAW,)).receipt
        self.assertIsNotNone(inv)
        inv_receipt = build_attempt(
            RUN, UPSTREAM, "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=(inv,), bytes_count=len(INVRAW),
            invocation=POL[UPSTREAM].operation_id, source_paths=(INVP,))
        upstream = RecordedOutcome(
            SimpleNamespace(artifacts=(inv,), disposition="CAPTURED",
                            source_paths=(INVP,)),
            commit_attempt(str(folder), inv_receipt))
        op = POL[SOURCE].operation_id
        consent = SourceConsent(RUN, SOURCE, op, TARGET,
                                datetime.now(timezone.utc), True)
        request = SourceRequest(
            RUN, SOURCE, op, target=TARGET, consent=consent,
            trusted_targets=frozenset({TARGET}))
        plan = OptionalSourcePlan(SOURCE, op, TARGET,
                                  ("sg_get_config", "--readonly", "--current", TARGET),
                                  CAP, POL[SOURCE].per_target_seconds, "approved impact")
        bound = dict(source_id=UPSTREAM, source_path=INVP,
                     evidence_id=inv.evidence_id)
        calls = SourceCallBudget()
        records = []
        for i in range(3 if not unsealed_source_reservation else 2):
            data = (b"A" * CAP if i < 2 and not unsealed_source_reservation
                    else b"B" * CAP if i == 0 else b"C" * 17)
            if i == 2:
                data = b"C" * 17
            if unsealed_source_reservation and i == 1:
                # Synthetic corruption of the private accounting meter:
                # its asserted source total has no corresponding sealed original.
                writer._source_reserved[(SOURCE,)] = POL[SOURCE].max_bytes
            captured = TransportCapture(data, b"", 0, .04, False, False, 0, 0)
            with patch("lbt_g5.o1_execution.plan_optional", return_value=plan), \
                 patch("lbt_g5.o1_execution._resolve_executable",
                       return_value="/usr/bin/sg_get_config"), \
                 patch("lbt_g5.o1_execution._capture_child",
                       return_value=captured):
                item = capture_and_record(
                    request, "%02d" % (i + 1), writer, ProbeSlots(), calls,
                    subcall=i, o1_inventory_binding=bound)
            records.append(item)
        if missing_prior:
            preserved = (upstream, records[0], records[-1])
        else:
            preserved = (upstream,) + tuple(records)
        run = EngineRun(RUN, (CollectorRun(POL[SOURCE].collector_id,preserved),))
        receipt = json.loads((folder / records[-1].receipt_private_path).read_text())
        return folder, receipt, run, records

    def test_41_01_actual_third_call_source_writer_limit(self):
        folder, receipt, run, records = self.fixture()
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        self.assertEqual(receipt["outcome"], "PARTIAL")
        self.assertEqual(receipt["reason"], "CAPTURE_LIMIT")
        self.assertEqual(receipt["limit_witnesses"], [{
            "unit": "bytes", "threshold": 8 * MIB,
            "observed_extent": 8 * MIB, "missing_extent": 17,
            "affected_scope": "SRC-18:call0003:source:writer",
            "reason": "CAPTURE_LIMIT"}])
        clipped = records[-1].outcome["receipts"][0]
        self.assertTrue(clipped.limit_applied)
        self.assertEqual(clipped.omitted_at_least, 17)
        self.assertEqual((folder / clipped.private_relative_path).read_bytes(), b"")
        self.assertEqual(clipped.sha256, hashlib.sha256(b"").hexdigest())
        build_canonical(folder, run)
        limits=json.loads((folder/"private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0]["affected_scope"], "SRC-18:call0003:source:writer")

    def test_41_02_missing_prior_source_original_refuses_aggregate(self):
        folder, receipt, run, _ = self.fixture(missing_prior=True)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder, run)

    def test_41_03_forged_source_writer_limit_rejected(self):
        for threshold, omitted, scope in (
            (8 * MIB - 1, 17, "source:writer"),
            (8 * MIB + 1, 17, "source:writer"),
            (8 * MIB, 0, "source:writer"),
            (8 * MIB, None, "source:writer"),
            (8 * MIB, 17, "source:bytes"),
        ):
            fact = dict(unit="bytes", threshold=threshold,
                        observed_extent=threshold, missing_extent=omitted,
                        affected_scope="SRC-18:call0003:" + scope,
                        reason="CAPTURE_LIMIT")
            with self.subTest(fact=fact), self.assertRaises(ValueError):
                build_attempt(RUN, SOURCE, "03", "ALLOW", "PARTIAL",
                              "CAPTURE_LIMIT", capture_limited=True,
                              limit_witnesses=(fact,))

    def test_41_04_unsealed_source_meter_reservation_is_not_proof(self):
        folder, receipt, run, _ = self.fixture(unsealed_source_reservation=True)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        with self.assertRaisesRegex(CanonicalContractError,
                                    "source writer aggregate"):
            build_canonical(folder, run)

    def test_41_05_src21_single_call_source_limit_not_invented(self):
        self.assertEqual(POL["SRC-21"].max_entries, 1)
        self.assertEqual(POL["SRC-21"].max_bytes, 8 * MIB)
        calls=SourceCallBudget()
        self.assertTrue(calls.begin(RUN, "SRC-21", 0))
        self.assertFalse(calls.begin(RUN, "SRC-21", 1))
        calls.end(RUN, "SRC-21", .01)

    def test_41_06_helper_internal_cumulative_effective_cap_unattested(self):
        # The protected wire-to-TransportCapture contract still omits the
        # exact helper-applied remaining byte and time ceilings.
        self.assertNotIn("applied_max_bytes", TransportCapture.__dataclass_fields__)
        self.assertNotIn("applied_max_seconds", TransportCapture.__dataclass_fields__)
        self.assertEqual(POL["SRC-13"].max_bytes, 32 * MIB)
        self.assertEqual(POL["SRC-13"].max_seconds, 60)

    def test_41_07_source_time_not_provable_by_elapsed_sum_alone(self):
        calls=SourceCallBudget()
        self.assertTrue(calls.begin(RUN, SOURCE, 0))
        calls.end(RUN, SOURCE, 7.9)
        self.assertGreater(calls.remaining(RUN, SOURCE), 0)
        self.assertLess(calls.remaining(RUN, SOURCE),
                        POL[SOURCE].max_seconds)
        # This is a budget measurement, NOT an observed timeout event.


if __name__=="__main__":
    unittest.main()
