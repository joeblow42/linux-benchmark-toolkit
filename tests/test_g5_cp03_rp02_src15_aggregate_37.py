"""RP-02 / Increment 37: source-first SRC-15 source-clock and writer-quota oracles.

Mock-only controlled source inputs. Not CP-02 independently accepted evidence.
"""
from contextlib import ExitStack
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lbt_g5.canonical_session import build_canonical, CanonicalContractError
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter, RunMeter
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest, initial_source_policies

RUN = "run-2026318170000"
SRC = "SRC-15"
MIB = 1024 * 1024
POL = {p.source_id: p for p in initial_source_policies()}


def mounts(count):
    return ("/",) + tuple("/mnt/f04_" + str(i).zfill(3) for i in range(1, count))


def original_mountinfo(paths):
    return "".join(
        f"{i + 1} 0 8:1 / {p} rw - ext4 /dev/loop0 rw\n"
        for i, p in enumerate(paths)
    ).encode()


def stat_payload(mount="/"):
    return (json.dumps(dict(mount=mount, fragment_size=4096, block_size=4096,
        blocks=100, free_blocks=40, available_blocks=30,
        files=1000, free_files=800), sort_keys=True) + "\n").encode()


def capture(payload):
    return TransportCapture(payload, b"", 0, 0.5, False, False, 0, 0)


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def monotonic_ns(self):
        return round(self.now * 1_000_000_000)


class SRC15AggregateOracles(unittest.TestCase):
    def acquire(self, paths, captures, *, clock=None, seal_lag=0.0,
                run_meter_extra=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name) / RUN
        folder.mkdir(mode=0o700)
        raw14 = original_mountinfo(paths)
        meter = (RunMeter(max_bytes=len(raw14) + run_meter_extra)
                 if run_meter_extra is not None else None)
        writer = EvidenceWriter(str(folder), RUN, meter)
        sealed14 = writer.seal_chunks(POL["SRC-14"], "01", "item0001", (raw14,))
        self.assertIsNone(sealed14.failure)
        self.assertFalse(sealed14.receipt.limit_applied)
        receipt14 = build_attempt(RUN, "SRC-14", "01", "ALLOW", "CAPTURED",
            "BYTES_PRESERVED", evidence=(sealed14.receipt,),
            bytes_count=sealed14.receipt.byte_count, invocation="MOUNTINFO",
            source_paths=("/proc/self/mountinfo",))
        rec14 = SimpleNamespace(
            receipt_private_path=commit_attempt(str(folder), receipt14),
            outcome=SimpleNamespace(artifacts=(sealed14.receipt,)))
        invoked = []
        transports = iter(captures)

        def worker(*args):
            invoked.append(args)
            item = next(transports)
            if clock is not None:
                clock.now += item.elapsed_seconds
            return item

        previous_seal = writer.seal_chunks

        def seal_with_clock(*args, **kwargs):
            sealed = previous_seal(*args, **kwargs)
            if clock is not None:
                clock.now += seal_lag
            return sealed

        with ExitStack() as stack:
            stack.enter_context(patch(
                "lbt_g5.additional.decide_source",
                return_value=SimpleNamespace(allowed=True, reason="APPROVED")))
            stack.enter_context(patch(
                "lbt_g5.additional.eligible_mounts", return_value=paths))
            stack.enter_context(patch(
                "lbt_g5.additional._resolve_executable",
                return_value="/usr/bin/python3"))
            stack.enter_context(patch(
                "lbt_g5.additional._capture_child", side_effect=worker))
            if clock is not None:
                stack.enter_context(patch(
                    "lbt_g5.additional.time",
                    SimpleNamespace(monotonic=clock.monotonic)))
                stack.enter_context(patch(
                    "lbt_g5.receipt_dispatch.time",
                    SimpleNamespace(monotonic_ns=clock.monotonic_ns)))
                stack.enter_context(patch.object(
                    writer, "seal_chunks", side_effect=seal_with_clock))
            rec15 = capture_and_record(SourceRequest(RUN, SRC, "FS_STAT"),
                "01", writer, ProbeSlots(), SourceCallBudget(),
                source14_evidence=raw14)
        record = json.loads((folder / rec15.receipt_private_path).read_text())
        run = EngineRun(RUN, (CollectorRun("COL-FS",
            (rec14, rec15)),))
        return folder, record, run, invoked

    def test_37_01_cumulative_clock_witness_after_successful_calls(self):
        paths = mounts(10)
        clock = Clock()
        folder, receipt, run, invoked = self.acquire(
            paths, [capture(stat_payload(p)) for p in paths],
            clock=clock, seal_lag=1.2)
        self.assertEqual(len(invoked), 9)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        self.assertTrue(receipt["timed_out"])
        self.assertEqual(receipt["reason"], "TIME_BUDGET_EXCEEDED")
        self.assertGreaterEqual(receipt["source_timing"]["elapsed_ms"], 15000)
        self.assertEqual(len(receipt["limit_witnesses"]), 1)
        bound = receipt["limit_witnesses"][0]
        self.assertEqual((bound["unit"], bound["threshold"], bound["missing_extent"],
                          bound["affected_scope"]),
                         ("seconds", 15, None, "SRC-15:call0001:source:time"))
        self.assertGreaterEqual(bound["observed_extent"], 15)
        build_canonical(folder, run)
        limits = json.loads((folder / "private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0]["affected_scope"], bound["affected_scope"])

    def test_37_02_nominal_last_target_stays_legacy(self):
        paths = mounts(1)
        folder, receipt, run, called = self.acquire(
            paths, [capture(stat_payload())])
        self.assertEqual(len(called), 1)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.4")
        self.assertNotIn("limit_witnesses", receipt)
        build_canonical(folder, run)

    def test_37_03_child_timeout_not_relabelled_source_timeout(self):
        paths = mounts(2)
        bad = TransportCapture(stat_payload(), b"", None, 2.03, True, False, 0, 0)
        folder, receipt, run, called = self.acquire(paths, [bad])
        self.assertEqual(len(called), 1)
        self.assertEqual(receipt["limit_witnesses"][0]["affected_scope"],
                         "SRC-15:call0001:transport")
        build_canonical(folder, run)

    def test_37_04_source_aggregate_writer_quota_and_stop(self):
        paths = mounts(4)
        folder, receipt, run, called = self.acquire(
            paths, [capture(b"A" * MIB), capture(b"B" * MIB),
                    capture(b"OVERFLOW"), capture(b"NEVER")])
        self.assertEqual(len(called), 3)
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        self.assertEqual(receipt["acquired_bytes"], 2 * MIB)
        self.assertEqual(len(receipt["limit_witnesses"]), 1)
        bound = receipt["limit_witnesses"][0]
        self.assertEqual((bound["unit"], bound["threshold"], bound["observed_extent"],
                          bound["missing_extent"], bound["affected_scope"]),
                         ("bytes", 2 * MIB, 2 * MIB, 8,
                          "SRC-15:call0001:source:writer"))
        build_canonical(folder, run)
        limits = json.loads((folder / "private/system.json").read_text())["capture_limits"]
        self.assertEqual(limits[0]["affected_scope"], bound["affected_scope"])

    def test_37_05_exact_source_byte_ceiling_no_omission(self):
        paths = mounts(2)
        folder, receipt, run, called = self.acquire(
            paths, [capture(b"A" * MIB), capture(b"B" * MIB)])
        self.assertEqual(len(called), 2)
        self.assertEqual(receipt["acquired_bytes"], 2 * MIB)
        self.assertNotIn("limit_witnesses", receipt)
        build_canonical(folder, run)

    def test_37_06_run_quota_does_not_impersonate_source_quota(self):
        paths = mounts(2)
        folder, receipt, run, called = self.acquire(
            paths, [capture(stat_payload())], run_meter_extra=16)
        self.assertEqual(len(called), 1)
        self.assertNotIn("limit_witnesses", receipt)
        self.assertEqual(receipt["outcome"], "PARTIAL")
        with self.assertRaisesRegex(
                CanonicalContractError, "dimension not evidenced"):
            build_canonical(folder, run)

    def test_37_07_reject_invented_source_clock(self):
        good = dict(unit="seconds", threshold=15, observed_extent=15.2,
            missing_extent=None, affected_scope="SRC-15:call0001:source:time",
            reason="TIME_BUDGET_EXCEEDED")
        bad = (dict(good, threshold=14), dict(good, threshold=16),
               dict(good, observed_extent=14.99),
               dict(good, affected_scope="SRC-15:call0002:source:time"))
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_attempt(RUN, SRC, "01", "ALLOW", "PARTIAL",
                    "TIME_BUDGET_EXCEEDED", timed_out=True,
                    limit_witnesses=(value,))
        with self.assertRaises(ValueError):
            build_attempt(RUN, SRC, "01", "ALLOW", "PARTIAL",
                "TIME_BUDGET_EXCEEDED", timed_out=False,
                limit_witnesses=(good,))

    def test_37_08_reject_unproved_writer_source_bytes(self):
        good = dict(unit="bytes", threshold=2*MIB, observed_extent=2*MIB,
            missing_extent=8, affected_scope="SRC-15:call0001:source:writer",
            reason="CAPTURE_LIMIT")
        for bad in (dict(good, threshold=MIB), dict(good, observed_extent=MIB),
                    dict(good, missing_extent=0),
                    dict(good, missing_extent=None),
                    dict(good, affected_scope="SRC-15:call0002:source:writer")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                build_attempt(RUN, SRC, "01", "ALLOW", "PARTIAL", "CAPTURE_LIMIT",
                    capture_limited=True, limit_witnesses=(bad,))


if __name__ == "__main__":
    unittest.main()
