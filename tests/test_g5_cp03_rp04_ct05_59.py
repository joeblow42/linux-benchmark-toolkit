"""RP-04 Increment 59 — CT-05 measured wall-time and byte-limit candidate checks.

The SRC-15 source wall-time test advances real monotonic time with an idle
controlled fixture; its source child payload is synthetic and cannot establish
physical-host FAT acceptance. G5-03 performs actual elapsed measurement.
The byte test actually seals temporary original bytes through G5-02 writer.
"""
import json
from pathlib import Path
import time
import unittest

import test_g5_cp03_rp02_src15_aggregate_37 as prior
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.records import build_attempt
from lbt_g5.runtime import TransportCapture
from lbt_g5.safety import initial_source_policies

POL={p.source_id:p for p in initial_source_policies()}
SRC="SRC-15"
MIB=1024*1024

class RP04CT05Candidate59(unittest.TestCase):
    wall_witness=None
    byte_witness=None

    def test_59_01_CT_05_P1_real_measured_source_elapsed_seconds(self):
        ceiling=POL[SRC].max_seconds
        self.assertEqual(ceiling,15)
        paths=prior.mounts(25)
        def measured_fixture():
            for mount in paths:
                start=time.monotonic()
                # Real elapsed clock; no device calls or CPU load. The G5-03
                # worker result is simulated only to preserve safe CI scope.
                time.sleep(1.08)
                measured=time.monotonic()-start
                yield TransportCapture(prior.stat_payload(mount),b"",0,
                    measured,False,False,0,0)
        folder,receipt,run,invoked=prior.SRC15AggregateOracles.acquire(
            self,paths,measured_fixture(),clock=None)
        self.assertGreater(len(invoked),1)
        self.assertLess(len(invoked),len(paths))
        self.assertTrue(receipt["timed_out"])
        self.assertEqual(receipt["reason"],"TIME_BUDGET_EXCEEDED")
        self.assertGreaterEqual(receipt["source_timing"]["elapsed_ms"],
                                ceiling*1000)
        self.assertGreaterEqual(receipt["elapsed_seconds"],ceiling)
        facts=receipt["limit_witnesses"]
        self.assertEqual(len(facts),1)
        bound=facts[0]
        self.assertEqual(bound["affected_scope"],"SRC-15:call0001:source:time")
        self.assertEqual(bound["unit"],"seconds")
        self.assertEqual(bound["threshold"],ceiling)
        self.assertEqual(bound["reason"],"TIME_BUDGET_EXCEEDED")
        self.assertIsNone(bound["missing_extent"])
        self.assertGreaterEqual(bound["observed_extent"],ceiling)
        # Source elapsed and actual recorded monotonic attempt duration must
        # be consistent; never infer omitted bytes from a clock.
        self.assertLessEqual(bound["observed_extent"],
                             receipt["source_timing"]["elapsed_ms"]/1000+.25)
        manifest=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),manifest)
        canonical=json.loads((folder/"private/system.json").read_text())
        self.assertEqual(len(canonical["capture_limits"]),1)
        self.assertEqual(canonical["capture_limits"][0]["unit"],"seconds")
        self.assertIsNone(canonical["capture_limits"][0]["missing_extent"])
        type(self).wall_witness={
            "source":"SRC-15","metric":"source_cumulative_monotonic_seconds",
            "threshold_seconds":ceiling,
            "source_elapsed_ms":receipt["source_timing"]["elapsed_ms"],
            "observed_seconds":bound["observed_extent"],
            "worker_calls":len(invoked),
            "original_payloads":"synthetic mount-local FS_STAT records",
            "actual_clock":"time.monotonic",
        }

    def test_59_02_CT_05_P2_real_writer_byte_omission(self):
        cap=POL[SRC].max_bytes
        self.assertEqual(cap,2*MIB)
        folder,receipt,run,invoked=prior.SRC15AggregateOracles.acquire(
            self,prior.mounts(4),[
                prior.capture(b"A"*MIB),prior.capture(b"B"*MIB),
                prior.capture(b"OVERFLOW"),prior.capture(b"NOT_INVOKED")])
        self.assertEqual(len(invoked),3)
        self.assertEqual(receipt["outcome"],"PARTIAL")
        self.assertEqual(receipt["reason"],"CAPTURE_LIMIT")
        self.assertEqual(receipt["acquired_bytes"],cap)
        fact=receipt["limit_witnesses"][0]
        self.assertEqual((fact["unit"],fact["threshold"],
                          fact["observed_extent"],fact["missing_extent"]),
                         ("bytes",cap,cap,len(b"OVERFLOW")))
        self.assertEqual(fact["affected_scope"],
                         "SRC-15:call0001:source:writer")
        manifest=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),manifest)
        self.assertEqual(manifest["counts"]["original_bytes"],
                         cap+len(prior.original_mountinfo(prior.mounts(4))))
        canonical=json.loads((folder/"private/system.json").read_text())
        self.assertEqual(len(canonical["capture_limits"]),1)
        limit=canonical["capture_limits"][0]
        self.assertEqual((limit["unit"],limit["threshold"],
                          limit["observed_extent"],limit["missing_extent"]),
                         ("bytes",cap,cap,8))
        type(self).byte_witness={
            "source":"SRC-15","unit":"bytes","applied_threshold":cap,
            "sealed_source_bytes":receipt["acquired_bytes"],
            "known_omitted_at_least":fact["missing_extent"],
            "writer_used":"G5-02 EvidenceWriter; actual temporary original bytes",
        }

    def test_59_03_CT_05_N1_time_event_cannot_be_byte_limit(self):
        ceiling=POL[SRC].max_seconds
        # Deliberately invalid negative fixture, NOT a claim of measurement.
        good=dict(unit="seconds",threshold=ceiling,
                  observed_extent=ceiling,missing_extent=None,
                  affected_scope="SRC-15:call0001:source:time",
                  reason="TIME_BUDGET_EXCEEDED")
        for bad in (dict(good,unit="bytes"),
                    dict(good,reason="CAPTURE_LIMIT"),
                    dict(good,missing_extent=1),
                    dict(good,affected_scope="SRC-15:call0001:source:writer")):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                build_attempt(prior.RUN,SRC,"01","ALLOW","PARTIAL",
                              "TIME_BUDGET_EXCEEDED",timed_out=True,
                              capture_limited=False,limit_witnesses=(bad,))


if __name__=="__main__":
    unittest.main()
