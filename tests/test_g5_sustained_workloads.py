import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from lbt_g5.peer_workload import Peer, run_peer
from lbt_g5.sustained_workloads import MIB, Monitor, SustainedParameters, run_sustained_cpu, run_sustained_storage
from lbt_g5.workload_process import ProcessLimit, ProcessResult, capture
from lbt_g5.workload_runtime import Cancelled, Context, Unavailable, Unsafe


class SustainedWorkloadsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.context = Context(self.root, lambda: None, {})
        self.sensor = self.root / "temp"
        self.sensor.write_text("45000")
        self.parameters = SustainedParameters(seconds=1, cpu_workers=1, storage_bytes=MIB,
                                             storage_mib_per_second=1)

    def test_monitor_stops_at_limit_and_on_loss(self):
        with patch("lbt_g5.sustained_workloads._sensor_paths", return_value=(self.sensor,)):
            monitor = Monitor(self.context, 80)
            self.sensor.write_text("80000")
            with self.assertRaisesRegex(Unsafe, "CPU_THERMAL_LIMIT"):
                monitor.poll(force=True)
            self.sensor.unlink()
            with self.assertRaisesRegex(Unsafe, "THERMAL_TELEMETRY_LOST"):
                monitor.poll(force=True)
            with self.assertRaisesRegex(Unavailable, "CPU_TEMPERATURE_UNAVAILABLE"):
                Monitor(self.context, 80)

    @patch("lbt_g5.sustained_workloads.check_pressure")
    @patch("lbt_g5.sustained_workloads.local_filesystem", return_value="fixture")
    @patch("lbt_g5.core_workloads.pressure", return_value={"avg10_percent": 0})
    def test_bounded_sustained_cpu_and_storage(self, *_):
        with patch("lbt_g5.sustained_workloads._sensor_paths", return_value=(self.sensor,)):
            cpu = run_sustained_cpu(self.context, self.parameters)
            storage = run_sustained_storage(self.context, self.parameters)
        self.assertGreater(cpu["cpu_samples"][0]["operations"], 0)
        self.assertIsNone(cpu["throughput_retention_percent"])
        self.assertEqual(storage["sampled_bytes"], MIB)
        self.assertEqual((self.root / "sustained-data").stat().st_size, MIB)
        self.assertTrue(storage["thermal_samples"])

    def test_process_deadline_bound_and_cancellation(self):
        with self.assertRaisesRegex(ProcessLimit, "COMMAND_DEADLINE"):
            capture(self.context, (sys.executable, "-c", "import time; time.sleep(10)"), seconds=.1)
        with self.assertRaisesRegex(ProcessLimit, "COMMAND_OUTPUT_LIMIT"):
            capture(self.context, (sys.executable, "-c", "print('x' * 1000)"),
                    seconds=2, output_bytes=100)
        calls = 0

        def cancel():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise Cancelled

        with self.assertRaises(Cancelled):
            capture(Context(self.root, cancel, {}),
                    (sys.executable, "-c", "import time; time.sleep(10)"), seconds=2)

    @patch("lbt_g5.peer_workload.tool_path", return_value="/usr/bin/iperf3")
    @patch("lbt_g5.peer_workload.capture")
    def test_peer_requires_consent_and_builds_bounded_two_direction_plan(self, capture_tool, _):
        with self.assertRaises(ValueError):
            Peer("192.0.2.1", False)
        with self.assertRaises(ValueError):
            Peer("example.org", True)
        end = {"sum_sent": {"bits_per_second": 10, "retransmits": 0},
               "sum_received": {"bits_per_second": 9}}
        capture_tool.return_value = ProcessResult(0, json.dumps({"end": end}).encode(), b"", 1)
        result = run_peer(self.context, Peer("192.0.2.1", True, seconds=1))
        self.assertEqual(result["directions"]["download"]["received_bits_per_second"], 9)
        self.assertEqual(capture_tool.call_count, 2)
        self.assertNotIn("--reverse", capture_tool.call_args_list[0].args[1])
        self.assertIn("--reverse", capture_tool.call_args_list[1].args[1])
