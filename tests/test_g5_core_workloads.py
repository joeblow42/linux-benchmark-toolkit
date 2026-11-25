"""RP-07 short workload regression and bounded functional checks."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lbt_g5.core_workloads import MIB, ShortParameters, run_cpu, run_memory, run_storage
from lbt_g5.workload_runtime import Context, Unavailable


class CoreWorkloadsTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.context = Context(Path(scratch.name), lambda: None, {})
        self.parameters = ShortParameters(cpu_seconds=0.05, cpu_workers=2,
                                          memory_bytes=MIB, memory_seconds=0.05,
                                          storage_bytes=MIB, random_operations=8)

    @patch("lbt_g5.core_workloads.pressure", return_value={"avg10_percent": 0.0, "total_us": 100})
    def test_cpu_and_memory_return_observed_units(self, _):
        cpu = run_cpu(self.context, self.parameters)
        self.assertGreater(cpu["single"]["operations"], 0)
        self.assertLessEqual(cpu["parallel"]["workers"], 2)
        self.assertGreater(cpu["scaling_ratio"], 0)
        with patch("lbt_g5.core_workloads._fields", return_value=iter([("MemAvailable", "262144")])):
            memory = run_memory(self.context, self.parameters)
        self.assertGreater(memory["mib_per_second"], 0)
        self.assertEqual(memory["working_set_bytes"], 2 * MIB)

    @patch("lbt_g5.core_workloads.pressure", return_value={"avg10_percent": 0.0, "total_us": 100})
    @patch("lbt_g5.core_workloads.local_filesystem", return_value="fixture")
    def test_storage_uses_bounded_isolated_file(self, *_):
        result = run_storage(self.context, self.parameters)
        self.assertEqual(result["sequential_write"]["bytes"], MIB)
        self.assertEqual(result["sequential_read"]["bytes"], MIB)
        self.assertEqual(result["random_read"]["operations"], 8)
        self.assertEqual(result["random_write"]["operations"], 8)
        self.assertEqual(result["random_block_bytes"], 4096)
        self.assertEqual((self.context.scratch / "bench-data").stat().st_size, MIB)
        with self.assertRaises(FileExistsError):
            run_storage(self.context, self.parameters)

    @patch("lbt_g5.core_workloads.pressure", return_value={"avg10_percent": 40, "total_us": 10})
    @patch("lbt_g5.core_workloads.local_filesystem", return_value="fixture")
    def test_pressure_skips_before_writing(self, *_):
        with self.assertRaisesRegex(Unavailable, "PREEXISTING_IO_PRESSURE"):
            run_storage(self.context, self.parameters)
        self.assertEqual(list(self.context.scratch.iterdir()), [])

    def test_rejects_out_of_range_parameters(self):
        for args in ({"cpu_workers": 0}, {"storage_bytes": 4097}, {"memory_seconds": float("nan")}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                ShortParameters(**args)
