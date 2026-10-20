"""Fixture-based tests for read-only system, CPU, and memory collectors."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from discovery.core import CollectionStatus, DiscoveryContext
from discovery.cpu import collect as cpu_collect
from discovery.memory import collect as memory_collect, parse_meminfo
from discovery.readers import read_text
from discovery.system import collect as system_collect


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class HardwareCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc = self.root / "proc"
        self.sys = self.root / "sys"
        self.etc = self.root / "etc"
        self.context = DiscoveryContext()

    def test_cpu_from_fixture(self):
        write(self.proc / "cpuinfo", (
            "processor : 0\nvendor_id : GenuineIntel\nmodel name : Test CPU\n"
            "flags : sse2 avx\n\nprocessor : 1\n\n"
        ))
        write(self.sys / "devices/system/cpu/online", "0-1\n")
        result = cpu_collect(self.context, proc_root=self.proc, sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(result.data["logical_processors_visible"], 2)
        self.assertEqual(result.data["vendor"], "GenuineIntel")
        self.assertEqual(result.data["instruction_sets"], ["avx", "sse2"])
        self.assertEqual(result.data["online_cpu_list"], "0-1")

    def test_cpu_missing_inputs(self):
        result = cpu_collect(self.context, proc_root=self.proc, sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.UNAVAILABLE)

    def test_memory_units_and_swap_privacy(self):
        write(self.proc / "meminfo", "MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
        write(self.proc / "swaps", (
            "Filename Type Size Used Priority\n"
            "/home/private/swapfile file 4096 20 -2\n"
        ))
        write(self.proc / "pressure/memory", "some avg10=0.00 avg60=0.00 total=0\n")
        result = memory_collect(self.context, proc_root=self.proc)
        self.assertEqual(result.data["metrics"]["MemTotal"]["value"], 1048576)
        self.assertEqual(result.data["swap_devices"][0]["capacity_bytes"], 4194304)
        self.assertNotIn("/home/private", str(result.to_dict()))
        self.assertIn("some avg10", result.data["pressure"])

    def test_memory_missing(self):
        result = memory_collect(self.context, proc_root=self.proc)
        self.assertEqual(result.status, CollectionStatus.UNAVAILABLE)

    def test_meminfo_ignores_bad_values(self):
        parsed = parse_meminfo("MemTotal: unknown kB\nMemAvailable: 22 kB\n")
        self.assertNotIn("MemTotal", parsed)
        self.assertEqual(parsed["MemAvailable"]["value"], 22528)

    def test_os_and_firmware(self):
        write(self.etc / "os-release", 'ID=ubuntu\nPRETTY_NAME="Ubuntu Test"\n')
        write(self.sys / "class/dmi/id/bios_vendor", "TestVendor\n")
        (self.sys / "firmware/efi").mkdir(parents=True)
        result = system_collect(self.context, etc_root=self.etc, sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(result.data["pretty_name"], "Ubuntu Test")
        self.assertEqual(result.data["bios_vendor"], "TestVendor")
        self.assertTrue(result.data["efi_boot"])
        self.assertNotIn("serial", str(result.to_dict()).lower())

    def test_system_missing_optional_firmware(self):
        result = system_collect(self.context, etc_root=self.etc, sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertFalse(result.data["efi_boot"])

    def test_read_text_limits(self):
        write(self.root / "data", "123456")
        value, status = read_text(self.root / "data", max_bytes=3)
        self.assertIsNone(value)
        self.assertEqual(status, CollectionStatus.FAILED)

    def test_read_text_missing(self):
        value, status = read_text(self.root / "absent")
        self.assertIsNone(value)
        self.assertEqual(status, CollectionStatus.UNAVAILABLE)


if __name__ == "__main__":
    unittest.main()
