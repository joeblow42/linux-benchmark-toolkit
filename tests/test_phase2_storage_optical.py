"""Synthetic Linux sysfs/procfs fixtures for storage and optical discovery."""
import tempfile
import unittest
from pathlib import Path

from discovery.core import CollectionStatus, DiscoveryContext
from discovery.optical import collect as optical_collect
from discovery.storage import collect as storage_collect


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class StorageOpticalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sys = self.root / "sys"
        self.proc = self.root / "proc"
        (self.sys / "class/block").mkdir(parents=True)

    def disk(self, name, sectors=2048, device="8:0", *, model="Example Disk",
             rota="1"):
        root = self.sys / "class/block" / name
        write(root / "size", str(sectors))
        write(root / "dev", device)
        write(root / "queue/logical_block_size", "512")
        write(root / "queue/rotational", rota)
        write(root / "device/model", model)
        return root

    def test_disk_capacity_and_rotational(self):
        self.disk("sda")
        result = storage_collect(DiscoveryContext(), sys_root=self.sys, proc_root=self.proc)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        disk = result.data["devices"][0]
        self.assertEqual(disk["capacity_bytes"], 1048576)
        self.assertTrue(disk["rotational"])
        self.assertEqual(disk["transport"], "unknown")  # sd does not imply SATA
        self.assertEqual(disk["health_status"], "NOT_COLLECTED")

    def test_ssd_and_partition(self):
        self.disk("nvme0n1", rota="0", device="259:0")
        part = self.disk("nvme0n1p1", device="259:1")
        write(part / "partition", "1")
        result = storage_collect(DiscoveryContext(), sys_root=self.sys, proc_root=self.proc)
        self.assertEqual(len(result.data["devices"]), 1)
        self.assertEqual(len(result.data["partitions"]), 1)
        self.assertFalse(result.data["devices"][0]["rotational"])
        self.assertEqual(result.data["devices"][0]["transport"], "nvme")
        self.assertEqual(result.data["partitions"][0]["partition_number"], 1)

    def test_mountpoints_redacted_by_default(self):
        self.disk("sda", device="8:0")
        write(self.proc / "self/mountinfo",
              "42 35 8:0 / /home/private/work rw,relatime - ext4 /dev/sda rw\n")
        result = storage_collect(DiscoveryContext(), sys_root=self.sys, proc_root=self.proc)
        self.assertEqual(result.data["devices"][0]["mounts"][0]["mountpoint"], "[REDACTED]")
        self.assertNotIn("private", str(result.to_dict()))

    def test_mountpoints_with_explicit_opt_in(self):
        self.disk("sda", device="8:0")
        write(self.proc / "self/mountinfo",
              "42 35 8:0 / /mnt/backups rw,relatime - ext4 /dev/sda rw\n")
        result = storage_collect(
            DiscoveryContext(include_identifiers=True),
            sys_root=self.sys, proc_root=self.proc)
        self.assertEqual(result.data["devices"][0]["mounts"][0]["mountpoint"],
                         "/mnt/backups")

    def test_virtual_block_device(self):
        self.disk("loop0")
        result = storage_collect(DiscoveryContext(), sys_root=self.sys, proc_root=self.proc)
        self.assertTrue(result.data["devices"][0]["virtual"])

    def test_no_devices_is_valid_inventory(self):
        result = storage_collect(DiscoveryContext(), sys_root=self.sys, proc_root=self.proc)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(result.data["devices"], [])

    def test_missing_sysfs_storage(self):
        result = storage_collect(DiscoveryContext(), sys_root=self.root / "absent",
                                 proc_root=self.proc)
        self.assertEqual(result.status, CollectionStatus.UNAVAILABLE)

    def test_no_optical_drives(self):
        self.disk("sda")
        result = optical_collect(DiscoveryContext(), sys_root=self.sys, proc_root=self.proc)
        self.assertEqual(result.status, CollectionStatus.UNAVAILABLE)
        self.assertEqual(result.data["drives"], [])

    def test_optical_drive_with_capabilities(self):
        drive = self.disk("sr0", device="11:0", model="DVD-ROM")
        write(drive / "device/type", "5")
        write(self.proc / "sys/dev/cdrom/info",
              "drive name:\t\tsr0\nCan read CD:\t\t1\nCan read DVD:\t\t1\n"
              "Can write DVD-R:\t\t0\n")
        result = optical_collect(DiscoveryContext(), sys_root=self.sys, proc_root=self.proc)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        item = result.data["drives"][0]
        self.assertTrue(item["capabilities"]["can_read_dvd"])
        self.assertFalse(item["capabilities"]["can_write_dvd-r"])
        self.assertIsNone(item["media_present"])

    def test_optical_drive_without_cdrom_info(self):
        drive = self.disk("sr0")
        write(drive / "device/type", "5")
        result = optical_collect(DiscoveryContext(), sys_root=self.sys, proc_root=self.proc)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(result.data["drives"][0]["capabilities"], {})

    def test_missing_sysfs_optical(self):
        result = optical_collect(DiscoveryContext(), sys_root=self.root / "absent",
                                 proc_root=self.proc)
        self.assertEqual(result.status, CollectionStatus.UNAVAILABLE)


if __name__ == "__main__":
    unittest.main()
