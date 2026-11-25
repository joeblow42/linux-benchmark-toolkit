import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lbt_g5.optical_workload import DVD, SECTOR, image_disc, run_dvd
from lbt_g5.workload_runtime import Context, Unavailable


class OpticalWorkloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = b"synthetic optical fixture".ljust(64 * SECTOR, b"\0")
        source = self.root / "source.iso"
        source.write_bytes(self.data)
        self.fd = os.open(source, os.O_RDONLY)
        self.addCleanup(os.close, self.fd)
        self.image = self.root / "image.partial"
        self.map = self.root / "read-events.jsonl"

    def test_images_and_independently_verifies_all_bytes(self):
        result = image_disc(self.fd, len(self.data), self.image, self.map, 1)
        self.assertTrue(result["verified"])
        self.assertEqual(result["image_sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(self.image.read_bytes(), self.data)
        self.assertEqual(self.map.read_bytes(), b"")
        with self.assertRaises(FileExistsError):
            image_disc(self.fd, len(self.data), self.image, self.map, 1)

    @patch("lbt_g5.optical_workload.os.pread", side_effect=OSError(errno.EIO, "fixture read error"))
    def test_retry_limit_and_unreadable_range(self, read):
        result = image_disc(self.fd, len(self.data), self.image, self.map, 1)
        self.assertFalse(result["verified"])
        self.assertEqual(result["copied_bytes"], 0)
        self.assertEqual(read.call_count, 2)
        events = [json.loads(row) for row in self.map.read_text().splitlines()]
        self.assertEqual([(row["offset"], row["will_retry"]) for row in events],
                         [(0, True), (0, False)])

    def test_refuses_unapproved_device_and_capacity(self):
        for arguments in (("/dev/sda", len(self.data), True),
                          ("/dev/sr0", len(self.data), False),
                          ("/dev/sr0", len(self.data) - 1, True)):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                DVD(*arguments)

    @patch("lbt_g5.optical_workload.os.access", return_value=False)
    @patch("lbt_g5.optical_workload.capture")
    def test_unreadable_device_does_not_start_worker(self, execute, _):
        with self.assertRaisesRegex(Unavailable, "OPTICAL_DEVICE_NOT_READABLE"):
            run_dvd(Context(self.root, lambda: None, {}, self.root / "evidence"),
                    DVD("/dev/sr0", len(self.data), True))
        execute.assert_not_called()
