import unittest
from lbt_g5.passive_worker import collect
from lbt_g5.local_space import eligible_mounts
class CompletionSmoke(unittest.TestCase):
    def test_only_known_sources(self):
        with self.assertRaises(ValueError):
            list(collect('SRC-13'))
    def test_remote_mount_excluded(self):
        self.assertEqual(eligible_mounts('41 25 0:35 / /mnt/net rw - nfs x:y rw'),())

    def test_d0_attempt_ceiling_counts_unavailable_attributes(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            dev=root/"hwmon0"
            dev.mkdir()
            for i in (1,2,3):
                (dev/("temp%d_input"%i)).symlink_to("/never/allowed")
            records=list(collect("SRC-25",roots={"SRC-25":str(root)},
                                 max_bytes=4096,max_entries=2))
            self.assertEqual(sum("error" in x for x in records),2)
            self.assertEqual(records[-1]["attempted"],2)
            self.assertTrue(records[-1]["limited"])

    def test_efi_terminal_marker(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            efi=Path(tmp)/"efi"
            efi.mkdir()
            records=list(collect("SRC-03",roots={"SRC-03":str(efi)}))
            self.assertEqual(records[-1]["entries"],1)
            self.assertTrue(records[-1]["end"])
