import unittest
from lbt_g5.passive_worker import collect
from lbt_g5.local_space import eligible_mounts
class CompletionSmoke(unittest.TestCase):
    def test_only_known_sources(self):
        with self.assertRaises(ValueError):
            list(collect('SRC-13'))
    def test_remote_mount_excluded(self):
        self.assertEqual(eligible_mounts('41 25 0:35 / /mnt/net rw - nfs x:y rw'),())
