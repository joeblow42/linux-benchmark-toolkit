import unittest
from lbt_g5.passive_worker import collect
class Fixture(unittest.TestCase):
    def test_worker_rejects_o1(self):
        with self.assertRaises(ValueError):
            list(collect('SRC-13'))
