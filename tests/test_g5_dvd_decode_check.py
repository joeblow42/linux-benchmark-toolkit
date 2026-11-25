import unittest

from scripts.rp08_dvd_decode_check import encryption_observation


class DVDDecodeObservationTests(unittest.TestCase):
    def test_classifies_only_reported_encryption(self):
        for log, expected in (
            (b"libdvdcss debug: disc is scrambled", "ENCRYPTED_REPORTED"),
            (b"libdvdcss debug: disc is not scrambled", "UNENCRYPTED_REPORTED"),
            (b"libdvdread: Using libdvdcss version 1.6.0", "UNVERIFIED"),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(encryption_observation(log), expected)
