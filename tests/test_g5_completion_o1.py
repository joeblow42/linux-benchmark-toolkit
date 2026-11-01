import unittest
from lbt_g5.safety import SourceRequest
from lbt_g5.o1 import plan_optional
class O1Refusals(unittest.TestCase):
    def test_missing_consent_denies_all_o1(self):
        run='run-2026305120000'
        for source,op,target in (('SRC-13','DEVICE_HEALTH','/dev/sda'),('SRC-18','OPTICAL_MEDIA','/dev/sr0'),('SRC-21','VAINFO','/dev/dri/renderD128')):
            with self.subTest(source=source),self.assertRaises(PermissionError):
                plan_optional(SourceRequest(run,source,op,target=target))
