"""Fixture-based GPU and VA-API tests without real GPU dependency."""
import tempfile
import unittest
from pathlib import Path

from discovery.core import CollectionStatus, DiscoveryContext
from discovery.gpu import collect as gpu_collect
from discovery.probes import ProbeResult
from discovery.vaapi import collect as vaapi_collect, parse_vainfo


def put(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


class GpuVaapiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sys = Path(self.tmp.name) / "sys"

    def gpu_fixture(self):
        real = self.sys / "devices/pci0000:00/0000:00:02.0"
        put(real / "vendor", "0x8086\n")
        put(real / "device", "0x1234\n")
        put(real / "subsystem_vendor", "0x103c\n")
        put(real / "subsystem_device", "0x0001\n")
        driver = self.sys / "bus/pci/drivers/i915"
        driver.mkdir(parents=True)
        (real / "driver").symlink_to(driver)
        drm = self.sys / "class/drm"
        drm.mkdir(parents=True)
        (drm / "card0").mkdir()
        (drm / "card0/device").symlink_to(real, target_is_directory=True)
        return real

    def test_gpu_intel_inventory(self):
        self.gpu_fixture()
        result = gpu_collect(DiscoveryContext(), sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(len(result.data["devices"]), 1)
        card = result.data["devices"][0]
        self.assertEqual(card["vendor_id"], "0x8086")
        self.assertEqual(card["kernel_driver"], "i915")
        self.assertEqual(card["video_acceleration"], "NOT_TESTED")
        self.assertNotIn("sysfs_device_path", card)

    def test_gpu_explicit_detail_opt_in(self):
        self.gpu_fixture()
        result = gpu_collect(DiscoveryContext(include_identifiers=True), sys_root=self.sys)
        self.assertIn("sysfs_device_path", result.data["devices"][0])

    def test_gpu_missing_device(self):
        (self.sys / "class/drm").mkdir(parents=True)
        self.assertEqual(gpu_collect(DiscoveryContext(), sys_root=self.sys).status,
                         CollectionStatus.UNAVAILABLE)

    def test_gpu_missing_class(self):
        self.assertEqual(gpu_collect(DiscoveryContext(), sys_root=self.sys).status,
                         CollectionStatus.UNAVAILABLE)

    def test_gpu_ignores_connectors(self):
        (self.sys / "class/drm/card0-HDMI-A-1").mkdir(parents=True)
        self.assertEqual(gpu_collect(DiscoveryContext(), sys_root=self.sys).data["devices"], [])

    def test_vaapi_parse_decode_and_encode(self):
        output = (
            "libva info: VA-API version 1.18.0\n"
            "      VAProfileH264Main : VAEntrypointVLD\n"
            "      VAProfileH264Main : VAEntrypointEncSlice\n"
            "      VAProfileHEVCMain : VAEntrypointVLD\n"
            "      VAProfileNone : VAEntrypointVideoProc\n"
        )
        rows = parse_vainfo(output)
        h264 = next(r for r in rows if r["profile"] == "VAProfileH264Main")
        hevc = next(r for r in rows if r["profile"] == "VAProfileHEVCMain")
        self.assertTrue(h264["decode_advertised"])
        self.assertTrue(h264["encode_advertised"])
        self.assertTrue(hevc["decode_advertised"])
        self.assertFalse(hevc["encode_advertised"])

    def test_vaapi_ignores_diagnostic_prose(self):
        self.assertEqual(parse_vainfo("Could not initialize display\nVAProfileFake : garbage"), [])

    def test_vaapi_collect_success(self):
        def probe(command, **kwargs):
            self.assertEqual(command, ["vainfo"])
            return ProbeResult(CollectionStatus.COMPLETE, tuple(command), 0,
                               "VA-API version: 1.18.0\nVAProfileH264Main : VAEntrypointVLD")
        result = vaapi_collect(DiscoveryContext(), probe=probe)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertFalse(result.data["functional_test"])
        self.assertEqual(result.data["va_api_version"], "1.18.0")
        self.assertEqual(len(result.data["profiles"]), 1)

    def test_vaapi_missing_tool(self):
        def probe(cmd, **kwargs):
            return ProbeResult(CollectionStatus.TOOL_MISSING, tuple(cmd),
                               reason="tool not installed")
        result = vaapi_collect(DiscoveryContext(), probe=probe)
        self.assertEqual(result.status, CollectionStatus.TOOL_MISSING)
        self.assertFalse(result.data["functional_test"])

    def test_vaapi_permission_error(self):
        def probe(cmd, **kwargs):
            return ProbeResult(CollectionStatus.PERMISSION_DENIED, tuple(cmd),
                               reason="permission denied")
        result = vaapi_collect(DiscoveryContext(), device="/dev/dri/renderD128",
                               probe=probe)
        self.assertEqual(result.status, CollectionStatus.PERMISSION_DENIED)

    def test_vaapi_reject_invalid_device(self):
        with self.assertRaises(ValueError):
            vaapi_collect(DiscoveryContext(), device="/tmp/unsafe")


if __name__ == "__main__":
    unittest.main()
