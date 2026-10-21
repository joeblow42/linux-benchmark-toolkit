"""Fixture-based tests for network, thermal and power discovery."""
import tempfile
import unittest
from pathlib import Path

from discovery.core import CollectionStatus, DiscoveryContext
from discovery.network import collect as network_collect
from discovery.thermal import collect as thermal_collect
from discovery.power import collect as power_collect


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)


class NetworkThermalPowerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sys = Path(self.temp.name) / "sys"

    def test_network_basic(self):
        iface = self.sys / "class/net/eth0"
        write(iface / "type", "1\n")
        write(iface / "operstate", "up\n")
        write(iface / "carrier", "1\n")
        write(iface / "speed", "1000\n")
        write(iface / "duplex", "full\n")
        write(iface / "mtu", "1500\n")
        write(iface / "address", "02:00:00:00:00:01\n")
        result = network_collect(DiscoveryContext(), sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        record = result.data["interfaces"][0]
        self.assertEqual(record["speed"], 1000)
        self.assertEqual(record["mtu"], 1500)
        self.assertEqual(record["operstate"], "up")
        self.assertNotIn("mac_address", record)
        self.assertNotIn("02:00:00:00:00:01", str(result.to_dict()))

    def test_network_detailed_identifiers(self):
        write(self.sys / "class/net/eth0/address", "02:00:00:00:00:01")
        record = network_collect(
            DiscoveryContext(include_identifiers=True), sys_root=self.sys,
        ).data["interfaces"][0]
        self.assertEqual(record["mac_address"], "02:00:00:00:00:01")

    def test_network_missing_sysfs(self):
        result = network_collect(DiscoveryContext(), sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.UNAVAILABLE)

    def test_network_empty_is_complete(self):
        (self.sys / "class/net").mkdir(parents=True)
        result = network_collect(DiscoveryContext(), sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(result.data["interfaces"], [])

    def test_network_unknown_speed(self):
        write(self.sys / "class/net/wlan0/speed", "-1")
        record = network_collect(DiscoveryContext(), sys_root=self.sys).data["interfaces"][0]
        self.assertIsNone(record["speed"])

    def test_thermal_zones(self):
        write(self.sys / "class/thermal/thermal_zone0/type", "x86_pkg_temp")
        write(self.sys / "class/thermal/thermal_zone0/temp", "42123")
        result = thermal_collect(DiscoveryContext(), sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(result.data["sensors"][0]["temperature_millidegrees_c"], 42123)

    def test_thermal_hwmon(self):
        write(self.sys / "class/hwmon/hwmon0/name", "coretemp")
        write(self.sys / "class/hwmon/hwmon0/temp1_input", "36000")
        write(self.sys / "class/hwmon/hwmon0/fan1_input", "1800")
        result = thermal_collect(DiscoveryContext(), sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        rows = result.data["sensors"]
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["unit"] for r in rows}, {"millidegrees_c", "rpm"})

    def test_thermal_missing(self):
        self.assertEqual(thermal_collect(DiscoveryContext(), sys_root=self.sys).status,
                         CollectionStatus.UNAVAILABLE)

    def test_thermal_malformed_reading(self):
        write(self.sys / "class/thermal/thermal_zone0/temp", "invalid")
        record = thermal_collect(DiscoveryContext(), sys_root=self.sys).data["sensors"][0]
        self.assertEqual(record["reading_status"], "FAILED")
        self.assertIsNone(record["temperature_millidegrees_c"])

    def test_power_battery(self):
        base = self.sys / "class/power_supply/BAT0"
        write(base / "type", "Battery")
        write(base / "status", "Discharging")
        write(base / "capacity", "73")
        write(base / "energy_now", "30000000")
        write(base / "serial_number", "PRIVATE-SERIAL")
        result = power_collect(DiscoveryContext(), sys_root=self.sys)
        record = result.data["supplies"][0]
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(record["metrics"]["capacity"], {"value": 73, "unit": "percent"})
        self.assertNotIn("PRIVATE-SERIAL", str(result.to_dict()))

    def test_power_explicit_detail(self):
        write(self.sys / "class/power_supply/BAT0/serial_number", "SERIAL")
        record = power_collect(DiscoveryContext(include_identifiers=True),
                               sys_root=self.sys).data["supplies"][0]
        self.assertEqual(record["serial_number"], "SERIAL")

    def test_power_missing_and_empty(self):
        self.assertEqual(power_collect(DiscoveryContext(), sys_root=self.sys).status,
                         CollectionStatus.UNAVAILABLE)
        (self.sys / "class/power_supply").mkdir(parents=True)
        result = power_collect(DiscoveryContext(), sys_root=self.sys)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(result.data["supplies"], [])


if __name__ == "__main__":
    unittest.main()
