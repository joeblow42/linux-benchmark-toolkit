"""CP03-09 SRC-22 source-first net sysfs provenance and link-state tests.

Expected outcomes are pinned before implementation in cp03_net_sysfs_oracle_09.
No packets, interface writes, host credentials or actual sysfs reads in tests.
"""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.normalization import SourceParseError, net_sysfs_path_identity, normalize_sealed_source, parser_available
from lbt_g5.passive_worker import ROOTS, ATTRS
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
ROOT = "/sys/class/net/"
ATTRS22 = ("address", "operstate", "carrier", "mtu", "speed", "type", "duplex", "ifindex")


class NetSysfsSourceOracles(unittest.TestCase):
    @contextmanager
    def captured(self, raws, paths, *, names=None, unavailable=(),
                 other_run=False, outcome="CAPTURED", reason="BYTES_PRESERVED"):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / RUN
            folder.mkdir(mode=0o700)
            writer = EvidenceWriter(str(folder), RUN)
            policy = {p.source_id:p for p in initial_source_policies()}["SRC-22"]
            if names is None:
                names = [f"item{i:04d}" for i in range(1, len(raws) + 1)]
            self.assertEqual(len(names), len(raws))
            artifacts = []
            for name, raw in zip(names, raws):
                receipt = writer.seal_chunks(policy, "01", name, (raw,)).receipt
                self.assertIsNotNone(receipt)
                artifacts.append(receipt)
            attempt = build_attempt(
                RUN, "SRC-22", "01", "ALLOW", outcome, reason,
                evidence=tuple(artifacts),
                bytes_count=sum(a.byte_count for a in artifacts),
                source_paths=tuple(paths), unavailable_fields=tuple(unavailable))
            location = commit_attempt(str(folder), attempt)
            if other_run:
                artifacts[0] = replace(artifacts[0], run_id="run-2026305120001")
            rec = SimpleNamespace(
                receipt_private_path=location,
                outcome=SimpleNamespace(artifacts=tuple(artifacts)))
            engine = EngineRun(RUN, (CollectorRun("COL-NET", (rec,)),))
            yield folder, engine, tuple(artifacts)

    def test_worker_source_contract_and_parser_registration(self):
        self.assertEqual(ROOTS["SRC-22"], ROOT.rstrip("/"))
        self.assertEqual(ATTRS["SRC-22"], ATTRS22)
        self.assertTrue(parser_available("SRC-22"))
        self.assertFalse(parser_available("SRC-13"))

    def test_private_link_observations_cite_precise_unmodified_originals(self):
        paths = (
            ROOT + "eth0/address", ROOT + "eth0/operstate",
            ROOT + "eth0/carrier", ROOT + "eth0/mtu",
            ROOT + "eth0/speed", ROOT + "eth0/type",
            ROOT + "eth0/duplex", ROOT + "eth0/ifindex",
        )
        raws = (b"02:11:22:33:44:55\n", b"up\n", b"1\n", b"1500\n",
                b"1000\n", b"1\n", b"full\n", b"2\n")
        with self.captured(raws, paths) as (folder, engine, artifacts):
            manifest = build_canonical(folder, engine)
            self.assertEqual(manifest["observation_count"], 16)
            self.assertEqual(validate_canonical(folder), manifest)
            data = json.loads((folder / "private/system.json").read_text())
            sem = [x for x in data["observations"] if x["transformation_ids"]]
            self.assertEqual(len(sem), 8)
            self.assertEqual([x["datum_path"] for x in sem],
                             ["network.link.eth0." + attr for attr in ATTRS22])
            self.assertEqual([x["normalized_value"] for x in sem],
                             ["02:11:22:33:44:55", "up", True, 1500,
                              1000, 1, "full", 2])
            self.assertEqual(sem[3]["unit"], "bytes")
            self.assertEqual(sem[4]["unit"], "Mb/s")
            for datum, artifact, raw in zip(sem, artifacts, raws):
                self.assertEqual(datum["evidence_refs"], [artifact.evidence_id])
                self.assertEqual(datum["source_attempt_ids"], ["SRC-22-01"])
                self.assertEqual((folder / artifact.private_relative_path).read_bytes(), raw)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), artifact.sha256)

    def test_unknown_speed_sentinel_is_not_negative_measured_throughput(self):
        got = normalize_sealed_source(
            "SRC-22", b"-1\n", source_path=ROOT + "wlan0/speed").values[0]
        self.assertEqual(got.normalized_value, {"known": False, "reported_code": -1})
        self.assertEqual(got.value_type, "OBJECT")
        self.assertIsNone(got.unit)
        future = normalize_sealed_source(
            "SRC-22", b"novel-state\n",
            source_path=ROOT + "wlan0/operstate").values[0]
        self.assertEqual(future.normalized_value, "novel-state")
        # No assumption that an address is Ethernet or a MAC/EUI-48 identity.
        addr = normalize_sealed_source(
            "SRC-22", b"non-Ethernet-link-identifier\n",
            source_path=ROOT + "ib0/address").values[0]
        self.assertEqual(addr.value_type, "STRING")
        self.assertEqual(addr.normalized_value, "non-Ethernet-link-identifier")

    def test_lexical_interface_order_and_optional_field_unavailability(self):
        paths = (ROOT + "eth10/address", ROOT + "eth2/address")
        with self.captured(
            (b"f1\n", b"f2\n"), paths,
            unavailable=("OSError[22]:" + ROOT + "eth2/speed",)
        ) as (folder, engine, originals):
            build_canonical(folder, engine)
            sem = [x for x in json.loads((folder / "private/system.json").read_text())["observations"]
                   if x["transformation_ids"]]
            self.assertEqual([x["datum_path"] for x in sem],
                             ["network.link.eth10.address", "network.link.eth2.address"])
            attempts = json.loads((folder / "private/source_attempts.json").read_text())
            self.assertEqual(len(attempts["attempts"][0]["unavailable_fields"]), 1)

    def test_absent_source_produces_no_interface_observations(self):
        with self.captured((), (), outcome="UNAVAILABLE", reason="SOURCE_ABSENT"
        ) as (folder, engine, originals):
            manifest = build_canonical(folder, engine)
            self.assertEqual(manifest["observation_count"], 0)
            self.assertEqual(validate_canonical(folder), manifest)

    def test_mismatched_order_duplicates_count_and_item_slot_rejected(self):
        fixtures = (
            ((b"1\n",), (), None),
            ((b"1\n",), (ROOT + "eth0/address", ROOT + "eth0/operstate"), None),
            ((b"1\n", b"2\n"), (ROOT + "eth0/mtu", ROOT + "eth0/carrier"), None),
            ((b"1\n", b"2\n"), (ROOT + "eth0/address", ROOT + "eth0/address"), None),
            ((b"1\n", b"2\n"), (ROOT + "eth2/ifindex", ROOT + "eth10/ifindex"), None),
            ((b"1\n",), (ROOT + "eth0/ifindex",), ("item0002",)),
        )
        for raws, paths, names in fixtures:
            with self.subTest(paths=paths, names=names):
                with self.captured(raws, paths, names=names) as (folder, engine, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, engine)
                    self.assertFalse((folder / "private/session_manifest.json").exists())

    def test_no_unapproved_path_or_credential_source(self):
        for path in ("/etc/NetworkManager/system-connections/secret",
                     ROOT + "eth0/wireless", ROOT + "eth0/statistics/rx_bytes",
                     ROOT + ".hidden/address", ROOT + "../eth0/address",
                     ROOT + "eth0/../address", ROOT + "eth0//address",
                     ROOT + "eth0/address\x00", "/proc/net/dev"):
            with self.subTest(path=path):
                self.assertIsNone(net_sysfs_path_identity(path))
                with self.assertRaises(SourceParseError):
                    normalize_sealed_source("SRC-22", b"up\n", source_path=path)
                with self.captured((b"up\n",), (path,)) as (folder, engine, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, engine)

    def test_invalid_values_actual_parse_failure_preserves_original(self):
        for raw, attr in ((b"2\n", "carrier"), (b"-1\n", "mtu"),
                          (b"0\n", "mtu"), (b"0\n", "ifindex"),
                          (b"-2\n", "speed"), (b"\xff\n", "address"),
                          (b"a\nb\n", "operstate"), (b"a\x00b", "duplex")):
            with self.subTest(raw=raw[:8], attr=attr), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-22", raw,
                      source_path=ROOT + "eth0/" + attr)
        with self.captured((b"\xff\n",), (ROOT + "eth0/address",)
        ) as (folder, engine, originals):
            manifest = build_canonical(folder, engine)
            self.assertEqual(manifest["observation_count"], 1)
            status = json.loads((folder / "private/status_records.json").read_text())
            self.assertEqual(status["status_records"][0]["reason_code"], "PARSE_FAILED")
            self.assertEqual((folder / originals[0].private_relative_path).read_bytes(),
                             b"\xff\n")
            self.assertEqual(validate_canonical(folder), manifest)

    def test_cross_run_evidence_forgery_fails_closed(self):
        with self.captured((b"1500\n",), (ROOT + "eth0/mtu",), other_run=True
        ) as (folder, engine, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder, engine)


if __name__ == "__main__":
    unittest.main()
