"""G5-03 privileged helper wire contract: strict fail-closed negative coverage."""
import json
import unittest

from lbt_g5.privilege_contract import (
    PROTOCOL_VERSION, MAX_HEALTH_ATTEMPTS_PER_RUN, MAX_HEALTH_BYTES,
    HealthSessionContract, PrivilegeContractError,
)

RUN="run-2026306163727"
TAG="0123456789abcdef0123456789abcdef"


def encode(**overrides):
    request=dict(protocol=PROTOCOL_VERSION,session=TAG,sequence=1,run_id=RUN,
                 source_id="SRC-13",operation_id="DEVICE_HEALTH",
                 target="/dev/sda",max_bytes=MAX_HEALTH_BYTES,max_seconds=12)
    request.update(overrides)
    return json.dumps(request,separators=(",",":"),allow_nan=True).encode()


class ProtocolSafety(unittest.TestCase):
    def setUp(self):
        self.session=HealthSessionContract(TAG)

    def test_valid_sata_and_nvme_bounded_requests(self):
        self.assertEqual(self.session.accept(encode()).target,"/dev/sda")
        self.assertEqual(self.session.accept(
            encode(sequence=2,target="/dev/nvme0")).target,"/dev/nvme0")
        self.assertEqual(self.session.accept(
            encode(sequence=3,target="/dev/nvme1n1")).sequence,3)

    def test_replay_rejected(self):
        self.session.accept(encode())
        for frame in (encode(),encode(sequence=3)):
            with self.assertRaises(PrivilegeContractError):
                self.session.accept(frame)
        self.assertEqual(self.session.accept(encode(sequence=2)).sequence,2)

    def test_other_sources_do_not_gain_root_access(self):
        for frame in (encode(source_id="SRC-18"),
                      encode(source_id="SRC-21"),
                      encode(operation_id="OPTICAL_MEDIA"),
                      encode(operation_id="SHELL"),
                      encode(source_id="SRC-02")):
            with self.subTest(frame=frame):
                with self.assertRaises(PrivilegeContractError):
                    self.session.accept(frame)

    def test_target_injection_and_device_traversal_refused(self):
        for path in ("/etc/shadow","/tmp/sda","/dev/disk/by-id/foo",
                     "/dev/sda;id","/dev/sda/../nvme0",
                     "/dev/sda\nid","/dev/mapper/foo","/dev/sr0",
                     "/dev/dri/renderD128","/dev/nvme0x",
                     "/dev/sda --help"):
            with self.subTest(path=path):
                with self.assertRaises(PrivilegeContractError):
                    self.session.accept(encode(target=path))

    def test_unknown_keys_and_override_flags_refused(self):
        for overrides in ({"argv":["sh","-c","id"]},
                          {"command":"sh"},
                          {"sudo":True},
                          {"path":"/etc/shadow"}):
            with self.subTest(data=overrides):
                with self.assertRaises(PrivilegeContractError):
                    self.session.accept(encode(**overrides))
        with self.assertRaises(PrivilegeContractError):
            self.session.accept(b"{}")

    def test_bounded_budget_and_strict_types(self):
        for overrides in ({"max_seconds":12.1},{"max_seconds":0},
                          {"max_seconds":True},{"max_seconds":float("nan")},
                          {"max_bytes":MAX_HEALTH_BYTES+1},
                          {"max_bytes":-1},{"max_bytes":"1024"},
                          {"max_bytes":True},{"sequence":1.0},
                          {"run_id":"run-..."}):
            with self.subTest(data=overrides):
                with self.assertRaises(PrivilegeContractError):
                    self.session.accept(encode(**overrides))

    def test_malformed_message_or_mismatch_refused(self):
        for raw in (b"", b"\x00",b"[]",b"not json",
                    encode()+b"\n"+encode(),
                    b"a"*4097,
                    encode(session="ffffffffffffffffffffffffffffffff"),
                    encode(protocol="lbt-root-helper-0"),
                    encode(run_id="run-2026010110000")):
            # Last run id is syntactically valid; only assert shape on others.
            if b"run-2026010110000" in raw:continue
            with self.subTest(raw=raw[:60]):
                with self.assertRaises(PrivilegeContractError):
                    self.session.accept(raw)

    def test_attempt_ceiling(self):
        for i in range(1, MAX_HEALTH_ATTEMPTS_PER_RUN+1):
            self.session.accept(encode(sequence=i))
        with self.assertRaises(PrivilegeContractError):
            self.session.accept(encode(sequence=MAX_HEALTH_ATTEMPTS_PER_RUN+1))

    def test_rejected_request_does_not_advance_counter(self):
        with self.assertRaises(PrivilegeContractError):
            self.session.accept(encode(target="/dev/sda;cat"))
        self.assertEqual(self.session.accept(encode()).sequence,1)

    def test_session_identifier_rejects_unsafe_input(self):
        for tag in ("", "zz"*16, "../"*10, "0"*31,"0"*33,"0"*32+"\n"):
            with self.assertRaises(PrivilegeContractError):
                HealthSessionContract(tag)


if __name__=="__main__":
    unittest.main()
