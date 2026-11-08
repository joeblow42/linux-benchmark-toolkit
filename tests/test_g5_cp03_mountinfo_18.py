"""CP03-18: source-first SRC-14 /proc/self/mountinfo positive and adversarial fixtures.

Oracle: verification/g5_04/cp03_mountinfo_oracle_18.json, committed
before parser edits. No live proc reads, subprocesses, privileged operations
or external network calls. No independence from implementation agent claimed.
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
from lbt_g5.normalization import SourceParseError, normalize_sealed_source, parser_available
from lbt_g5.passive_worker import ROOTS, STATIC_FILES
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
PATH = "/proc/self/mountinfo"
RAW = (
    b"36 35 0:30 / /proc rw,nosuid,nodev,noexec,relatime shared:4 - proc proc rw\n"
    b"37 36 8:1 /var\040lib /mnt/my\040drive rw,relatime shared:7 master:2 future_tag:3 - ext4 /dev/sda1 rw,errors=remount-ro\n"
)
# Byte constants must contain *literal* backslash-octal source notation.
RAW = RAW.replace(b"/var lib",b"/var\\040lib").replace(b"/mnt/my drive",b"/mnt/my\\040drive")
ROOT_OUTSIDE = b"51 999 0:99 / / rw - tmpfs none rw\n"
STACKED = (b"52 51 0:98 / /mount rw - tmpfs none rw\n"
           b"53 52 0:97 / /mount ro - proc proc ro\n")


class MountinfoOracles(unittest.TestCase):
    def parse(self, raw=RAW):
        return normalize_sealed_source("SRC-14",raw,source_path=PATH)

    @contextmanager
    def original(self, raw=RAW, *, paths=None, names=None, outcome="CAPTURED",
                 reason="BYTES_PRESERVED", tamper_run=False, tamper_bytes=False,
                 target=None, invocation="MOUNTINFO", unavailable=(),
                 capture_limited=False):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/RUN
            folder.mkdir(mode=0o700)
            policy={p.source_id:p for p in initial_source_policies()}["SRC-14"]
            writer=EvidenceWriter(str(folder),RUN)
            if names is None:
                names=("item0001",)
            evid=[]
            for name in names:
                item=writer.seal_chunks(policy,"01",name,(raw,)).receipt
                self.assertIsNotNone(item)
                evid.append(item)
            att=build_attempt(
                RUN,"SRC-14","01","ALLOW",outcome,reason,
                evidence=tuple(evid),bytes_count=sum(v.byte_count for v in evid),
                source_paths=(PATH,) if paths is None else tuple(paths),
                target=target,invocation=invocation,
                unavailable_fields=tuple(unavailable),
                capture_limited=capture_limited)
            receipt_path=commit_attempt(str(folder),att)
            if tamper_run:
                evid[0]=replace(evid[0],run_id="run-2026305120001")
            if tamper_bytes:
                (folder/evid[0].private_relative_path).write_bytes(b"forged\n")
            rec=SimpleNamespace(
                receipt_private_path=receipt_path,
                outcome=SimpleNamespace(artifacts=tuple(evid)))
            yield folder,EngineRun(RUN,(CollectorRun("COL-FS",(rec,)),)),tuple(evid)

    def test_source_is_exact_registered_one_file(self):
        self.assertEqual(ROOTS["SRC-14"], PATH)
        self.assertIn("SRC-14",STATIC_FILES)
        policy={p.source_id:p for p in initial_source_policies()}["SRC-14"]
        self.assertEqual((policy.authorization_class,policy.operation_id,policy.fixed_file),
                         ("D0","MOUNTINFO",PATH))
        self.assertEqual(policy.max_entries,1)
        self.assertTrue(parser_available("SRC-14"))
        self.assertFalse(parser_available("SRC-28"))

    def test_positive_field_order_escapes_and_unknown_optional_tags(self):
        result=self.parse()
        self.assertEqual(result.parser_id,"linux-mountinfo-proc-bounded-v1")
        self.assertEqual(len(result.values),1)
        datum=result.values[0]
        self.assertEqual((datum.datum_path,datum.value_type),
                         ("storage.mountinfo.records","ARRAY"))
        self.assertEqual(len(datum.normalized_value),2)
        a,b=datum.normalized_value
        self.assertEqual((a["mount_id"],a["parent_id"],a["major"],a["minor"]),
                         (36,35,0,30))
        self.assertEqual((a["root"],a["mount_point"],a["filesystem_type"],
                          a["mount_source"]),("/","/proc","proc","proc"))
        self.assertEqual(a["mount_options"],"rw,nosuid,nodev,noexec,relatime")
        self.assertEqual(a["super_options"],"rw")
        self.assertEqual(b["root"],"/var lib")
        self.assertEqual(b["mount_point"],"/mnt/my drive")
        self.assertEqual(b["mount_source"],"/dev/sda1")
        self.assertEqual(b["optional_fields"],["shared:7","master:2","future_tag:3"])
        self.assertEqual(b["super_options"],"rw,errors=remount-ro")
        self.assertFalse(any("health" in name for name in b))

    def test_escaped_tab_newline_backslash_and_mount_source(self):
        raw=(b"1 1 8:2 /mnt\\011tab\\012line\\134slash "
             b"/mount\\040space rw - ext4 /dev/by\\040id rw\n")
        parsed=self.parse(raw).values[0].normalized_value[0]
        self.assertEqual(parsed["root"],"/mnt\ttab\nline\\slash")
        self.assertEqual(parsed["mount_point"],"/mount space")
        self.assertEqual(parsed["mount_source"],"/dev/by id")

    def test_external_parent_and_duplicate_mountpoints_are_valid(self):
        rows=self.parse(ROOT_OUTSIDE+STACKED).values[0].normalized_value
        self.assertEqual([x["parent_id"] for x in rows],[999,51,52])
        self.assertEqual([x["mount_point"] for x in rows],
                         ["/","/mount","/mount"])
        self.assertEqual(rows[2]["mount_options"],"ro")
        # Do not manufacture mount hierarchy validity from a missing parent.

    def test_direct_parser_requires_registered_attribution(self):
        for kw in (
            {},
            {"source_path":"/proc/1/mountinfo"},
            {"source_path":"../proc/self/mountinfo"},
            {"source_path":PATH,"source_stream":"stdout"},
            {"source_path":PATH,"source_command":"cat"},
            {"source_path":PATH,"source_target":"/dev/sda"},
        ):
            with self.subTest(kw=kw),self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-14",RAW,**kw)

    def test_malformed_separator_fields_numbers_and_root_rejected(self):
        bad=(
            b"36 35 0:30 / / rw proc proc rw\n",            # missing separator
            b"36 35 0:30 / / rw - ext4 /dev/sda1\n",       # missing super options
            b"36 35 0:30 / / rw - ext4 /dev/sda1 rw extra\n",
            b"36 35 0:30 / / rw - ext4 /dev/sda1 rw - tail\n",
            b"0 0 0:30 / / rw - ext4 none rw\n",
            b"-2 1 0:30 / / rw - ext4 none rw\n",
            b"1 -2 0:30 / / rw - ext4 none rw\n",
            b"1 0 0::30 / / rw - ext4 none rw\n",
            b"1 0 a:30 / / rw - ext4 none rw\n",
            b"1 0 0:4294967296 / / rw - ext4 none rw\n",
            b"1 0 0:30 relative / rw - ext4 none rw\n",
            b"1 0 0:30 / relative rw - ext4 none rw\n",
            b"1 0 0:30 / / rw,,noexec - ext4 none rw\n",
            b"1 0 0:30 / / rw foo: - ext4 none rw\n",
            b"1 0 0:30 / / rw - ext4 none rw\n"
            b"1 0 0:31 / /mnt rw - proc proc rw\n",
            b"1 0 0:30 / / rw - ext4 none rw",          # missing newline
            b"",
        )
        for payload in bad:
            with self.subTest(raw=payload[:65]),self.assertRaises(SourceParseError):
                self.parse(payload)

    def test_malformed_escapes_utf8_and_controls_rejected(self):
        for raw in (
            b"1 1 0:1 /\\123 / rw - ext4 none rw\n",
            b"1 1 0:1 /\\999 / rw - ext4 none rw\n",
            b"1 1 0:1 /\\400 / rw - ext4 none rw\n",
            b"1 1 0:1 /\\ / rw - ext4 none rw\n",
            b"1 1 0:1 / /rw\\123bad rw - ext4 none rw\n",
            b"1 1 0:1 / / rw - ext4 /\\012evil rw\n", # decoded NL in source is allowed
            b"1 1 0:1 / / rw - ext4 none rw\x00\n",
            b"1 1 0:1 / / rw - ext4 none rw\r\n",
            b"1 1 0:1 / /\trw - ext4 none rw\n",
            b"1 1 0:1 / / rw - ext4 \xff rw\n",
        ):
            # Kernel-supported escape \\012 for mount_source is *valid*.
            if b"/\\012evil" in raw:
                got=self.parse(raw).values[0].normalized_value[0]
                self.assertEqual(got["mount_source"],"/\nevil")
                continue
            with self.subTest(raw=raw[:60]),self.assertRaises(SourceParseError):
                self.parse(raw)

    def test_bounded_record_and_input_sizes_rejected(self):
        many=b"".join(
            (f"{i} 1 0:1 / /m{i} rw - tmpfs none rw\n").encode()
            for i in range(1,4099))
        for raw in (
            many,
            b"1 1 0:1 / / rw - ext4 none "+b"a"*5000+b"\n",
            b"1 1 0:1 / / rw - ext4 none rw\n"*(1024*1024//33+20),
        ):
            with self.subTest(size=len(raw)),self.assertRaises(SourceParseError):
                self.parse(raw)

    def test_canonical_original_hash_and_single_semantic_reference(self):
        with self.original() as (folder,run,evidence):
            manifest=build_canonical(folder,run)
            self.assertEqual(manifest["observation_count"],2)
            self.assertEqual(validate_canonical(folder),manifest)
            obs=json.loads((folder/"private/system.json").read_text())["observations"]
            semantic=[x for x in obs if x["transformation_ids"]]
            self.assertEqual(len(semantic),1)
            self.assertEqual(semantic[0]["evidence_refs"],[evidence[0].evidence_id])
            self.assertEqual(semantic[0]["source_attempt_ids"],["SRC-14-01"])
            self.assertEqual(len(semantic[0]["normalized_value"]),2)
            self.assertEqual((folder/evidence[0].private_relative_path).read_bytes(),RAW)
            self.assertEqual(evidence[0].sha256,hashlib.sha256(RAW).hexdigest())
            status=json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual((status["status_records"][0]["status"],
                              status["status_records"][0]["reason_code"]),
                             ("COMPLETE","OK"))

    def test_canonical_parser_failure_preserves_raw_no_semantics(self):
        with self.original(b"malformed mountinfo\n") as (folder,run,evidence):
            manifest=build_canonical(folder,run)
            self.assertEqual(validate_canonical(folder),manifest)
            obs=json.loads((folder/"private/system.json").read_text())["observations"]
            self.assertEqual(len(obs),1)
            self.assertEqual(obs[0]["evidence_refs"],[evidence[0].evidence_id])
            self.assertEqual(obs[0]["normalized_value"],None)
            status=json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual((status["status_records"][0]["status"],
                              status["status_records"][0]["reason_code"]),
                             ("PARTIAL","PARSE_FAILED"))

    def test_canonical_provenance_path_and_ordinal_attack_fail_closed(self):
        cases=(
            {"paths":()},
            {"paths":("/proc/1/mountinfo",)},
            {"paths":(PATH,PATH)},
            {"names":("item0002",)},
            {"names":("item0001","item0002")},
            {"invocation":"cat /proc/self/mountinfo"},
            {"target":"/dev/sda"},
            {"unavailable":("Unexpected:missing",)},
            {"tamper_run":True},
            {"tamper_bytes":True},
        )
        for case in cases:
            with self.subTest(case=case):
                with self.original(**case) as (folder,run,_):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder,run)
                    self.assertFalse((folder/"private/session_manifest.json").exists())

    def test_partial_capture_never_complete_even_with_valid_prefix(self):
        with self.original(RAW, outcome="PARTIAL", reason="CAPTURE_LIMIT",
                           capture_limited=True) as (folder,run,_):
            manifest=build_canonical(folder,run)
            self.assertEqual(validate_canonical(folder),manifest)
            status=json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual((status["status_records"][0]["status"],
                              status["status_records"][0]["reason_code"]),
                             ("PARTIAL","CAPTURE_LIMIT"))


if __name__=="__main__":
    unittest.main()
