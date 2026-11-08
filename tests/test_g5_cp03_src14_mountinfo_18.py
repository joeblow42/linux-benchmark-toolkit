"""CP-03 Increment 18: independent-from-parser source-first mountinfo fixtures.

Contract frozen in verification/g5_04/cp03_src14_mountinfo_oracle_18.json
BEFORE parser implementation. No live host read or mount operation in tests.
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
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
PATH = "/proc/self/mountinfo"
RAW = (b"36 22 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro\n"
       b"37 36 0:43 /folder\\040with\\040spaces /mnt/Media\\040Library ro,nosuid "
       b"master:10 future:value - fuse.sshfs server\\134share ro,user_id=1000\n")


class MountinfoSourceFirstOracles(unittest.TestCase):
    @contextmanager
    def originals(self, payload=RAW, *, paths=(PATH,), names=("item0001",),
                  outcome="CAPTURED", reason="BYTES_PRESERVED", wrong_run=False):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/RUN
            folder.mkdir(mode=0o700)
            policy={p.source_id:p for p in initial_source_policies()}["SRC-14"]
            self.assertEqual(policy.fixed_file,PATH)
            writer=EvidenceWriter(str(folder),RUN)
            items=[]
            for name in names:
                receipt=writer.seal_chunks(policy,"01",name,(payload,)).receipt
                self.assertIsNotNone(receipt)
                items.append(receipt)
            rec=build_attempt(RUN,"SRC-14","01","ALLOW",outcome,reason,
                              evidence=tuple(items),
                              bytes_count=sum(x.byte_count for x in items),
                              source_paths=paths)
            path=commit_attempt(str(folder),rec)
            if wrong_run:
                items[0]=replace(items[0],run_id="run-2026305120001")
            item=SimpleNamespace(
                receipt_private_path=path,
                outcome=SimpleNamespace(artifacts=tuple(items)))
            yield folder,EngineRun(RUN,(CollectorRun("COL-FS",(item,)),)),tuple(items)

    def parsed(self, raw=RAW):
        return normalize_sealed_source("SRC-14",raw)

    def test_exact_registered_d0_source_and_opaque_options(self):
        self.assertTrue(parser_available("SRC-14"))
        result=self.parsed()
        self.assertEqual(result.parser_id,"linux-mountinfo-sealed-v1")
        self.assertEqual(len(result.values),1)
        datum=result.values[0]
        self.assertEqual(datum.datum_path,"filesystem.mountinfo.mounts")
        self.assertEqual(datum.value_type,"ARRAY")
        self.assertEqual(len(datum.normalized_value),2)
        a,b=datum.normalized_value
        self.assertEqual((a["mount_id"],a["parent_id"],a["major"],a["minor"]),
                         (36,22,8,1))
        self.assertEqual(a["mount_options"],"rw,relatime")
        self.assertEqual(a["super_options"],"rw,errors=remount-ro")
        self.assertEqual(a["optional_fields"],["shared:1"])
        self.assertEqual(a["filesystem_type"],"ext4")
        self.assertEqual(a["mount_source"],"/dev/sda1")
        self.assertEqual(b["root"],"/folder with spaces")
        self.assertEqual(b["mount_point"],"/mnt/Media Library")
        self.assertEqual(b["mount_source"],"server\\share")
        self.assertEqual(b["optional_fields"],["master:10","future:value"])
        self.assertNotIn("mount_health",repr(result.values))

    def test_escape_names_space_tab_newline_backslash(self):
        raw=b"1 9 0:0 /dir\\011tab\\012line /mnt\\040space\\134slash rw - tmpfs none rw\n"
        item=self.parsed(raw).values[0].normalized_value[0]
        self.assertEqual(item["root"],"/dir\ttab\nline")
        self.assertEqual(item["mount_point"],"/mnt space\\slash")

    def test_hidden_parent_and_stacked_distinct_ids_not_invalid(self):
        raw=(b"21 99 0:1 / / rw - tmpfs none rw\n"
             b"22 21 0:2 / / rw - ext4 /dev/sda rw\n")
        result=self.parsed(raw)
        self.assertEqual([v["mount_id"] for v in
                          result.values[0].normalized_value],[21,22])

    def test_sealed_canonical_preserves_original_bytes_and_provenance(self):
        with self.originals() as (folder,run,originals):
            manifest=build_canonical(folder,run)
            self.assertEqual(validate_canonical(folder),manifest)
            system=json.loads((folder/"private/system.json").read_text())
            observations=system["observations"]
            semantic=[a for a in observations if a["transformation_ids"]]
            self.assertEqual(len(semantic),1)
            self.assertEqual(semantic[0]["evidence_refs"],[originals[0].evidence_id])
            self.assertEqual(semantic[0]["source_attempt_ids"],["SRC-14-01"])
            self.assertEqual(semantic[0]["normalized_value"][1]["mount_point"],
                             "/mnt/Media Library")
            states=json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual((states["status_records"][0]["status"],
                              states["status_records"][0]["reason_code"]),
                             ("COMPLETE","OK"))
            self.assertEqual((folder/originals[0].private_relative_path).read_bytes(),RAW)
            self.assertEqual(originals[0].sha256,hashlib.sha256(RAW).hexdigest())

    def test_malformed_original_is_parse_failed_with_raw_preserved(self):
        bad=b"36 22 bad / / rw - ext4 /dev/sda1 rw\n"
        with self.originals(bad) as (folder,run,items):
            manifest=build_canonical(folder,run)
            self.assertEqual(validate_canonical(folder),manifest)
            sys=json.loads((folder/"private/system.json").read_text())
            self.assertEqual(len(sys["observations"]),1)
            self.assertTrue(any(s.startswith("PARSER_FAILED:")
                                for s in sys["observations"][0]["parser_findings"]))
            record=json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual(record["status_records"][0]["reason_code"],"PARSE_FAILED")
            self.assertEqual((folder/items[0].private_relative_path).read_bytes(),bad)

    def test_fail_closed_wrong_fixed_path_missing_path_extra_path(self):
        for paths in ((("/proc/1/mountinfo",)),tuple(),(PATH,PATH),
                      ("/proc/self/mounts",)):
            with self.subTest(paths=paths):
                with self.originals(paths=paths) as (folder,run,_):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder,run)
                    self.assertFalse((folder/"private/session_manifest.json").exists())

    def test_fail_closed_wrong_slot_and_forged_cross_run_evidence(self):
        for names in (("item0002",),("call0001-stdout",),("item0001","item0002")):
            with self.subTest(names=names):
                with self.originals(names=names,paths=(PATH,)*len(names)) as (folder,run,_):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder,run)
                    self.assertFalse((folder/"private/session_manifest.json").exists())
        with self.originals(wrong_run=True) as (folder,run,_):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder,run)

    def test_no_src14_stream_or_path_override_at_parser_boundary(self):
        for kwargs in ({"source_path":"/proc/self/mountinfo"},
                       {"source_stream":"stdout"},
                       {"source_command":"lsblk"},
                       {"source_target":"/proc/self/mountinfo"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-14",RAW,**kwargs)

    def test_adversarial_truncation_delimiter_and_identity_inputs(self):
        bad=[
            b"",b"\xff",b"\x00",RAW+b"\r",
            b"36 22 8:1 / / rw ext4 /dev/sda1 rw\n",
            b"36 22 8:1 / / rw - ext4 /dev/sda1\n",
            b"36 22 8:1 / / rw - ext4 /dev/sda1 rw extra\n",
            b"36 22 8:1 / / rw - ext4 /dev/sda1 - rw\n",
            b"36 22 8:1 / / rw - ext4 /dev/sda1 rw\n"*2,
            b"36 22 8:1 / / rw - ext4 /dev/sda1 rw\n"+b"36 22 8:2 / / ro - tmpfs none ro\n",
            b"zz 22 8:1 / / rw - ext4 /dev/sda1 rw\n",
            b"36 -2 8:1 / / rw - ext4 /dev/sda1 rw\n",
            b"36 22 8:three / / rw - ext4 /dev/sda1 rw\n",
            b"36 22 8:1 / / rw - ext4 /dev/sda1 rw\n"*4097,
            b"36 22 8:1 / / rw - ext4 /dev/sda1 rw\n"+b"x"*1048576,
            b"36 22 8:1 /relative / rw - ext4 /dev/sda1 rw\n",
            b"36 22 8:1 / not_absolute rw - ext4 /dev/sda1 rw\n",
            b"36 22 8:1 /bad\\999 / rw - ext4 /dev/sda1 rw\n",
            b"36 22 8:1 /bad\\0400 / rw - ext4 /dev/sda1 rw\n",
            b"36 22 8:1 /bad\\000 / rw - ext4 /dev/sda1 rw\n",
            b"36 22 8:1 /bad\\ / rw - ext4 /dev/sda1 rw\n",
            b"36 22 8:1 / / rw - ext4 /dev/sda1 rw\n"*0,
            b"36 22 8:1 / / rw  - ext4 /dev/sda1 rw\n",
            b"18446744073709551616 1 8:1 / / rw - ext4 /dev/sda1 rw\n",
        ]
        for data in bad:
            with self.subTest(data=data[:60]), self.assertRaises(SourceParseError):
                self.parsed(data)

if __name__=="__main__":
    unittest.main()
