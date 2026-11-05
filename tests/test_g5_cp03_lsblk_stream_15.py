"""CP03-15: source-first SRC-11 fixed lsblk D1 JSON and sealed-stream oracles.

Contract and negative expectations frozen in cp03_lsblk_stream_oracle_15.json
before parser source edit. No host lsblk execution occurs in this suite.
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
from lbt_g5.runtime import command_plan
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
APPROVED = ("lsblk", "--bytes", "--json", "--output",
            "NAME,KNAME,TYPE,SIZE,RO,RM,MODEL,SERIAL,TRAN")
CMD = " ".join(APPROVED)
RAW = json.dumps({"blockdevices":[
    {"name":"sda","kname":"sda","type":"disk","size":10000,"ro":False,
     "rm":False,"model":"Private device","serial":"PRIVATE-123","tran":"sata",
     "children":[{"name":"sda1","kname":"sda1","type":"part","size":4000,
                  "ro":False,"rm":False,"model":None,"serial":None,"tran":None}]}
]}).encode("utf-8") + b"\n"


class LsblkD1Oracles(unittest.TestCase):
    @contextmanager
    def original(self, streams, *, names=None, source_paths=(),
                 invocation=CMD, outcome="CAPTURED", reason="BYTES_PRESERVED",
                 exit_code=0, wrong_run=False):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/RUN
            folder.mkdir(mode=0o700)
            pol={p.source_id:p for p in initial_source_policies()}["SRC-11"]
            writer=EvidenceWriter(str(folder),RUN)
            names=names if names is not None else [n for n,_ in streams]
            self.assertEqual(len(names),len(streams))
            evid=[]
            for (_,raw),name in zip(streams,names):
                rec=writer.seal_chunks(pol,"01",name,(raw,)).receipt
                self.assertIsNotNone(rec)
                evid.append(rec)
            att=build_attempt(RUN,"SRC-11","01","ALLOW",outcome,reason,
                              evidence=tuple(evid),
                              bytes_count=sum(x.byte_count for x in evid),
                              source_paths=source_paths,invocation=invocation,
                              exit_code=exit_code)
            recpath=commit_attempt(str(folder),att)
            if wrong_run:
                evid[0]=replace(evid[0],run_id="run-2026305120001")
            record=SimpleNamespace(
                receipt_private_path=recpath,
                outcome=SimpleNamespace(artifacts=tuple(evid)))
            yield folder,EngineRun(RUN,(CollectorRun("COL-BLOCK",(record,)),)),tuple(evid)

    def test_approved_fixed_command_and_only_stdout_is_data(self):
        self.assertEqual(command_plan("SRC-11").argv, APPROVED)
        self.assertTrue(parser_available("SRC-11"))
        # SRC-13 becomes available in later CP03-17, with O1 verification.
        self.assertTrue(parser_available("SRC-13"))
        got=normalize_sealed_source("SRC-11",RAW,source_stream="stdout")
        self.assertEqual(got.values[0].datum_path,"storage.lsblk.blockdevices")
        self.assertEqual(got.values[0].value_type,"ARRAY")
        self.assertEqual(got.values[0].normalized_value[0]["size"],10000)
        self.assertEqual(got.values[0].normalized_value[0]["serial"],"PRIVATE-123")
        self.assertEqual(got.values[0].normalized_value[0]["children"][0]["name"],"sda1")
        with self.assertRaises(SourceParseError):
            normalize_sealed_source("SRC-11",RAW)
        with self.assertRaises(SourceParseError):
            normalize_sealed_source("SRC-11",b"warning\n",source_stream="stderr")

    def test_valid_stdout_stderr_originals_are_distinct_and_immutable(self):
        streams=(("call0001-stdout",RAW),
                 ("call0001-stderr",b"sample diagnostic\n"))
        with self.original(streams) as (folder,run,evid):
            manifest=build_canonical(folder,run)
            self.assertEqual(manifest["observation_count"],3)
            self.assertEqual(validate_canonical(folder),manifest)
            obs=json.loads((folder/"private/system.json").read_text())["observations"]
            semantic=[v for v in obs if v["transformation_ids"]]
            self.assertEqual(len(semantic),1)
            self.assertEqual(semantic[0]["evidence_refs"],[evid[0].evidence_id])
            self.assertEqual(semantic[0]["source_attempt_ids"],["SRC-11-01"])
            self.assertTrue(any("DIAGNOSTIC_ORIGINAL_PRESERVED"
                              in x["parser_findings"] for x in obs))
            status=json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual(status["status_records"][0]["reason_code"],"OK")
            for (_,raw),item in zip(streams,evid):
                self.assertEqual((folder/item.private_relative_path).read_bytes(),raw)
                self.assertEqual(item.sha256,hashlib.sha256(raw).hexdigest())

    def test_empty_device_tree_is_not_fabricated(self):
        v=normalize_sealed_source(
            "SRC-11",b'{"blockdevices":[]}\n',source_stream="stdout")
        self.assertEqual(v.values[0].normalized_value,[])

    def test_owner_approved_partial_nonzero_with_both_streams(self):
        with self.original((("call0001-stdout",RAW),),
              outcome="PARTIAL",reason="EXIT_NONZERO",exit_code=2) as (folder,run,_):
            manifest=build_canonical(folder,run)
            self.assertEqual(validate_canonical(folder),manifest)
            status=json.loads((folder/"private/status_records.json").read_text())
            record=status["status_records"][0]
            self.assertEqual((record["status"],record["reason_code"]),
                             ("PARTIAL","SOURCE_INCOMPLETE"))
            self.assertIn("exit_code=2",record["detail"])
            self.assertNotEqual(record["reason_code"],"OK")

    def test_absent_stdout_cannot_be_successfully_normalized(self):
        with self.original((("call0001-stderr",b"error\n"),)) as (folder,run,_):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder,run)
        # Owner alternative A treats a nonzero command as incomplete even if
        # stderr is its only original: never masquerades as semantic data.
        with self.original((("call0001-stderr",b"error\n"),),
              outcome="PARTIAL",reason="EXIT_NONZERO",exit_code=2) as (folder,run,_):
            manifest=build_canonical(folder,run)
            self.assertEqual(manifest["observation_count"],1)
            status=json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual(status["status_records"][0]["reason_code"],
                             "SOURCE_INCOMPLETE")

    def test_forged_streams_and_order_fail_closed(self):
        for streams in (
            (("call0001-stderr",b"warning\n"),("call0001-stdout",RAW)),
            (("call0002-stdout",RAW),),
            (("stdout",RAW),),
        ):
            with self.subTest(names=[x[0] for x in streams]):
                with self.original(streams) as (folder,run,_):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder,run)
                    self.assertFalse((folder/"private/session_manifest.json").exists())
        with self.original((("call0001-stdout",RAW),),
             source_paths=("/dev/sda",)) as (folder,run,_):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder,run)
        with self.original((("call0001-stdout",RAW),),
             invocation="lsblk --output-all") as (folder,run,_):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder,run)

    def test_duplicate_json_invalid_children_and_unselected_fields(self):
        bad=[
            b'{"blockdevices":[],"blockdevices":[]}',
            b'{"blockdevices":{}}',
            b'{"blockdevices":null}',
            b'{"blockdevices":[{"name":"sda","mountpoint":"/"}]}',
            b'{"blockdevices":[{"name":"sda","children":[123]}]}',
            b'{"blockdevices":[{"name":"sda","size":NaN}]}',
            b'{"blockdevices":[{"name":"sda","size":1.5}]}',
            b'{"blockdevices":[{"name":"sda","size":-1}]}',
            b'{"blockdevices":[{"name":"sda","ro":2}]}',
            b'{"blockdevices":[{"name":"sda","name":"sdb"}]}',
            b'{"blockdevices":[{"type":"disk"}]}',
            b'{"blockdevices":[{"name":"sda","serial":"AB\\u0000CD"}]}',
            b'{"blockdevices":[{"name":"sda","serial":true}]}',
            b'{"blockdevices":[{"name":"sda","children":{}}]}',
            b'{"bad":[]}',
            b'{bad json}',
            b'\xff',
        ]
        for payload in bad:
            with self.subTest(payload=payload[:50]),self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-11",payload,source_stream="stdout")

    def test_bounded_depth_node_count_and_original_parse_failure(self):
        node={"name":"leaf"}
        for i in range(17):
            node={"name":f"p{i}","children":[node]}
        deep=json.dumps({"blockdevices":[node]}).encode()
        with self.assertRaises(SourceParseError):
            normalize_sealed_source("SRC-11",deep,source_stream="stdout")
        many=json.dumps({"blockdevices":[{"name":"sda"}]*4097}).encode()
        with self.assertRaises(SourceParseError):
            normalize_sealed_source("SRC-11",many,source_stream="stdout")
        with self.original((("call0001-stdout",b"not json"),)) as (folder,run,evid):
            manifest=build_canonical(folder,run)
            self.assertEqual(manifest["observation_count"],1)
            state=json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual(state["status_records"][0]["reason_code"],"PARSE_FAILED")
            self.assertEqual((folder/evid[0].private_relative_path).read_bytes(),b"not json")
            self.assertEqual(validate_canonical(folder),manifest)

    def test_cross_run_original_is_not_valid_source_provenance(self):
        with self.original((("call0001-stdout",RAW),),wrong_run=True) as (folder,run,_):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder,run)


if __name__=="__main__":
    unittest.main()
