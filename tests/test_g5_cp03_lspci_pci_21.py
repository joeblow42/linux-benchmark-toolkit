"""CP03-21 source-first lspci -nn sealed stdout/receipt fixtures; no host PCI probe."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import hashlib, json, tempfile, unittest
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import EngineRun, CollectorRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.runtime import command_plan
from lbt_g5.normalization import normalize_sealed_source, parser_available, SourceParseError
from lbt_g5.safety import initial_source_policies

RUN="run-2026305120000"
OUTPUT=(b"00:02.0 VGA compatible controller [0300]: Intel Corporation HD Graphics [8086:0416] (rev 06)\n"
        b"0000:01:00.0 Display controller [0380]: Advanced Micro Devices [AMD] Radeon HD [1002:6660] (rev c3)\n")
POL={p.source_id:p for p in initial_source_policies()}

class LspciSourceFirstOracles(unittest.TestCase):
    def parse(self, raw=OUTPUT, **attrs):
        return normalize_sealed_source("SRC-20",raw,source_stream="stdout",**attrs)

    @contextmanager
    def sealed(self, items=(("call0001-stdout",OUTPUT),), *,
               names=None, source_paths=(), invocation="lspci -nn",
               target=None, outcome="CAPTURED", reason="BYTES_PRESERVED",
               exit_code=0, timed_out=False, capture_limited=False,
               tamper=False):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/RUN
            folder.mkdir(mode=0o700)
            writer=EvidenceWriter(str(folder),RUN)
            receipts=[]
            for i,(name,raw) in enumerate(items):
                artifact_name=names[i] if names else name
                value=writer.seal_chunks(POL["SRC-20"],"01",artifact_name,(raw,)).receipt
                self.assertIsNotNone(value)
                receipts.append(value)
            record=build_attempt(RUN,"SRC-20","01","ALLOW",outcome,reason,
                                 evidence=tuple(receipts),
                                 bytes_count=sum(a.byte_count for a in receipts),
                                 invocation=invocation,source_paths=source_paths,
                                 target=target,exit_code=exit_code,timed_out=timed_out,
                                 capture_limited=capture_limited)
            path=commit_attempt(str(folder),record)
            rec=SimpleNamespace(receipt_private_path=path,
                                outcome=SimpleNamespace(artifacts=tuple(receipts)))
            if tamper and receipts:
                (folder/receipts[0].private_relative_path).write_bytes(b"tamper\n")
            yield folder,EngineRun(RUN,(CollectorRun("COL-GPU",(rec,)),)),tuple(receipts)

    def test_existing_registered_d1_command_and_parser(self):
        p=POL["SRC-20"]
        self.assertEqual((p.authorization_class,p.operation_id,p.max_entries,p.max_seconds),
                         ("D1","LSPCI",1,6))
        self.assertEqual(command_plan("SRC-20").argv,("lspci","-nn"))
        self.assertTrue(parser_available("SRC-20"))

    def test_source_reported_slot_class_and_pci_ids_are_preserved(self):
        r=self.parse()
        self.assertEqual(r.parser_id,"linux-lspci-nn-bounded-v1")
        d=r.values[0]
        self.assertEqual((d.datum_path,d.value_type),("gpu.pci.lspci.devices","ARRAY"))
        a,b=d.normalized_value
        self.assertEqual((a["slot"],a["class_code"],a["vendor_id"],a["device_id"],a["revision"]),
                         ("00:02.0","0300","8086","0416","06"))
        self.assertEqual((b["slot"],b["vendor_id"],b["device_id"],b["revision"]),
                         ("0000:01:00.0","1002","6660","c3"))
        self.assertIn("[AMD]",b["reported_description"])
        self.assertFalse(any("driver" in v or "healthy" in v for v in a))

    def test_unknown_revision_and_nonascii_reported_text(self):
        value=b"00:1f.3 Audio device [0403]: Example Unicode \xc3\xa9 [1234:0001]\n"
        d=self.parse(value).values[0].normalized_value[0]
        self.assertEqual(d["revision"],None)
        self.assertEqual(d["reported_description"],"Example Unicode é")

    def test_invalid_grammar_and_bound_fail_closed(self):
        invalid=(
            b"lspci: no devices\n", b"",
            b"00:02.0 VGA controller: Intel [8086:0416]\n", # missing class code
            b"00:02.0 VGA [030Z]: Intel [8086:0416]\n",
            b"00:02.0 VGA [0300]: Intel [808G:0416]\n",
            b"00:02.0 VGA [0300]: Intel [8086:0416] (rev XX)\n",
            b"00000:01:00.0 VGA [0300]: AMD [1002:6660]\n",
            b"00:02.9 VGA [0300]: Intel [8086:0416]\n",
            b"00:02.0 VGA [0300]: Intel [8086:0416]\n"*2,
            b"\xff\n",OUTPUT+b"\x00",OUTPUT+b"\r",
            OUTPUT+b"x"*9000+b"\n",
            OUTPUT+b"x"*(1024*1024)+b"\n",
            OUTPUT.rstrip(b"\n"))
        for value in invalid:
            with self.subTest(value=value[:40]),self.assertRaises(SourceParseError):
                self.parse(value)

    def test_direct_data_stream_and_forbidden_attribution_rejected(self):
        for kwargs in ({"source_stream":"stderr"},
                       {"source_path":"/sys/class/drm/card0/device/vendor"},
                       {"source_target":"/dev/dri/renderD128"},
                       {"source_command":"lspci"}):
            with self.subTest(kwargs=kwargs),self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-20",OUTPUT,**kwargs)
        with self.assertRaises(SourceParseError):
            normalize_sealed_source("SRC-20",OUTPUT)

    def test_canonical_verified_original_and_stderr_diagnostic(self):
        items=(("call0001-stdout",OUTPUT),("call0001-stderr",b"warning\n"))
        with self.sealed(items) as (folder,run,artifacts):
            manifest=build_canonical(folder,run)
            self.assertEqual(validate_canonical(folder),manifest)
            obs=json.loads((folder/"private/system.json").read_text())["observations"]
            typed=[x for x in obs if x["datum_path"]=="gpu.pci.lspci.devices"]
            self.assertEqual(len(typed),1)
            self.assertEqual(typed[0]["evidence_refs"],[artifacts[0].evidence_id])
            self.assertFalse(any(x["transformation_ids"] for x in obs
                if x["evidence_refs"]==[artifacts[1].evidence_id]))
            self.assertEqual((folder/artifacts[0].private_relative_path).read_bytes(),OUTPUT)
            self.assertEqual(artifacts[0].sha256,hashlib.sha256(OUTPUT).hexdigest())
            st=json.loads((folder/"private/status_records.json").read_text())["status_records"]
            state=next(x for x in st if x["subject_id"]=="SRC-20")
            self.assertEqual((state["status"],state["reason_code"]),("COMPLETE","OK"))

    def test_captured_invalid_text_is_parser_failure_not_fabricated_inventory(self):
        bad=b"garbled PCI row\n"
        with self.sealed((("call0001-stdout",bad),)) as (folder,run,artifacts):
            build_canonical(folder,run)
            st=json.loads((folder/"private/status_records.json").read_text())["status_records"]
            state=next(x for x in st if x["subject_id"]=="SRC-20")
            self.assertEqual((state["status"],state["reason_code"]),("PARTIAL","PARSE_FAILED"))
            self.assertEqual((folder/artifacts[0].private_relative_path).read_bytes(),bad)

    def test_d1_nonzero_original_and_status_preserved(self):
        with self.sealed(outcome="PARTIAL",reason="EXIT_NONZERO",exit_code=2) as (folder,run,_):
            build_canonical(folder,run)
            status=json.loads((folder/"private/status_records.json").read_text())["status_records"]
            state=next(s for s in status if s["subject_id"]=="SRC-20")
            self.assertEqual((state["status"],state["reason_code"]),("PARTIAL","SOURCE_INCOMPLETE"))
            self.assertIn("exit_code=2",state["detail"])

    def test_missing_stdout_forged_call_path_command_and_target_fail(self):
        cases=(
         dict(items=(("call0001-stderr",b"warning\n"),)),
         dict(names=("call0002-stdout",)),
         dict(names=("item0001",)),
         dict(invocation="lspci -vv"),
         dict(source_paths=("/sys/class/drm/card0/device/vendor",)),
         dict(target="/dev/dri/renderD128"),
         dict(tamper=True),
         dict(exit_code=1),
         dict(timed_out=True),
         dict(capture_limited=True))
        for changes in cases:
            with self.subTest(changes=changes),self.sealed(**changes) as (folder,run,_):
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)

if __name__=="__main__":
    unittest.main()
