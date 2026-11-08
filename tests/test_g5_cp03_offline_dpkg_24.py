"""CP03-24: source-first sealed offline dpkg-query metadata/negative tests.

All evidence is synthetic, sealed with real G5-02 writer; no command executes.
"""
import hashlib, json, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from lbt_g5.additional import _DPKG_ARGV
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.normalization import normalize_sealed_source, parser_available, SourceParseError
from lbt_g5.safety import initial_source_policies

RUN="run-2026305120000"
RAW=(b"dpkg\t1.21.22\n"
     b"libc6:amd64\t2.36-9+deb12u9\n"
     b"ffmpeg\t7:5.1.7-0+deb12u1\n"
     b"libfoo\t\n")
POL={p.source_id:p for p in initial_source_policies()}["SRC-28"]

class OfflineDpkgSourceFirstOracles(unittest.TestCase):
    def direct(self,raw=RAW,**changes):
        kw=dict(source_path="installed-packages",source_stream="stdout",
                source_command="dpkg-query")
        kw.update(changes)
        return normalize_sealed_source("SRC-28",raw,**kw)

    def make(self,*,raw=RAW,items=None,invocation="OFFLINE_METADATA",
             source_paths=None,attempt="01",outcome="CAPTURED",
             reason="BYTES_PRESERVED",target=None,exit_code=None,
             timed_out=False,capture_limited=False,tamper=False):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        folder=Path(td.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        items=items or (("call0001-stdout",raw),)
        artifacts=[]
        for name,data in items:
            a=writer.seal_chunks(POL,attempt,name,(data,)).receipt
            self.assertIsNotNone(a)
            artifacts.append(a)
        if source_paths is None:
            source_paths=tuple("installed-packages:"+name.rsplit("-",1)[-1] for name,_ in items)
        receipt=build_attempt(RUN,"SRC-28",attempt,"ALLOW",outcome,reason,
                              evidence=tuple(artifacts),bytes_count=sum(a.byte_count for a in artifacts),
                              invocation=invocation,source_paths=source_paths,
                              target=target,exit_code=exit_code,
                              timed_out=timed_out,capture_limited=capture_limited)
        path=commit_attempt(str(folder),receipt)
        recorded=SimpleNamespace(receipt_private_path=path,
                                 outcome=SimpleNamespace(artifacts=tuple(artifacts)))
        if tamper:
            (folder/artifacts[0].private_relative_path).write_bytes(b"tampered\n")
        return folder,EngineRun(RUN,(CollectorRun("COL-SOFTCODEC",(recorded,)),)),tuple(artifacts)

    def test_registered_existing_local_only_adapter_and_parser(self):
        self.assertEqual((POL.authorization_class,POL.operation_id,POL.max_entries,
                          POL.max_seconds,POL.per_target_bytes,POL.per_target_seconds),
                         ("D1","OFFLINE_METADATA",4,20,8*1024*1024,8))
        expected="-f=$"+"{Package}"+r"\t$"+"{Version}"+r"\n"
        self.assertEqual(_DPKG_ARGV,("dpkg-query","-W",expected))
        self.assertTrue(parser_available("SRC-28"))

    def test_package_records_are_reported_without_installed_verdict(self):
        r=self.direct()
        self.assertEqual(r.parser_id,"linux-dpkg-query-package-records-v1")
        d=r.values[0]
        self.assertEqual((d.datum_path,d.value_type),
                         ("software.dpkg.reported_package_db_records","ARRAY"))
        self.assertEqual(d.normalized_value[0],{"package":"dpkg","reported_version":"1.21.22"})
        self.assertEqual(d.normalized_value[1]["package"],"libc6:amd64")
        self.assertEqual(d.normalized_value[2]["reported_version"],"7:5.1.7-0+deb12u1")
        self.assertEqual(d.normalized_value[3]["reported_version"],"")
        self.assertNotIn("installed",str(d.normalized_value).lower())

    def test_duplicate_package_name_remains_source_ordered(self):
        v=self.direct(b"libc6\t2.36-1\nlibc6\t2.36-2\n").values[0].normalized_value
        self.assertEqual([x["reported_version"] for x in v],["2.36-1","2.36-2"])

    def test_empty_snapshot_report(self):
        self.assertEqual(self.direct(b"\n").values[0].normalized_value,[])

    def test_bad_rows_utf8_controls_and_bounds(self):
        bad=(b"dpkg 1.0\n",b"dpkg\t1.0\textra\n",b"\t1.0\n",
             b"Dpkg\t1.0\n",b"bad_name\t1.0\n",b"dpkg\t1.0 bad\n",
             b"dpkg\t1.0\x00\n",b"dpkg\t1.0\r\n",b"dpkg\t\xff\n",
             b"dpkg\t1.0",b"dpkg\t1.0\nlast",
             b"dpkg\t"+b"x"*600+b"\n",b"dpkg\t1.0\n"*100001,
             b"dpkg\t"+b"1"*(8*1024*1024)+b"\n")
        for raw in bad:
            with self.subTest(raw=raw[:25],size=len(raw)),self.assertRaises(SourceParseError):
                self.direct(raw)

    def test_direct_wrong_source_stream_or_command(self):
        for kw in (dict(source_stream=None),dict(source_stream="stderr"),
                   dict(source_path="/var/lib/dpkg/status"),dict(source_path="installed"),
                   dict(source_command=None),dict(source_command="rpm"),
                   dict(source_command="apt update"),dict(source_target="/dev/sda")):
            with self.subTest(kw=kw),self.assertRaises(SourceParseError):
                self.direct(**kw)

    def test_verified_original_stderr_diagnostic_and_status(self):
        items=(("call0001-stdout",RAW),("call0001-stderr",b"diagnostic\n"))
        folder,run,artifacts=self.make(items=items)
        manifest=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),manifest)
        obs=json.loads((folder/"private/system.json").read_text())["observations"]
        found=[x for x in obs if x["datum_path"]=="software.dpkg.reported_package_db_records"]
        self.assertEqual(len(found),1)
        self.assertEqual(found[0]["evidence_refs"],[artifacts[0].evidence_id])
        self.assertFalse(any(x["transformation_ids"] for x in obs
             if x["evidence_refs"]==[artifacts[1].evidence_id]))
        for art in artifacts:
            self.assertEqual(hashlib.sha256((folder/art.private_relative_path).read_bytes()).hexdigest(),art.sha256)
        statuses=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        source=next(x for x in statuses if x["subject_id"]=="SRC-28")
        self.assertEqual((source["status"],source["reason_code"]),("COMPLETE","OK"))

    def test_partial_source_incomplete_without_forged_exit(self):
        folder,run,_=self.make(outcome="PARTIAL",reason="SOURCE_INCOMPLETE")
        build_canonical(folder,run)
        st=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        source=next(x for x in st if x["subject_id"]=="SRC-28")
        self.assertEqual((source["status"],source["reason_code"]),("PARTIAL","SOURCE_INCOMPLETE"))
        self.assertNotIn("exit_code=2",source["detail"])

    def test_malformed_captured_bytes_retain_original_and_mark_parse_failed(self):
        raw=b"not a package database listing\n"
        folder,run,artifacts=self.make(raw=raw)
        build_canonical(folder,run)
        st=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        self.assertEqual(next(x for x in st if x["subject_id"]=="SRC-28")["reason_code"],"PARSE_FAILED")
        self.assertEqual((folder/artifacts[0].private_relative_path).read_bytes(),raw)

    def test_stderr_only_cannot_be_complete(self):
        folder,run,_=self.make(items=(("call0001-stderr",b"warning\n"),))
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder,run)

    def test_invalid_receipt_stream_source_and_transport_fail_closed(self):
        bad=(dict(attempt="02"),dict(items=(("call0002-stdout",RAW),)),
             dict(items=(("item0001",RAW),)),dict(invocation="dpkg-query -W"),
             dict(invocation="apt update"),dict(source_paths=("installed-packages:stderr",)),
             dict(source_paths=("/var/lib/dpkg/status:stdout",)),
             dict(source_paths=()),dict(target="apt"),dict(exit_code=2),
             dict(timed_out=True),dict(capture_limited=True),dict(tamper=True))
        for kw in bad:
            with self.subTest(kw=kw):
                folder,run,_=self.make(**kw)
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)
                self.assertFalse((folder/"private/session_manifest.json").exists())

if __name__=="__main__":
    unittest.main()
