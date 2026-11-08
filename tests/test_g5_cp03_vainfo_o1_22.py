"""CP03-22: source-first SRC-21 VAINFO original O1 consent/negative oracles.

Synthetic sealed stdout and D0 GPU receipts only; no VA-API driver initialized.
"""
import hashlib, json, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.receipt_dispatch import RecordedOutcome
from lbt_g5.normalization import SourceParseError, normalize_sealed_source, parser_available
from lbt_g5.safety import initial_source_policies

RUN="run-2026305120000"
TARGET="/dev/dri/renderD128"
SRC19_PATH="/sys/class/drm/card0/device/vendor"
ARGV=("vainfo","--display","drm","--device",TARGET)
RAW=(b"Trying display: drm\n"
     b"vainfo: VA-API version: 1.14 (libva 2.12.0)\n"
     b"vainfo: Driver version: Mesa Gallium 23.2.1\n"
     b"vainfo: Supported profile and entrypoints\n"
     b"      VAProfileMPEG2Simple            : VAEntrypointVLD\n"
     b"      VAProfileH264Main               : VAEntrypointEncSlice\n"
     b"      VAProfileNone                   : VAEntrypointVideoProc\n")
POL={p.source_id:p for p in initial_source_policies()}

class VainfoO1SourceFirstOracles(unittest.TestCase):
    def parse(self,raw=RAW,**changes):
        opts=dict(source_stream="stdout",source_command="vainfo",source_target=TARGET)
        opts.update(changes)
        return normalize_sealed_source("SRC-21",raw,**opts)

    def fixture(self, *, raw=RAW, original="call0001-stdout",
                witness_mod=None, receipt_mod=None, include_inventory=True,
                memory_witness=True, tamper=False, partial=False,
                inv_path=SRC19_PATH):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        folder=Path(td.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        original_gpu=writer.seal_chunks(POL["SRC-19"],"01","item0001",(b"0x8086\n",)).receipt
        inv=build_attempt(RUN,"SRC-19","01","ALLOW","CAPTURED","BYTES_PRESERVED",
                          evidence=(original_gpu,),bytes_count=original_gpu.byte_count,
                          source_paths=(inv_path,),invocation="DRM_PCI_SYSFS")
        invpath=commit_attempt(str(folder),inv)
        entries=[]
        if include_inventory:
            entries.append(RecordedOutcome(
              SimpleNamespace(artifacts=(original_gpu,),disposition="CAPTURED",source_paths=(inv_path,)),
              invpath))
        original_va=writer.seal_chunks(POL["SRC-21"],"01",original,(raw,)).receipt
        witness={
            "run_id":RUN,"source_id":"SRC-21","operation_id":"VAINFO","target":TARGET,
            "consent_run_id":RUN,"consent_source_id":"SRC-21",
            "consent_operation_id":"VAINFO","consent_target":TARGET,
            "consent_issued_utc":"2026-11-01T12:00:00Z","impact_acknowledged":True,
            "inventory_source_id":"SRC-19","inventory_source_path":inv_path,
            "inventory_evidence_id":original_gpu.evidence_id,"approved_argv":list(ARGV)
        }
        witness.update(witness_mod or {})
        state,reason,code=("PARTIAL","ACQUISITION_ERROR",2) if partial else ("CAPTURED","BYTES_PRESERVED",0)
        opts=dict(evidence=(original_va,),bytes_count=original_va.byte_count,
                  target=TARGET,invocation=" ".join(ARGV),
                  exit_code=code,authorization_provenance=witness)
        opts.update(receipt_mod or {})
        rec=build_attempt(RUN,"SRC-21","01","ALLOW",state,reason,**opts)
        path=commit_attempt(str(folder),rec)
        entries.append(RecordedOutcome({"disposition":state,"reason":reason,
                                        "receipts":(original_va,)},path,
                      authorization_provenance=witness if memory_witness else None))
        if tamper:
            (folder/original_va.private_relative_path).write_bytes(b"forged\n")
        collectors = ((CollectorRun("COL-GPU", (entries[0],)),)
                      if include_inventory else ())
        run=EngineRun(RUN,collectors+(CollectorRun("COL-VAAPI",(entries[-1],)),))
        return folder,run,original_va

    def test_approved_registered_o1_source_and_parser(self):
        pol=POL["SRC-21"]
        self.assertEqual((pol.authorization_class,pol.operation_id,pol.max_entries,pol.max_seconds),
                         ("O1","VAINFO",1,10))
        self.assertTrue(parser_available("SRC-21"))

    def test_reported_version_driver_and_profile_pairs(self):
        p=self.parse()
        self.assertEqual(p.parser_id,"linux-vainfo-profile-entrypoints-v1")
        d=p.values[0]
        self.assertEqual((d.datum_path,d.value_type),("gpu.vaapi.reported_capabilities","OBJECT"))
        value=d.normalized_value
        self.assertEqual(value["va_api_version"],"1.14 (libva 2.12.0)")
        self.assertEqual(value["driver_version"],"Mesa Gallium 23.2.1")
        self.assertEqual(value["profile_entrypoints"][0],
                         {"profile":"VAProfileMPEG2Simple","entrypoint":"VAEntrypointVLD"})
        self.assertEqual(value["profile_entrypoints"][2]["entrypoint"],"VAEntrypointVideoProc")
        self.assertNotIn("benchmark",str(value).lower())

    def test_no_supported_profiles_reported_is_not_fabricated(self):
        data=b"vainfo: Supported profile and entrypoints\n"
        v=self.parse(data).values[0].normalized_value
        self.assertEqual(v["profile_entrypoints"],[])
        self.assertIsNone(v["va_api_version"])
        self.assertIsNone(v["driver_version"])

    def test_unknown_reported_va_profile_kept_as_source_label(self):
        v=self.parse(b"vainfo: Supported profile and entrypoints\n"
                     b" VAProfileFutureX : VAEntrypointFutureY\n").values[0].normalized_value
        self.assertEqual(v["profile_entrypoints"],[
           {"profile":"VAProfileFutureX","entrypoint":"VAEntrypointFutureY"}])

    def test_direct_stream_target_command_and_path_attacks(self):
        for attrs in ({"source_stream":"stderr"},{"source_stream":None},
                      {"source_command":"cat"},{"source_command":None},
                      {"source_target":"/dev/sda"},
                      {"source_target":"/dev/dri/card0"},
                      {"source_path":SRC19_PATH}):
            with self.subTest(attrs=attrs),self.assertRaises(SourceParseError):
                self.parse(**attrs)

    def test_malformed_stdout_utf8_control_and_bounds(self):
        bad=(
          b"not vainfo\n",
          b"VAProfileH264Main: VAEntrypointVLD\n",
          b"vainfo: Driver version: Unknown\n",
          b"vainfo: Supported profile and entrypoints\nBroken\n",
          b"vainfo: Supported profile and entrypoints\n VAProfileH264Main : bad\n",
          b"vainfo: Supported profile and entrypoints\n VAProfileH264Main : VAEntrypointVLD\n VAProfileH264Main : VAEntrypointVLD\n",
          b"vainfo: Supported profile and entrypoints\n\xff\n",
          RAW+b"\x00",RAW+b"\r",RAW.rstrip(b"\n"),
          RAW+b"x"*9000+b"\n",
          RAW+b"x"*(1024*1024)+b"\n")
        for data in bad:
            with self.subTest(data=data[:45]),self.assertRaises(SourceParseError):
                self.parse(data)

    def test_canonical_sealed_sha_and_source19_witness(self):
        folder,run,artifact=self.fixture()
        manifest=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),manifest)
        obs=json.loads((folder/"private/system.json").read_text())["observations"]
        typed=[v for v in obs if v["datum_path"]=="gpu.vaapi.reported_capabilities"]
        self.assertEqual(len(typed),1)
        self.assertEqual(typed[0]["evidence_refs"],[artifact.evidence_id])
        self.assertEqual((folder/artifact.private_relative_path).read_bytes(),RAW)
        self.assertEqual(artifact.sha256,hashlib.sha256(RAW).hexdigest())
        states=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        state=next(s for s in states if s["subject_id"]=="SRC-21")
        self.assertEqual((state["status"],state["reason_code"]),("COMPLETE","OK"))

    def test_partial_nonzero_o1_consent_maps_source_incomplete(self):
        folder,run,_=self.fixture(partial=True)
        build_canonical(folder,run)
        states=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        state=next(s for s in states if s["subject_id"]=="SRC-21")
        self.assertEqual((state["status"],state["reason_code"]),("PARTIAL","SOURCE_INCOMPLETE"))
        self.assertIn("exit_code=2",state["detail"])

    def test_captured_stderr_only_never_claims_capabilities(self):
        folder,run,_=self.fixture(original="call0001-stderr")
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder,run)

    def test_consent_command_inventory_and_original_attack_refused(self):
        cases=(
          dict(witness_mod={"consent_target":"/dev/dri/renderD129"}),
          dict(witness_mod={"consent_source_id":"SRC-18"}),
          dict(witness_mod={"approved_argv":["vainfo","--display","x11"]}),
          dict(witness_mod={"inventory_source_id":"SRC-17"}),
          dict(witness_mod={"inventory_evidence_id":"wrong"}),
          dict(witness_mod={"impact_acknowledged":False}),
          dict(memory_witness=False),
          dict(include_inventory=False),
          dict(original="call0002-stdout"),
          dict(receipt_mod={"invocation":"vainfo --display x11"}),
          dict(receipt_mod={"target":"/dev/dri/renderD129"}),
          dict(receipt_mod={"exit_code":2}),
          dict(receipt_mod={"exit_code":None}),
          dict(receipt_mod={"timed_out":True}),
          dict(receipt_mod={"capture_limited":True}),
          dict(tamper=True))
        for change in cases:
            with self.subTest(change=change):
                folder,run,_=self.fixture(**change)
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)

    def test_invalid_sealed_stdout_preserves_original_with_parse_failed(self):
        original=b"driver initialization unclear\n"
        folder,run,artifact=self.fixture(raw=original)
        build_canonical(folder,run)
        states=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        status=next(s for s in states if s["subject_id"]=="SRC-21")
        self.assertEqual((status["status"],status["reason_code"]),("PARTIAL","PARSE_FAILED"))
        self.assertEqual((folder/artifact.private_relative_path).read_bytes(),original)

if __name__=="__main__":
    unittest.main()
