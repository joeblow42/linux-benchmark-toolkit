"""CP03-20 SRC-18 source-first O1 sealed optical fixture oracles, no device access."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.receipt_dispatch import RecordedOutcome
from lbt_g5.normalization import normalize_sealed_source, parser_available, SourceParseError
from lbt_g5.safety import initial_source_policies
import tempfile, unittest, json, hashlib

RUN = "run-2026305120000"
TARGET = "/dev/sr0"
INVPATH = "/sys/class/block/sr0/removable"
ARGV = ("sg_get_config","--readonly","--current",TARGET)
OUTPUT = (b"Current profile: DVD-ROM\nFeatures:\n"
          b" Profile list feature\n version=0, persist=1, current=1 [0x0]\n"
          b" available profiles [more recent typically higher in list]:\n"
          b" profile: DVD-ROM , currentP=1\n")
POL = {p.source_id:p for p in initial_source_policies()}

class OpticalO1Oracles(unittest.TestCase):
    def parse(self, raw=OUTPUT, **overrides):
        args=dict(source_stream="stdout",source_command="sg_get_config",source_target=TARGET)
        args.update(overrides)
        return normalize_sealed_source("SRC-18",raw,**args)

    def fixture(self, *, raw=OUTPUT, original="call0001-stdout", witness_mod=None,
                o1_mod=None, upstream=True, corrupt=False, partial=False,
                upstream_path=INVPATH, memory_witness=True):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder=Path(temp.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        upstream_entries=[]
        original_inv=writer.seal_chunks(POL["SRC-17"],"01","item0001",(b"1\n",)).receipt
        invreceipt=build_attempt(RUN,"SRC-17","01","ALLOW","CAPTURED","BYTES_PRESERVED",
                                 evidence=(original_inv,),bytes_count=original_inv.byte_count,
                                 source_paths=(upstream_path,),invocation="OPTICAL_SYSFS")
        ipath=commit_attempt(str(folder),invreceipt)
        if upstream:
            upstream_entries.append(RecordedOutcome(
                SimpleNamespace(artifacts=(original_inv,),disposition="CAPTURED",
                                source_paths=(upstream_path,)),ipath))
        o=writer.seal_chunks(POL["SRC-18"],"01",original,(raw,)).receipt
        witness={
           "run_id":RUN,"source_id":"SRC-18","operation_id":"OPTICAL_MEDIA",
           "target":TARGET,"consent_run_id":RUN,"consent_source_id":"SRC-18",
           "consent_operation_id":"OPTICAL_MEDIA","consent_target":TARGET,
           "consent_issued_utc":"2026-11-01T12:00:00Z",
           "impact_acknowledged":True,"inventory_source_id":"SRC-17",
           "inventory_source_path":upstream_path,"inventory_evidence_id":original_inv.evidence_id,
           "approved_argv":list(ARGV)
        }
        witness.update(witness_mod or {})
        state, reason, code = ("PARTIAL","ACQUISITION_ERROR",2) if partial else ("CAPTURED","BYTES_PRESERVED",0)
        fields=dict(evidence=(o,),bytes_count=o.byte_count,target=TARGET,
                    invocation=" ".join(ARGV),exit_code=code,authorization_provenance=witness)
        fields.update(o1_mod or {})
        rec=build_attempt(RUN,"SRC-18","01","ALLOW",state,reason,**fields)
        rp=commit_attempt(str(folder),rec)
        entry=RecordedOutcome({"disposition":state,"reason":reason,"receipts":(o,)},rp,
                              authorization_provenance=witness if memory_witness else None)
        if corrupt:
            (folder/o.private_relative_path).write_bytes(b"forged\n")
        return folder,EngineRun(RUN,(CollectorRun("COL-OPTICAL",tuple(upstream_entries+[entry])),)),o

    def test_existing_o1_fixed_consent_metadata(self):
        p=POL["SRC-18"]
        self.assertEqual((p.authorization_class,p.operation_id,p.collector_id,p.max_entries),
                         ("O1","OPTICAL_MEDIA","COL-OPTICAL",4))
        self.assertTrue(parser_available("SRC-18"))

    def test_reported_profile_and_opaque_feature_lines(self):
        r=self.parse()
        self.assertEqual(r.parser_id,"linux-sg-get-config-current-v1")
        self.assertEqual(len(r.values),1)
        d=r.values[0]
        self.assertEqual((d.datum_path,d.value_type),("optical.mmc.current_configuration","OBJECT"))
        self.assertEqual(d.normalized_value["reported_profile"],"DVD-ROM")
        self.assertIn(" profile: DVD-ROM , currentP=1",d.normalized_value["feature_lines"])
        self.assertNotIn("health",str(d.normalized_value).lower())

    def test_missing_profile_is_unknown_not_media_absence(self):
        r=self.parse(b"Features:\n Profile list feature\n")
        self.assertIsNone(r.values[0].normalized_value["reported_profile"])

    def test_direct_wrong_stream_command_target_path_rejected(self):
        for args in ({"source_stream":"stderr"},{"source_stream":None},
                     {"source_command":"cat"},{"source_command":None},
                     {"source_target":"/dev/sr9/../sr1"},{"source_target":"/dev/sda"},
                     {"source_path":"/dev/sr0"}):
            with self.subTest(args=args),self.assertRaises(SourceParseError):
                self.parse(**args)

    def test_malformed_profile_utf8_controls_bounds_rejected(self):
        for raw in (b"not sg3 output\n",b"Current profile: DVD-ROM\n",
                    b"Current profile: DVD-ROM\nCurrent profile: CD-ROM\nFeatures:\n",
                    b"Features:\nCurrent profile: fake\n", b"Features:\n\xff\n",
                    b"Features:\n bad\x00\n",b"Features:\n bad\r\n",
                    b"Features:\n"+b"x"*9000+b"\n",
                    b"Features:\n"+b"x\n"*4097,
                    b"Features:\n"+b"x"*1048576+b"\n",b"Features:"):
            with self.subTest(raw=raw[:35]),self.assertRaises(SourceParseError):
                self.parse(raw)

    def test_canonical_same_run_original_provenance(self):
        folder,run,o=self.fixture()
        manifest=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),manifest)
        obs=json.loads((folder/"private/system.json").read_text())["observations"]
        semantic=[x for x in obs if x["datum_path"]=="optical.mmc.current_configuration"]
        self.assertEqual(len(semantic),1)
        self.assertEqual(semantic[0]["evidence_refs"],[o.evidence_id])
        self.assertEqual((folder/o.private_relative_path).read_bytes(),OUTPUT)
        self.assertEqual(o.sha256,hashlib.sha256(OUTPUT).hexdigest())
        statuses=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        state=next(s for s in statuses if s["subject_id"]=="SRC-18")
        self.assertEqual((state["status"],state["reason_code"]),("COMPLETE","OK"))

    def test_nonzero_owner_mapping_without_medial_health_conclusion(self):
        folder,run,_=self.fixture(partial=True)
        build_canonical(folder,run)
        statuses=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        state=next(s for s in statuses if s["subject_id"]=="SRC-18")
        self.assertEqual((state["status"],state["reason_code"]),("PARTIAL","SOURCE_INCOMPLETE"))
        self.assertIn("exit_code=2",state["detail"])

    def test_stderr_only_is_not_successful_semantic_data(self):
        folder,run,_=self.fixture(original="call0001-stderr")
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder,run)

    def test_verified_capture_contradictions_rejected(self):
        for changes in ({"exit_code":2},{"exit_code":None},{"timed_out":True},
                        {"capture_limited":True}):
            with self.subTest(changes=changes):
                folder,run,_=self.fixture(o1_mod=changes)
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)

    def test_forged_authorization_target_inventory_and_evidence_rejected(self):
        variants=(
          dict(witness_mod={"consent_target":"/dev/sr1"}),
          dict(witness_mod={"approved_argv":["sg_get_config","/dev/sr0"]}),
          dict(witness_mod={"inventory_evidence_id":"fake"}),
          dict(witness_mod={"impact_acknowledged":False}),
          dict(upstream=False),dict(memory_witness=False),
          dict(original="call0002-stdout"),
          dict(upstream_path="/sys/class/block/sr1/removable"),
          dict(o1_mod={"invocation":"sg_get_config --raw /dev/sr0"}),
          dict(o1_mod={"target":"/dev/sr1"}),
          dict(corrupt=True))
        for args in variants:
            with self.subTest(args=args):
                folder,run,_=self.fixture(**args)
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)

    def test_malformed_sealed_stdout_keeps_exact_original(self):
        bad=b"unknown optical data\n"
        folder,run,o=self.fixture(raw=bad)
        build_canonical(folder,run)
        statuses=json.loads((folder/"private/status_records.json").read_text())["status_records"]
        state=next(s for s in statuses if s["subject_id"]=="SRC-18")
        self.assertEqual((state["status"],state["reason_code"]),("PARTIAL","PARSE_FAILED"))
        self.assertEqual((folder/o.private_relative_path).read_bytes(),bad)

if __name__=="__main__":
    unittest.main()
