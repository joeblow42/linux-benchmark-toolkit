"""G5-02 bounded local contract checks; no live source invocation."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest.mock import patch

from lbt_g5.safety import (
    MIB,SourceConsent,SourceRequest,decide_source,
    initial_source_policies,valid_run_id,
)
from lbt_g5.evidence import EvidenceWriter,RunMeter,evidence_identifier

RUN = "run-2026305120000"

class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.policies={p.source_id:p for p in initial_source_policies()}

    def request(self,source="SRC-05",**kw):
        return SourceRequest(RUN,source,self.policies[source].operation_id,**kw)

    def decision(self,request,**kw):
        with patch("lbt_g5.safety.os.geteuid",return_value=1000):
            return decide_source(request,**kw)

    def test_01_complete_approved_registry(self):
        self.assertEqual(len(self.policies),28)
        self.assertEqual({s for s,p in self.policies.items() if p.authorization_class=="O1"},
                         {"SRC-13","SRC-18","SRC-21"})
        self.assertEqual((self.policies["SRC-13"].per_target_bytes,
                         self.policies["SRC-13"].per_target_seconds),(8*MIB,12))
        self.assertEqual(self.policies["SRC-23"].max_entries,2)
        self.assertEqual(self.policies["SRC-25"].max_entries,4096)

    def test_02_root_refused(self):
        with patch("lbt_g5.safety.os.geteuid",return_value=0):
            self.assertEqual(decide_source(self.request()).reason,"PRIVILEGED_PROCESS")

    def test_03_unregistered_operation_and_bad_run(self):
        bad=SourceRequest(RUN,"SRC-05","ARBITRARY")
        self.assertEqual(self.decision(bad).reason,"UNREGISTERED_SOURCE_OR_OPERATION")
        self.assertFalse(valid_run_id("run-2026367120000"))
        self.assertEqual(self.decision(SourceRequest("run-2026367120000","SRC-05","LSCPU")).reason,"INVALID_RUN_ID")

    def test_04_no_user_argv_or_path_override(self):
        for override in ({"override_argv":("sh","-c","curl example.com")},
                         {"override_path":"/etc/shadow"}):
            with self.subTest(override=override):
                self.assertEqual(self.decision(self.request(**override)).reason,"UNTRUSTED_OVERRIDE")

    def test_05_o1_fail_closed_without_exact_one_run_consent(self):
        for sid in ("SRC-13","SRC-18","SRC-21"):
            self.assertEqual(self.decision(self.request(sid)).reason,"OPERATOR_AUTH_REQUIRED")
            c=SourceConsent(RUN,sid,self.policies[sid].operation_id,"device-A",datetime.now(timezone.utc),True)
            self.assertEqual(self.decision(self.request(sid,target="device-A",consent=c)).reason,"OPERATOR_AUTH_REQUIRED")
            self.assertTrue(self.decision(self.request(sid,target="device-A",consent=c,
                trusted_targets=frozenset({"device-A"}))).allowed)
            self.assertEqual(self.decision(self.request(sid,target="device-B",consent=c,
                trusted_targets=frozenset({"device-B"}))).reason,"OPERATOR_AUTH_REQUIRED")
            c2=SourceConsent("run-2026305120001",sid,self.policies[sid].operation_id,"device-A",datetime.now(timezone.utc),True)
            self.assertEqual(self.decision(self.request(sid,target="device-A",consent=c2,
                trusted_targets=frozenset({"device-A"}))).reason,"OPERATOR_AUTH_REQUIRED")

    def test_06_privacy_cannot_bypass_authorization(self):
        self.assertTrue(self.decision(self.request()).allowed)
        self.assertEqual(self.decision(self.request(operator_disabled=True)).reason,"OPERATOR_DISABLED")
        self.assertEqual(self.decision(self.request(),remaining_seconds=0).reason,"RUN_BUDGET_EXHAUSTED")
        self.assertEqual(self.decision(self.request(),remaining_bytes=0).reason,"RUN_BUDGET_EXHAUSTED")

    def test_07_fixed_file_allowlist(self):
        self.assertEqual(self.policies["SRC-06"].fixed_file,"/proc/cpuinfo")
        self.assertTrue(self.decision(self.request("SRC-06",target="/proc/cpuinfo")).allowed)
        self.assertEqual(self.decision(self.request("SRC-06",target="/etc/shadow")).reason,"UNTRUSTED_TARGET")

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir=Path(self.temp.name)/RUN
        self.run_dir.mkdir()
        self.policy={p.source_id:p for p in initial_source_policies()}["SRC-05"]
        self.writer=EvidenceWriter(str(self.run_dir),RUN)

    def test_08_exact_bytes_and_sha256_and_identity(self):
        original=b"known=ok\x00\xff\xfe\n"
        result=self.writer.seal_chunks(self.policy,"01","stdout",[original[:3],original[3:]])
        self.assertIsNone(result.failure)
        rec=result.receipt
        self.assertEqual(rec.evidence_id,f"{RUN}_COL-CPU_SRC-05_01:stdout")
        self.assertEqual(rec.byte_count,len(original))
        self.assertEqual(rec.sha256,hashlib.sha256(original).hexdigest())
        self.assertTrue(rec.complete)
        self.assertEqual((self.run_dir/rec.private_relative_path).read_bytes(),original)

    def test_09_stdout_stderr_independent_same_attempt(self):
        out=self.writer.seal_chunks(self.policy,"01","stdout",[b"a"]).receipt
        err=self.writer.seal_chunks(self.policy,"01","stderr",[b"b"]).receipt
        self.assertNotEqual(out.evidence_id,err.evidence_id)
        self.assertNotEqual(out.private_relative_path,err.private_relative_path)

    def test_10_no_replace_on_collision(self):
        rec=self.writer.seal_chunks(self.policy,"01","stdout",[b"original"]).receipt
        failure=self.writer.seal_chunks(self.policy,"01","stdout",[b"mutated"])
        self.assertIsNone(failure.receipt)
        self.assertEqual(failure.failure.reason,"EVIDENCE_PERSIST_FAILED")
        self.assertEqual((self.run_dir/rec.private_relative_path).read_bytes(),b"original")

    def test_11_per_stream_cap_keeps_actual_partial_bytes(self):
        result=self.writer.seal_chunks(self.policy,"01","stdout",[b"abcdef"],per_stream_limit=4)
        self.assertTrue(result.receipt.limit_applied)
        self.assertFalse(result.receipt.complete)
        self.assertEqual(result.receipt.omitted_at_least,2)
        self.assertEqual((self.run_dir/result.receipt.private_relative_path).read_bytes(),b"abcd")

    def test_12_global_budget_prevents_byte_overrun(self):
        writer=EvidenceWriter(str(self.run_dir),RUN,RunMeter(max_bytes=3))
        rec=writer.seal_chunks(self.policy,"01","stdout",[b"abcdefgh"]).receipt
        self.assertEqual(rec.byte_count,3)
        self.assertTrue(rec.limit_applied)
        self.assertEqual(writer.meter.bytes_reserved,3)

    def test_13_source_budget_shared_between_artifacts(self):
        a=self.writer.seal_chunks(self.policy,"01","stdout",[b"a"*(12*MIB)]).receipt
        b=self.writer.seal_chunks(self.policy,"01","stderr",[b"b"*(4*MIB+2)]).receipt
        self.assertEqual((a.byte_count,b.byte_count),(12*MIB,4*MIB))
        self.assertTrue(b.limit_applied)

    def test_14_invalid_artifact_and_symlink_path_refused(self):
        with self.assertRaises(ValueError):
            evidence_identifier(RUN,self.policy,"01","../secret")
        parent=Path(self.temp.name)/"shortcut"
        parent.symlink_to(self.run_dir, target_is_directory=True)
        with self.assertRaises(ValueError):
            EvidenceWriter(str(parent),RUN)

    def test_15_private_directory_permissions(self):
        rec=self.writer.seal_chunks(self.policy,"01","stdout",[b"x"]).receipt
        path=self.run_dir/rec.private_relative_path
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertEqual((self.run_dir/"private/evidence").stat().st_mode&0o777,0o700)

    def test_16_failure_has_no_fake_receipt(self):
        (self.run_dir/"private").mkdir(mode=0o777)
        (self.run_dir/"private").chmod(0o755)
        result=self.writer.seal_chunks(self.policy,"01","stdout",[b"x"])
        self.assertIsNone(result.receipt)
        self.assertEqual(result.failure.reason,"EVIDENCE_PERSIST_FAILED")

    def test_17_bad_chunk_is_programming_exception(self):
        with self.assertRaises(TypeError):
            self.writer.seal_chunks(self.policy,"01","stdout",["not bytes"])

if __name__=="__main__": unittest.main()
