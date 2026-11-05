"""CP03-17 frozen source-first SMART/NVMe positive and negative fixtures.

See verification/g5_04/cp03_src13_health_stream_oracle_17.json.
No real device, helper, sudo, shell, or host probe in these fixtures.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.normalization import SourceParseError, normalize_sealed_source, parser_available
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.receipt_dispatch import RecordedOutcome
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
SMART = (b"smartctl 7.4\n=== START OF INFORMATION SECTION ===\n"
         b"Device Model:    Example Drive\nSerial Number: PRIVATE-12345\n"
         b"Firmware Version: 2.2\n=== START OF READ SMART DATA SECTION ===\n"
         b"SMART overall-health self-assessment test result: PASSED\n")
NVME = (b"Smart Log for NVME device:nvme0 namespace-id:ffffffff\n"
        b"critical_warning : 0x02\ntemperature : 35 C (308 Kelvin)\n"
        b"available_spare : 100%\npercentage_used : 3%\n"
        b"power_on_hours : 3,510\nmedia_errors : 0\n")
SRC13_SMART = ("smartctl", "-i", "-H", "/dev/sda")
SRC13_NVME = ("nvme", "smart-log", "/dev/nvme0")


class SRC13HealthOracles(unittest.TestCase):
    def parse(self, raw=SMART, command="smartctl", target="/dev/sda"):
        return normalize_sealed_source(
            "SRC-13", raw, source_stream="stdout",
            source_command=command, source_target=target)

    def test_registered_and_bounded_smartctl_report_values(self):
        self.assertTrue(parser_available("SRC-13"))
        parsed=self.parse()
        self.assertEqual(parsed.parser_id, "linux-src13-health-verified-stdout-v1")
        fields={d.datum_path:d for d in parsed.values}
        self.assertEqual(fields["storage.device_health.smartctl.device_model"].normalized_value,
                         "Example Drive")
        self.assertEqual(fields["storage.device_health.smartctl.serial_number"].normalized_value,
                         "PRIVATE-12345")
        self.assertEqual(fields["storage.device_health.smartctl.reported_assessment"].normalized_value,
                         "PASSED")
        self.assertFalse(any("healthy" in d.datum_path or "failing" in d.datum_path
                             for d in parsed.values))
        self.assertTrue(all(d.value_type=="STRING" for d in parsed.values))

    def test_smart_health_text_not_inferred_from_exit_code(self):
        result=self.parse(SMART.replace(b"PASSED",b"FAILED!"))
        self.assertEqual([d for d in result.values if
                          d.datum_path.endswith("reported_assessment")][0].normalized_value,
                         "FAILED!")

    def test_nvme_hex_percent_count_and_celsius_without_health_verdict(self):
        parsed=self.parse(NVME,"nvme","/dev/nvme0")
        v={x.datum_path.split(".")[-1]:x for x in parsed.values}
        self.assertEqual(v["warning_bits"].normalized_value,2)
        self.assertEqual((v["temperature"].normalized_value,v["temperature"].unit),
                         (35,"C"))
        self.assertEqual((v["available_spare"].normalized_value,v["available_spare"].unit),
                         (100,"%"))
        self.assertEqual(v["power_on_hours"].normalized_value,3510)
        self.assertEqual(v["power_on_hours"].unit,"h")
        self.assertEqual(v["media_errors"].normalized_value,0)
        self.assertNotIn("healthy",str(parsed.values).lower())

    def test_unknown_temperature_unit_is_not_converted(self):
        raw=NVME.replace(b"35 C (308 Kelvin)",b"91 \xc2\xb0F (306 K)")
        r=self.parse(raw,"nvme","/dev/nvme0")
        temp=[d for d in r.values if d.datum_path.endswith(".temperature")][0]
        self.assertEqual(temp.value_type,"STRING")
        self.assertIsNone(temp.unit)
        self.assertEqual(temp.normalized_value,"91 \N{DEGREE SIGN}F (306 K)")

    def test_stream_and_command_attribution_fail_closed(self):
        for kw in (
            {"source_stream":"stderr", "source_command":"smartctl","source_target":"/dev/sda"},
            {"source_stream":None, "source_command":"smartctl","source_target":"/dev/sda"},
            {"source_stream":"stdout", "source_command":None,"source_target":"/dev/sda"},
            {"source_stream":"stdout", "source_command":"nvme","source_target":"/dev/sda"},
            {"source_stream":"stdout", "source_command":"smartctl","source_target":"/dev/nvme0"},
            {"source_stream":"stdout", "source_command":"smartctl","source_target":"/dev/sda",
             "source_path":"/sys/class/block/sda/size"},
        ):
            with self.subTest(kw=kw), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-13",SMART,**kw)

    def test_wrong_nvme_header_or_untrusted_content_fails(self):
        for raw in (
            NVME.replace(b"device:nvme0",b"device:nvme9"),
            NVME.replace(b"Smart Log for NVME device:nvme0 namespace-id:ffffffff\n",b""),
            b"SMART overall-health self-assessment test result: PASSED\n",
            b""),
            b"invalid unknown lines\n",
        ):
            with self.subTest(raw=raw[:45]),self.assertRaises(SourceParseError):
                self.parse(raw,"nvme","/dev/nvme0")

    def test_invalid_smartctl_and_numeric_forms_fail(self):
        for raw,command,target in (
            (SMART+b"Serial Number: duplicate\n","smartctl","/dev/sda"),
            (NVME+b"critical_warning : 0x20\n","nvme","/dev/nvme0"),
            (NVME.replace(b"100%",b"1.0%"),"nvme","/dev/nvme0"),
            (NVME.replace(b"3,510",b"3,5,10"),"nvme","/dev/nvme0"),
            (NVME.replace(b"0x02",b"0xZZ"),"nvme","/dev/nvme0"),
            (b"header only, no recognized data\n","smartctl","/dev/sda"),
        ):
            with self.subTest(raw=raw[:45]),self.assertRaises(SourceParseError):
                self.parse(raw,command,target)

    def test_utf8_control_and_bounds_rejected(self):
        for raw in (b"\xff",SMART+b"\x00",SMART+b"\r",SMART*(1024*1024//len(SMART)+1),
                    b"not recognized\n"*514):
            with self.subTest(size=len(raw)),self.assertRaises(SourceParseError):
                self.parse(raw)

    def canonical(self, *,raw=SMART,partial=False,stderr_only=False):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder=Path(temp.name)/RUN
        folder.mkdir(mode=0o700)
        policies={x.source_id:x for x in initial_source_policies()}
        writer=EvidenceWriter(str(folder),RUN)
        original=writer.seal_chunks(policies["SRC-12"],"01","item0001",(b"3907029168\n",)).receipt
        inv=build_attempt(RUN,"SRC-12","01","ALLOW","CAPTURED","BYTES_PRESERVED",
                          evidence=(original,),bytes_count=original.byte_count,
                          source_paths=("/sys/class/block/sda/size",))
        invfile=commit_attempt(str(folder),inv)
        inv_record=RecordedOutcome(
            SimpleNamespace(artifacts=(original,)),invfile)
        stream_name="call0001-stderr" if stderr_only else "call0001-stdout"
        o1_original=writer.seal_chunks(policies["SRC-13"],"01",stream_name,(raw,)).receipt
        consent_time=datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
        witness={
            "run_id":RUN,"source_id":"SRC-13","operation_id":"DEVICE_HEALTH","target":"/dev/sda",
            "consent_run_id":RUN,"consent_source_id":"SRC-13",
            "consent_operation_id":"DEVICE_HEALTH","consent_target":"/dev/sda",
            "consent_issued_utc":consent_time,"impact_acknowledged":True,
            "inventory_source_id":"SRC-12","inventory_source_path":"/sys/class/block/sda/size",
            "inventory_evidence_id":original.evidence_id,
            "approved_argv":list(SRC13_SMART)}
        status="PARTIAL" if partial else "CAPTURED"
        reason="ACQUISITION_ERROR" if partial else "BYTES_PRESERVED"
        attempt=build_attempt(
            RUN,"SRC-13","01","ALLOW",status,reason,
            evidence=(o1_original,),bytes_count=o1_original.byte_count,
            target="/dev/sda",invocation=" ".join(SRC13_SMART),
            exit_code=2 if partial else 0,authorization_provenance=witness)
        attempt_file=commit_attempt(str(folder),attempt)
        o1_record=RecordedOutcome(
            {"disposition":status,"reason":reason,"receipts":(o1_original,)},
            attempt_file,authorization_provenance=witness)
        run=EngineRun(RUN,(CollectorRun("COL-BLOCK",(inv_record,o1_record)),))
        return folder,run,original,o1_original

    def test_captured_verified_smartctl_stdout_creates_private_semantics(self):
        folder,run,inv,original=self.canonical()
        result=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),result)
        statuses=json.loads((folder/"private/status_records.json").read_text())
        self.assertEqual(statuses["status_records"][1]["reason_code"],"OK")
        obs=json.loads((folder/"private/system.json").read_text())["observations"]
        selected=[v for v in obs if v["datum_path"].endswith(".serial_number")]
        self.assertEqual(len(selected),1)
        self.assertEqual(selected[0]["evidence_refs"],[original.evidence_id])
        self.assertEqual((folder/original.private_relative_path).read_bytes(),SMART)
        self.assertEqual(original.sha256,hashlib.sha256(SMART).hexdigest())

    def test_nonzero_smartctl_passed_text_still_partial_incomplete(self):
        folder,run,_,_=self.canonical(partial=True)
        result=build_canonical(folder,run)
        self.assertEqual(validate_canonical(folder),result)
        status=json.loads((folder/"private/status_records.json").read_text())
        o1=status["status_records"][1]
        self.assertEqual((o1["status"],o1["reason_code"]),
                         ("PARTIAL","SOURCE_INCOMPLETE"))
        self.assertIn("ACQUISITION_ERROR",o1["detail"])
        self.assertIn("exit_code=2",o1["detail"])

    def test_diagnostic_only_stderr_cannot_complete_success(self):
        folder,run,_,_=self.canonical(stderr_only=True)
        with self.assertRaises(CanonicalContractError):
            build_canonical(folder,run)
        self.assertFalse((folder/"private/session_manifest.json").exists())

    def test_nonzero_stderr_only_retains_incomplete_not_health_claim(self):
        folder,run,_,_=self.canonical(partial=True,stderr_only=True)
        result=build_canonical(folder,run)
        status=json.loads((folder/"private/status_records.json").read_text())
        self.assertEqual(status["status_records"][1]["reason_code"],
                         "SOURCE_INCOMPLETE")
        self.assertEqual(result["attempt_count"],2)

    def test_raw_only_fallback_on_malformed_captured_stdout(self):
        folder,run,_,_=self.canonical(raw=b"unrecognized reported data\n")
        manifest=build_canonical(folder,run)
        statuses=json.loads((folder/"private/status_records.json").read_text())
        self.assertEqual(statuses["status_records"][1]["reason_code"],"PARSE_FAILED")
        self.assertEqual(validate_canonical(folder),manifest)


if __name__=="__main__":
    unittest.main()
