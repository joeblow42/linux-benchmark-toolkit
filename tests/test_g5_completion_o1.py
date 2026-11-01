import unittest
from lbt_g5.safety import SourceRequest
from lbt_g5.o1 import plan_optional
class O1Refusals(unittest.TestCase):
    def test_missing_consent_denies_all_o1(self):
        run='run-2026305120000'
        for source,op,target in (('SRC-13','DEVICE_HEALTH','/dev/sda'),('SRC-18','OPTICAL_MEDIA','/dev/sr0'),('SRC-21','VAINFO','/dev/dri/renderD128')):
            with self.subTest(source=source),self.assertRaises(PermissionError):
                plan_optional(SourceRequest(run,source,op,target=target))


class O1SyntheticExecution(unittest.TestCase):
    def test_optical_success_preserves_original_and_exit_evidence(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from lbt_g5.safety import AuthorizationDecision,initial_source_policies
        from lbt_g5.o1 import OptionalSourcePlan
        from lbt_g5.o1_execution import execute_optional
        from lbt_g5.runtime import ProbeSlots,SourceCallBudget,TransportCapture
        from lbt_g5.evidence import EvidenceWriter

        run="run-2026305120000"
        policy=next(p for p in initial_source_policies() if p.source_id=="SRC-18")
        auth=AuthorizationDecision(True,"ALLOW","APPROVED_PREFLIGHT_ONLY",policy)
        plan=OptionalSourcePlan("SRC-18",policy.operation_id,"/dev/sr0",
             ("sg_get_config","--readonly","--current","/dev/sr0"),
             4*1024*1024,8,"device capability read")
        captured=TransportCapture(b"DVD-ROM current\n",b"",0,.12,
                                   False,False,0,0)
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/run
            folder.mkdir()
            writer=EvidenceWriter(str(folder),run)
            request=SourceRequest(run,"SRC-18",policy.operation_id,target="/dev/sr0")
            with patch("lbt_g5.safety.decide_source",return_value=auth),\
                 patch("lbt_g5.o1_execution.plan_optional",return_value=plan),\
                 patch("lbt_g5.o1_execution._resolve_executable",
                       return_value="/usr/bin/sg_get_config"),\
                 patch("lbt_g5.o1_execution._capture_child",return_value=captured):
                outcome=execute_optional(request,"01",0,writer,ProbeSlots(),
                                         SourceCallBudget())
            self.assertEqual(outcome["disposition"],"CAPTURED")
            self.assertEqual(outcome["exit_code"],0)
            self.assertFalse(outcome["timed_out"])
            self.assertEqual(outcome["elapsed_seconds"],.12)
            self.assertEqual(len(outcome["receipts"]),1)
            item=outcome["receipts"][0]
            self.assertEqual((folder/item.private_relative_path).read_bytes(),
                             b"DVD-ROM current\n")

    def test_nonzero_exit_is_not_reported_as_success(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from lbt_g5.safety import AuthorizationDecision,initial_source_policies
        from lbt_g5.o1 import OptionalSourcePlan
        from lbt_g5.o1_execution import execute_optional
        from lbt_g5.runtime import ProbeSlots,SourceCallBudget,TransportCapture
        from lbt_g5.evidence import EvidenceWriter

        run="run-2026305120000"
        policy=next(p for p in initial_source_policies() if p.source_id=="SRC-18")
        auth=AuthorizationDecision(True,"ALLOW","APPROVED_PREFLIGHT_ONLY",policy)
        plan=OptionalSourcePlan("SRC-18",policy.operation_id,"/dev/sr0",
             ("sg_get_config","--readonly","--current","/dev/sr0"),
             4*1024*1024,8,"device capability read")
        captured=TransportCapture(b"",b"device permission denied\n",2,.1,
                                   False,False,0,0)
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/run
            folder.mkdir()
            writer=EvidenceWriter(str(folder),run)
            request=SourceRequest(run,"SRC-18",policy.operation_id,target="/dev/sr0")
            with patch("lbt_g5.safety.decide_source",return_value=auth),\
                 patch("lbt_g5.o1_execution.plan_optional",return_value=plan),\
                 patch("lbt_g5.o1_execution._resolve_executable",
                       return_value="/usr/bin/sg_get_config"),\
                 patch("lbt_g5.o1_execution._capture_child",return_value=captured):
                outcome=execute_optional(request,"01",0,writer,ProbeSlots(),
                                         SourceCallBudget())
            self.assertEqual(outcome["disposition"],"PARTIAL")
            self.assertEqual(outcome["exit_code"],2)
            self.assertEqual(outcome["reason"],"ACQUISITION_ERROR")
