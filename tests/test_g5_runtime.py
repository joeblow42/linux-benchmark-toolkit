"""G5-02 command worker and dispatch fixtures use synthetic processes only.

No real lscpu, lsblk, lspci, ip, O1 source, or device probe is invoked.
"""
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from lbt_g5.safety import SourceRequest,AuthorizationDecision,initial_source_policies
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.runtime import (command_plan,ProbeSlots,SourceCallBudget,
                            _capture_child,execute_source_command)
RUN="run-2026305120000"

class Plans(unittest.TestCase):
    def test_01_exact_whitelisted_argv(self):
        self.assertEqual(command_plan("SRC-05").argv,("lscpu",))
        self.assertEqual(command_plan("SRC-11").argv[:3],("lsblk","--bytes","--json"))
        self.assertEqual(command_plan("SRC-20").argv,("lspci","-nn"))
        self.assertEqual(command_plan("SRC-23",0).argv,("ip","-j","addr","show"))
        self.assertEqual(command_plan("SRC-23",1).argv,("ip","-j","route","show"))

    def test_02_no_o1_or_unvetted_commands(self):
        for sid in ("SRC-13","SRC-15","SRC-18","SRC-21","SRC-28","SRC-02","SRC-27"):
            with self.subTest(sid=sid),self.assertRaises(ValueError):
                command_plan(sid)
        for subcall in (True,-1,2,"0"):
            with self.subTest(subcall=subcall),self.assertRaises(ValueError):
                command_plan("SRC-23",subcall)

    def test_03_slots_limit_two_ordinary(self):
        slots=ProbeSlots()
        with slots.hold("D1"):
            with slots.hold("D0"):
                with self.assertRaises(RuntimeError):
                    with slots.hold("D1"): pass
            with self.assertRaises(RuntimeError):
                with slots.hold("O1"): pass
        with slots.hold("O1"):
            with self.assertRaises(RuntimeError):
                with slots.hold("D0"): pass
            with self.assertRaises(RuntimeError):
                with slots.hold("O1"): pass
        with slots.hold("D1"): pass

    def test_04_invocation_budget_per_subcall(self):
        budget=SourceCallBudget()
        self.assertTrue(budget.begin(RUN,"SRC-23",0))
        self.assertFalse(budget.begin(RUN,"SRC-23",0))
        budget.end(RUN,"SRC-23",5.1)
        self.assertTrue(budget.begin(RUN,"SRC-23",1))
        self.assertFalse(budget.begin(RUN,"SRC-23",2))
        budget.end(RUN,"SRC-23",5)
        self.assertEqual(budget.remaining(RUN,"SRC-23"),0)

class BoundedSyntheticChild(unittest.TestCase):
    def test_05_binary_stdout_and_stderr_exact(self):
        argv=(sys.executable,"-c","import os; os.write(1,b'\\x00\\xffa'); os.write(2,b'\\xfeb')")
        r=_capture_child(argv,64,64,2.0)
        self.assertEqual(r.stdout,b"\x00\xffa")
        self.assertEqual(r.stderr,b"\xfeb")
        self.assertEqual(r.returncode,0)
        self.assertFalse(r.timed_out)

    def test_06_hard_timeout_terminates_child(self):
        argv=(sys.executable,"-c","import time; print('hello',flush=True); time.sleep(20)")
        start=time.monotonic()
        r=_capture_child(argv,100,100,0.20)
        self.assertTrue(r.timed_out)
        self.assertLess(time.monotonic()-start,2.0)
        self.assertLessEqual(len(r.stdout),100)

    def test_07_output_ceiling_terminates_child(self):
        argv=(sys.executable,"-c","import os,time; os.write(1,b'A'*200000);time.sleep(20)")
        r=_capture_child(argv,128,100,2.0)
        self.assertEqual(r.stdout,b"A"*128)
        self.assertTrue(r.exceeded_limit)
        self.assertGreater(r.stdout_omitted_at_least,0)

    def test_08_combined_cap_handles_two_pipes(self):
        argv=(sys.executable,"-c","import os;os.write(1,b'A'*10);os.write(2,b'B'*10)")
        r=_capture_child(argv,20,20,2.0,combined_cap=12)
        self.assertEqual(len(r.stdout)+len(r.stderr),12)
        self.assertTrue(r.exceeded_limit)

    def test_09_nonzero_exit_preserved(self):
        argv=(sys.executable,"-c","import sys;sys.stderr.write('problem');sys.exit(7)")
        r=_capture_child(argv,64,64,2.0)
        self.assertEqual((r.returncode,r.stderr),(7,b"problem"))

class Dispatch(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        run=Path(self.tmp.name)/RUN
        run.mkdir()
        self.writer=EvidenceWriter(str(run),RUN)
        self.slots=ProbeSlots()
        self.calls=SourceCallBudget()

    def allowed(self,request,**kwargs):
        policy={p.source_id:p for p in initial_source_policies()}[request.source_id]
        return AuthorizationDecision(True,"ALLOW","APPROVED_PREFLIGHT_ONLY",policy)

    def request(self,sid="SRC-05",op="LSCPU",**kwargs):
        return SourceRequest(RUN,sid,op,**kwargs)

    def test_10_denial_never_starts_process(self):
        request=self.request("SRC-21","VAINFO")
        with patch("lbt_g5.runtime._capture_child",side_effect=AssertionError("ran")),\
             patch("lbt_g5.safety.os.geteuid",return_value=1000):
            out=execute_source_command(request,0,"01",self.writer,self.slots,self.calls)
        self.assertEqual((out.disposition,out.reason),("DENIED","OPERATOR_AUTH_REQUIRED"))

    def test_11_fixed_plan_and_sealed_stdout_stderr(self):
        from lbt_g5.runtime import TransportCapture
        captured=TransportCapture(b"\xff\x00",b"warning",0,0.1,False,False,0,0)
        with patch("lbt_g5.runtime.decide_source",side_effect=self.allowed),\
             patch("lbt_g5.runtime._resolve_executable",return_value="/usr/bin/lscpu"),\
             patch("lbt_g5.runtime._capture_child",return_value=captured) as child:
            out=execute_source_command(self.request(),0,"01",self.writer,self.slots,self.calls)
        self.assertEqual(out.disposition,"CAPTURED")
        self.assertEqual(out.reason,"BYTES_PRESERVED")
        self.assertEqual(child.call_args.args[0],("/usr/bin/lscpu",))
        path=Path(self.tmp.name)/RUN
        self.assertEqual((path/out.stdout.private_relative_path).read_bytes(),b"\xff\x00")
        self.assertEqual((path/out.stderr.private_relative_path).read_bytes(),b"warning")

    def test_12_repeated_subcall_refused_before_execution(self):
        with patch("lbt_g5.runtime.decide_source",side_effect=self.allowed),\
             patch("lbt_g5.runtime._resolve_executable",return_value="/usr/bin/ip"),\
             patch("lbt_g5.runtime._capture_child") as capture:
            from lbt_g5.runtime import TransportCapture
            capture.return_value=TransportCapture(b"{}",b"",0,0.1,False,False,0,0)
            req=self.request("SRC-23","IP_LOCAL")
            first=execute_source_command(req,0,"01",self.writer,self.slots,self.calls)
            second=execute_source_command(req,0,"02",self.writer,self.slots,self.calls)
        self.assertEqual(first.disposition,"CAPTURED")
        self.assertEqual((second.disposition,second.reason),
                         ("DENIED","SOURCE_CALL_BUDGET_OR_DUPLICATE"))
        self.assertEqual(capture.call_count,1)

    def test_13_non_allowed_source_cannot_invoke_child(self):
        with patch("lbt_g5.runtime.decide_source",side_effect=self.allowed),\
             patch("lbt_g5.runtime._capture_child",side_effect=AssertionError("not allowed")):
            out=execute_source_command(self.request("SRC-28","OFFLINE_METADATA"),0,"01",
                                       self.writer,self.slots,self.calls)
        self.assertEqual((out.disposition,out.reason),("DENIED","NO_SAFE_ADAPTER"))

    def test_14_missing_tool_is_not_fabricated_success(self):
        with patch("lbt_g5.runtime.decide_source",side_effect=self.allowed),\
             patch("lbt_g5.runtime._resolve_executable",return_value=None):
            out=execute_source_command(self.request(),0,"01",self.writer,self.slots,self.calls)
        self.assertEqual((out.disposition,out.reason),("UNAVAILABLE","EXECUTABLE_NOT_FOUND"))

if __name__=='__main__': unittest.main()
