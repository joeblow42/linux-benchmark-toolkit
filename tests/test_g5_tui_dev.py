"""G5-03 Dialog application-lifetime privilege and IC-02 runner fixtures.

No sudo, interactive Dialog, root execution or physical O1 device IO.
"""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from lbt_g5.tui_dev import OperatorTui, TuiRuntimeError, _MENU, Dialog
from lbt_g5.privileged_session import PrivilegedSessionError


class ScriptedDialog:
    def __init__(self, choices, devices=(), approvals=()):
        self.choices = list(choices)
        self.devices = list(devices)
        self.approvals = list(approvals)
        self.notices = []

    def menu(self, active):
        self.active.append(active) if hasattr(self, "active") else None
        return self.choices.pop(0)

    def device(self):
        return self.devices.pop(0)

    def consent(self, target):
        self.consented.append(target) if hasattr(self, "consented") else None
        return self.approvals.pop(0)

    def notice(self, message, *, title="LBT acquisition"):
        self.notices.append(message)


class FakeHelperContext:
    def __init__(self):
        self.starts=0
        self.stops=0

    def __enter__(self):
        self.starts += 1
        return self

    def __exit__(self, *args):
        self.stops += 1


class TuiSessionContracts(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output=Path(self.tmp.name)/"evidence"

    def _run(self, choices, *, devices=(), approvals=(), sudo=False):
        dialog=ScriptedDialog(choices,devices,approvals)
        dialog.active=[]
        dialog.consented=[]
        helper=FakeHelperContext()
        factory=Mock(return_value=helper)
        calls=[]
        def engine_builder(folder,run_id):
            def invoke(selected,**kwargs):
                calls.append((run_id,selected,kwargs))
                return SimpleNamespace(run_id=run_id,collectors=(),
                                       source_attempt_count=0)
            return SimpleNamespace(run=invoke)
        tui=OperatorTui(self.output,dialog=dialog,
                        helper_factory=factory,engine_factory=engine_builder)
        with patch("lbt_g5.tui_dev.os.geteuid",return_value=os.geteuid()):
            with patch("lbt_g5.tui_dev.sys.stdin.isatty",return_value=True):
                with patch("lbt_g5.tui_dev.sys.stderr.isatty",return_value=True):
                    with patch("lbt_g5.tui_dev._run_id",
                               side_effect=(
                                   "run-2026306182900","run-2026306182901",
                                   "run-2026306182902","run-2026306182903")):
                        # TemporaryDirectory is 0700 already; new evidence root is too.
                        with patch("lbt_g5.tui_dev.verify_acquisition",
                                   return_value=(3,3,1,42,0)):
                            result=tui.run(sudo=sudo)
        return result,dialog,helper,factory,calls,tui

    def test_one_password_session_spans_two_independent_health_runs(self):
        status,dlg,helper,auth,calls,tui=self._run(
            ["enable","health","health","exit"],
            devices=["/dev/sda","/dev/nvme0"], approvals=[True,True])
        self.assertEqual(status,0)
        self.assertEqual(auth.call_count,1)
        self.assertEqual(helper.starts,1)
        self.assertEqual(helper.stops,1)
        self.assertEqual(len(calls),2)
        self.assertEqual(dlg.active,[False,True,True,True])
        self.assertIs(calls[0][2]["privileged_session"],helper)
        self.assertIs(calls[1][2]["privileged_session"],helper)
        self.assertEqual(calls[0][1],("COL-BLOCK",))
        self.assertNotEqual(calls[0][0],calls[1][0])
        for index,target in enumerate(("/dev/sda","/dev/nvme0")):
            request=calls[index][2]["o1_requests"]["SRC-13"]
            self.assertEqual(request.target,target)
            self.assertEqual(request.consent.run_id,calls[index][0])
            self.assertTrue(request.consent.impact_acknowledged)
        self.assertEqual(tui._sessions,2)
        self.assertIsNone(tui._helper)

    def test_sudo_at_tui_startup_is_not_repeated_on_repeated_menu_selection(self):
        _,dlg,helper,auth,calls,_=self._run(
            ["enable","os","memory","exit"],sudo=True)
        self.assertEqual(auth.call_count,1)
        self.assertEqual(helper.starts,1)
        self.assertEqual(helper.stops,1)
        self.assertEqual([x[1] for x in calls],
                         [("COL-OS",),("COL-MEM",)])
        self.assertTrue(all(x[2]["privileged_session"] is helper for x in calls))

    def test_declined_health_does_not_start_sudo_or_acquire(self):
        _,dlg,helper,auth,calls,_=self._run(
            ["health","exit"],devices=["/dev/sda"],approvals=[False])
        self.assertEqual(auth.call_count,0)
        self.assertEqual(calls,[])
        self.assertTrue(any("declined" in n for n in dlg.notices))

    def test_unprivileged_os_acquisition_does_not_request_sudo(self):
        _,dlg,helper,auth,calls,_=self._run(["os","exit"])
        self.assertEqual(auth.call_count,0)
        self.assertEqual(len(calls),1)
        self.assertIsNone(calls[0][2]["privileged_session"])

    def test_consent_without_sudo_session_does_not_acquire(self):
        _,dlg,helper,auth,calls,_=self._run(
            ["health","exit"],devices=["/dev/sda"],approvals=[True])
        self.assertEqual(auth.call_count,0)
        self.assertEqual(calls,[])
        self.assertTrue(any("Enable privileged" in n for n in dlg.notices))

    def test_menu_contains_no_report_viewer_or_diagnostics(self):
        items=dict(_MENU)
        self.assertNotIn("diagnostics",items)
        self.assertNotIn("report",items)
        self.assertNotIn("view",items)

    def test_failed_sudo_is_not_reprompted_while_tui_remains_open(self):
        class FailingHelper:
            def __enter__(self):
                raise PrivilegedSessionError("simulated password failure")
            def __exit__(self,*unused):
                raise AssertionError("helper never started")
        dialog=ScriptedDialog(["enable","enable","os","exit"])
        starts=Mock(return_value=FailingHelper())
        with patch("lbt_g5.tui_dev.os.geteuid",return_value=os.geteuid()):
            with patch("lbt_g5.tui_dev.sys.stdin.isatty",return_value=True):
                with patch("lbt_g5.tui_dev.sys.stderr.isatty",return_value=True):
                    with patch("lbt_g5.tui_dev._run_id",
                               return_value="run-2026306182900"):
                        with patch("lbt_g5.tui_dev.verify_acquisition",
                                   return_value=(4,4,1,8,0)):
                            engine=Mock()
                            engine.return_value.run.return_value=SimpleNamespace(
                                run_id="run-2026306182900",
                                collectors=(),source_attempt_count=0)
                            tui=OperatorTui(self.output,dialog=dialog,
                                            helper_factory=starts,
                                            engine_factory=engine)
                            self.assertEqual(tui.run(),0)
        self.assertEqual(starts.call_count,1)
        self.assertEqual(engine.return_value.run.call_count,1)
        self.assertTrue(any("already attempted" in n for n in dialog.notices))

    def test_dialog_device_path_rejects_injection(self):
        dialog=object.__new__(Dialog)
        dialog.binary="/usr/bin/dialog"
        for name in ("/etc/shadow","/dev/sda;id","/dev/sda/../nvme0"):
            with patch.object(dialog,"_call",return_value=(0,name)):
                with self.assertRaises(TuiRuntimeError):
                    dialog.device()


if __name__=="__main__":
    unittest.main()
