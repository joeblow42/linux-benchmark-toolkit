"""G5-03 root helper protocol/transport tests with no privilege or device I/O."""
import base64
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lbt_g5.privileged_session import PrivilegedHealthSession, PrivilegedSessionError
from lbt_g5.privilege_contract import PROTOCOL_VERSION
from lbt_g5.safety import SourceConsent, SourceRequest
from datetime import datetime, timezone
from lbt_g5.o1 import OptionalSourcePlan

FILE=Path(__file__).resolve().parents[1]/"packaging"/"lbt_root_helper.py"
spec=importlib.util.spec_from_file_location("testable_standalone_lbt_helper",FILE)
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
TAG="0123456789abcdef0123456789abcdef"
RUN="run-2026306163727"


def msg(sequence=1, **kwargs):
    fields=dict(protocol=PROTOCOL_VERSION, session=TAG,sequence=sequence,
                run_id=RUN,source_id="SRC-13",operation_id="DEVICE_HEALTH",
                target="/dev/sda",max_bytes=4096,max_seconds=2.0)
    fields.update(kwargs)
    return (json.dumps(fields,separators=(",",":"))+"\n").encode("utf-8")


class RootHelperFixtures(unittest.TestCase):
    def test_two_health_queries_one_session(self):
        incoming=io.BytesIO(msg()+msg(sequence=2,target="/dev/nvme0"))
        output=io.BytesIO()
        called=[]
        def fake(op):
            called.append(op["target"])
            return dict(
                returncode=0, elapsed_seconds=0.03, timed_out=False,
                exceeded_limit=False,
                stdout_b64=base64.b64encode(b"device original bytes").decode(),
                stderr_b64="",
                stdout_omitted_at_least=0,stderr_omitted_at_least=0)
        result=helper.serve(TAG,incoming,output,executor=fake)
        self.assertEqual(result,0)
        response=[json.loads(x) for x in output.getvalue().splitlines()]
        self.assertEqual(response[0]["ready"], True)
        self.assertEqual([x["sequence"] for x in response[1:]], [1,2])
        self.assertEqual(called,["/dev/sda","/dev/nvme0"])

    def test_rejected_operation_never_reaches_executor(self):
        outgoing=io.BytesIO()
        called=[]
        result=helper.serve(TAG,io.BytesIO(msg(source_id="SRC-18")),
                            outgoing,executor=lambda m: called.append(m))
        self.assertEqual(result,65)
        self.assertEqual(called,[])
        self.assertIn(b"error",outgoing.getvalue())

    def test_root_contract_denies_injection_and_duplicates(self):
        for payload in (msg(target="/etc/shadow"),msg(target="/dev/sda;id"),
                        msg(max_bytes=999999999),msg(sequence=3),
                        msg(override_argv=["sh","-c","id"]),
                        b'{"protocol":"lbt-root-helper-1","protocol":"override"}\n'):
            with self.subTest(payload=payload[:60]):
                out=io.BytesIO()
                code=helper.serve(TAG,io.BytesIO(payload),out,
                    executor=lambda m: self.fail("untrusted helper execution"))
                self.assertNotEqual(code,0)

    def test_frame_size_rejected_before_execution(self):
        out=io.BytesIO()
        result=helper.serve(TAG,io.BytesIO(b"x"*4100+b"\n"),out,
                            executor=lambda x:self.fail("unexpected execution"))
        self.assertEqual(result,64)

    def test_sudo_client_cannot_start_without_installed_helper(self):
        with patch("lbt_g5.privileged_session.os.path.isfile",return_value=False):
            with self.assertRaises(PrivilegedSessionError):
                PrivilegedHealthSession().start()

    def test_no_arbitrary_helper_location(self):
        with self.assertRaises(PrivilegedSessionError):
            PrivilegedHealthSession(helper_path="/tmp/user-owned-helper.py")

    def test_two_privileged_client_captures_reuse_one_pipe_session(self):
        """Full client/server wire path using a fake executor, never sudo/root."""
        client=PrivilegedHealthSession()
        req_in, req_out = os.pipe()
        rep_in, rep_out = os.pipe()
        called=[]
        thread_errors=[]
        def execute(message):
            called.append(message["target"])
            raw=b"test-only original "+message["target"].encode()
            return dict(returncode=0,elapsed_seconds=.05,
                        timed_out=False,exceeded_limit=False,
                        stdout_b64=base64.b64encode(raw).decode(),
                        stderr_b64="",stdout_omitted_at_least=0,
                        stderr_omitted_at_least=0)
        def server():
            try:
                with os.fdopen(req_in,"rb",buffering=0) as source:
                    with os.fdopen(rep_out,"wb",buffering=0) as sink:
                        helper.serve(client.tag,source,sink,executor=execute)
            except BaseException as error:
                thread_errors.append(error)
        worker=threading.Thread(target=server,daemon=True)
        worker.start()
        read_pipe=os.fdopen(rep_in,"rb",buffering=0)
        write_pipe=os.fdopen(req_out,"wb",buffering=0)
        client.proc=SimpleNamespace(
            stdin=write_pipe,stdout=read_pipe,
            poll=lambda:None,wait=lambda timeout=None:worker.join(timeout))
        try:
            self.assertTrue(client._read_frame(2.0)["ready"])
            for target in ("/dev/sda","/dev/nvme0"):
                consent=SourceConsent(RUN,"SRC-13","DEVICE_HEALTH",target,
                                      datetime.now(timezone.utc),True)
                req=SourceRequest(RUN,"SRC-13","DEVICE_HEALTH",target=target,
                                  consent=consent,
                                  trusted_targets=frozenset((target,)))
                plan=OptionalSourcePlan("SRC-13","DEVICE_HEALTH",target,
                    ("smartctl","-i","-H",target),4096,2,"may wake drive")
                capture=client.capture(req,plan,seconds=2.0)
                self.assertEqual(capture.stdout,
                                 b"test-only original "+target.encode())
            self.assertEqual(called,["/dev/sda","/dev/nvme0"])
            self.assertEqual(client.sequence,2)
        finally:
            client.close()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(thread_errors,[])

    def test_host_cli_sudo_flag_uses_one_session_at_startup(self):
        from lbt_g5.host_smoke import main
        from lbt_g5.engine import EngineRun
        from unittest.mock import Mock
        if os.geteuid()==0:
            self.skipTest("main toolkit may not run as root")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("lbt_g5.host_smoke.PrivilegedHealthSession") as session:
                session.return_value.__enter__.return_value=Mock()
                with patch("lbt_g5.host_smoke.UnifiedCollectorEngine") as engine:
                    engine.return_value.run.return_value=EngineRun(RUN,())
                    self.assertEqual(main(["--sudo","--collectors","COL-OS",
                                           "--output-root",tmp]),0)
                    self.assertEqual(session.return_value.__enter__.call_count,1)
                    self.assertEqual(engine.return_value.run.call_count,1)

    def test_cli_rejects_drive_without_sudo_and_consent(self):
        from lbt_g5.host_smoke import main
        with self.assertRaises(SystemExit):
            main(["--device-health","/dev/sda","--acknowledge-drive-impact"])
        with self.assertRaises(SystemExit):
            main(["--sudo","--device-health","/dev/sda"])
        with self.assertRaises(SystemExit):
            main(["--sudo","--device-health","/dev/sda",
                  "--acknowledge-drive-impact","--collectors","COL-MEM"])

    def test_unprivileged_client_can_parse_real_protocol_fixture(self):
        client=PrivilegedHealthSession()
        payload=(json.dumps({"protocol":PROTOCOL_VERSION,"session":client.tag,
                             "ready":True})+"\n").encode()
        read_fd,write_fd=os.pipe()
        try:
            os.write(write_fd,payload)
            os.close(write_fd)
            with os.fdopen(read_fd,"rb",buffering=0) as pipe:
                client.proc=SimpleNamespace(stdout=pipe,poll=lambda:None)
                self.assertEqual(client._read_frame(1.0)["ready"],True)
        finally:
            client.proc=None



if __name__=="__main__":
    unittest.main()
