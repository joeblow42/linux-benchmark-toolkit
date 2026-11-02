"""Unprivileged G5-03 sudo session client for installed fixed SRC-13 helper.

--sudo explicitly authenticates once at CLI startup.  No password enters LBT.
The installed root-owned helper has its own hard command/target allowlist.
Never invoke root Python code from the user-writable repository checkout.
"""
import base64
import binascii
import json
import os
import secrets
import select
import shutil
import subprocess
import time

from .privilege_contract import (
    PROTOCOL_VERSION, MAX_HEALTH_BYTES, MAX_HEALTH_SECONDS,
    MAX_RESPONSE_BYTES, HealthSessionContract,
)
from .runtime import TransportCapture

HELPER = "/usr/local/libexec/lbt/lbt-root-helper.py"
PYTHON = "/usr/bin/python3"
SUDO = "/usr/bin/sudo"


class PrivilegedSessionError(RuntimeError):
    pass


def _no_duplicate_json_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise PrivilegedSessionError("duplicate helper response key")
        result[key] = value
    return result


class PrivilegedHealthSession:
    """Private paired pipes with one sudo process for one application session."""

    def __init__(self, *, helper_path=HELPER):
        if helper_path != HELPER:
            raise PrivilegedSessionError("non-installed helper path refused")
        self.tag = secrets.token_hex(16)
        self.contract = HealthSessionContract(self.tag)
        self.proc = None
        self._buffer = b""
        self.sequence = 0

    def _read_frame(self, timeout):
        if self.proc is None or self.proc.stdout is None:
            raise PrivilegedSessionError("helper session unavailable")
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise PrivilegedSessionError("privileged helper response timeout")
            ready, _, _ = select.select([self.proc.stdout.fileno()], [], [],
                                        min(remaining, 0.25))
            if not ready:
                if self.proc.poll() is not None:
                    raise PrivilegedSessionError("privileged helper exited")
                continue
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if not chunk:
                raise PrivilegedSessionError("privileged helper channel closed")
            self._buffer += chunk
            if len(self._buffer) > MAX_RESPONSE_BYTES:
                raise PrivilegedSessionError("oversized privileged reply")
        raw, self._buffer = self._buffer.split(b"\n", 1)
        if not raw or len(raw) > MAX_RESPONSE_BYTES or b"\x00" in raw:
            raise PrivilegedSessionError("invalid helper reply frame")
        try:
            frame = json.loads(raw.decode("utf-8"),
                               object_pairs_hook=_no_duplicate_json_pairs)
        except (ValueError, UnicodeError) as exc:
            raise PrivilegedSessionError("malformed helper response") from exc
        if (type(frame) is not dict or frame.get("protocol") != PROTOCOL_VERSION
                or frame.get("session") != self.tag):
            raise PrivilegedSessionError("unexpected privileged session response")
        return frame

    def start(self):
        if self.proc is not None:
            raise PrivilegedSessionError("already authenticated this session")
        if os.geteuid() == 0:
            raise PrivilegedSessionError("the LBT main process must not be root")
        if not (os.path.isfile(PYTHON) and os.path.isfile(SUDO)
                and os.path.isfile(HELPER)):
            raise PrivilegedSessionError("sudo or installed root-owned helper unavailable")
        try:
            tty_fd = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY)
        except OSError as exc:
            raise PrivilegedSessionError(
                "interactive controlling terminal required for sudo") from exc
        else:
            os.close(tty_fd)
        # sudo -k requests fresh authentication rather than timestamp reuse.
        # sudo reads the password directly from /dev/tty; never via LBT stdin.
        try:
            self.proc = subprocess.Popen(
                (SUDO, "-k", "-p", "[sudo] LBT administrator password: ",
                 "--", PYTHON, "-I", "-S", HELPER, "--session", self.tag),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=None, bufsize=0, close_fds=True,
                cwd="/", env={
                    "PATH":"/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG":"C", "LC_ALL":"C",
                    "TERM":os.environ.get("TERM", "dumb")[:80],
                })
            hello = self._read_frame(90.0)  # human password-entry deadline
            if set(hello) != {"protocol","session","ready"} or hello["ready"] is not True:
                raise PrivilegedSessionError("privileged helper did not initialize")
        except (OSError, PrivilegedSessionError):
            self.close()
            raise
        return self

    def capture(self, request, plan, *, seconds):
        """Execute one previously authorized SRC-13 operation only."""
        if self.proc is None or self.proc.poll() is not None:
            raise PrivilegedSessionError("privileged session not active")
        if (request.source_id != "SRC-13" or plan.source_id != "SRC-13"
                or request.operation_id != plan.operation_id
                or request.target != plan.target
                or request.consent is None
                or not request.consent.impact_acknowledged
                or request.target not in request.trusted_targets):
            raise PrivilegedSessionError("source consent/inventory not authorized")
        self.sequence += 1
        params = dict(protocol=PROTOCOL_VERSION, session=self.tag,
                      sequence=self.sequence, run_id=request.run_id,
                      source_id="SRC-13", operation_id="DEVICE_HEALTH",
                      target=plan.target,
                      max_bytes=min(plan.max_bytes, MAX_HEALTH_BYTES),
                      max_seconds=float(min(seconds, MAX_HEALTH_SECONDS)))
        encoded = json.dumps(params,sort_keys=True,separators=(",",":")).encode()
        self.contract.accept(encoded)
        try:
            self.proc.stdin.write(encoded+b"\n")
            self.proc.stdin.flush()
            response = self._read_frame(params["max_seconds"]+8.0)
            if response.get("sequence") != self.sequence:
                raise PrivilegedSessionError("privileged helper sequence mismatch")
            if "error" in response:
                raise PrivilegedSessionError("privileged helper: "+str(response["error"])[:120])
            required = {"protocol","session","sequence","returncode",
                        "elapsed_seconds","timed_out","exceeded_limit",
                        "stdout_b64","stderr_b64","stdout_omitted_at_least",
                        "stderr_omitted_at_least"}
            if set(response) != required:
                raise PrivilegedSessionError("invalid helper result envelope")
            stdout = base64.b64decode(response["stdout_b64"],validate=True)
            stderr = base64.b64decode(response["stderr_b64"],validate=True)
            if len(stdout)+len(stderr) > params["max_bytes"]:
                raise PrivilegedSessionError("helper output over approved limit")
            if (type(response["timed_out"]) is not bool
                    or type(response["exceeded_limit"]) is not bool
                    or type(response["returncode"]) not in (int, type(None))
                    or type(response["elapsed_seconds"]) not in (int,float)
                    or not 0 <= response["elapsed_seconds"] <= seconds+8.0
                    or type(response["stdout_omitted_at_least"]) is not int
                    or type(response["stderr_omitted_at_least"]) is not int
                    or response["stdout_omitted_at_least"] < 0
                    or response["stderr_omitted_at_least"] < 0):
                raise PrivilegedSessionError("invalid captured result values")
            return TransportCapture(
                stdout,stderr,response["returncode"],response["elapsed_seconds"],
                response["timed_out"],response["exceeded_limit"],
                response["stdout_omitted_at_least"],
                response["stderr_omitted_at_least"])
        except (OSError, ValueError, binascii.Error, PrivilegedSessionError) as exc:
            self.close()
            raise PrivilegedSessionError("privileged request failed") from exc

    def close(self):
        proc, self.proc = self.proc, None
        self._buffer = b""
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()  # helper ends when request pipe reaches EOF
            if proc.poll() is None:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2)
        finally:
            if proc.stdout:
                proc.stdout.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()
