"""G5-03 privileged SRC-13 worker: install as a root-owned, immutable file.

This module MUST run only from /usr/local/libexec/lbt/lbt-root-helper.py
under '/usr/bin/python3 -I -S' through sudo. It has no imports from the
unprivileged LBT checkout, takes no user-selected executable/argv, and never
writes to the LBT run directory. It sends original stdout/stderr over pipes.

CAUTION: a valid request does not replace application O1 impact consent.
The unprivileged engine must first validate consent and D0 identity.
"""
import base64
import datetime
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

INSTALL_PATH = "/usr/local/libexec/lbt/lbt-root-helper.py"
PROTOCOL = "lbt-root-helper-1"
SESSION_RE = re.compile(r"[0-9a-f]{32}\Z")
RUN_RE = re.compile(r"run-\d{13}\Z")
TARGET_RE = re.compile(r"/dev/(sd[a-z]+|nvme[0-9]+(?:n[0-9]+)?)\Z")
REQUEST_MAX = 4096
STDOUT_MAX = 12 * 1024 * 1024
OUTPUT_MAX = 8 * 1024 * 1024
SECONDS_MAX = 12.0
MAX_COUNT = 32
MAX_RUN_BYTES = 32 * 1024 * 1024
MAX_RUN_SECONDS = 60.0
FIELDS = frozenset(("protocol","session","sequence","run_id","source_id",
                    "operation_id","target","max_bytes","max_seconds"))
_TOOLS = {
    "smartctl": ("/usr/sbin/smartctl", "/usr/bin/smartctl"),
    "nvme": ("/usr/sbin/nvme", "/usr/bin/nvme"),
}


class Rejected(ValueError):
    pass


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Rejected("duplicate JSON key")
        value[key] = item
    return value


def _valid_run_id(value):
    if type(value) is not str or not RUN_RE.fullmatch(value):
        return False
    try:
        date = datetime.datetime.strptime(value[4:], "%Y%j%H%M%S")
        return date.strftime("%Y%j%H%M%S") == value[4:]
    except ValueError:
        return False


def _validate(raw, tag, next_sequence, counts):
    if type(raw) is not bytes or len(raw) == 0 or len(raw) > REQUEST_MAX:
        raise Rejected("invalid frame size")
    if b"\x00" in raw or b"\n" in raw or b"\r" in raw:
        raise Rejected("multiple/invalid frames")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise Rejected("invalid JSON frame") from exc
    if type(obj) is not dict or set(obj) != FIELDS:
        raise Rejected("missing or unexpected keys")
    if (obj["protocol"] != PROTOCOL or obj["session"] != tag
            or obj["source_id"] != "SRC-13"
            or obj["operation_id"] != "DEVICE_HEALTH"):
        raise Rejected("operation not approved")
    seq = obj["sequence"]
    run = obj["run_id"]
    dev = obj["target"]
    size = obj["max_bytes"]
    seconds = obj["max_seconds"]
    if (type(seq) is not int or seq != next_sequence
            or not _valid_run_id(run)
            or type(dev) is not str or not TARGET_RE.fullmatch(dev)):
        raise Rejected("invalid sequence, run or device")
    if (type(size) is not int or not 0 < size <= OUTPUT_MAX
            or type(seconds) not in (float, int)
            or not 0 < seconds <= SECONDS_MAX):
        raise Rejected("invalid operation budget")
    if counts.get(run, 0) >= MAX_COUNT:
        raise Rejected("run health-query count exhausted")
    return obj


def _verify_installed_code():
    """Never elevate a user-writable checkout or user-owned parent directory."""
    if os.geteuid() != 0 or os.path.realpath(__file__) != INSTALL_PATH:
        raise Rejected("must run as installed root-only helper")
    for path in ("/usr", "/usr/local", "/usr/local/libexec",
                 "/usr/local/libexec/lbt", INSTALL_PATH):
        info = os.lstat(path)
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise Rejected("unsafe root code location or permissions")
    if not stat.S_ISREG(os.stat(INSTALL_PATH).st_mode):
        raise Rejected("helper is not regular file")


def _resolve_fixed_executable(name):
    for candidate in _TOOLS[name]:
        resolved = os.path.realpath(candidate)
        if not resolved.startswith("/usr/"):
            continue
        try:
            info = os.stat(resolved)
        except OSError:
            continue
        if (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and not (info.st_mode & 0o022)
                and os.access(resolved, os.X_OK)):
            return resolved
    raise Rejected("approved drive-health utility not installed")


def _device_kind(path):
    """Preflight device; never open it outside an individually approved query."""
    if not TARGET_RE.fullmatch(path):
        raise Rejected("unknown device")
    # /dev is system owned; the caller cannot create a replacement node here.
    dev = os.lstat("/dev")
    if dev.st_uid != 0 or dev.st_mode & 0o022:
        raise Rejected("unsafe device directory")
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise Rejected("device unavailable") from exc
    nvme = re.fullmatch(r"nvme[0-9]+", path.rsplit("/", 1)[-1])
    if nvme:
        if not stat.S_ISCHR(st.st_mode):
            raise Rejected("NVMe controller is not character device")
        if not os.path.exists("/sys/class/nvme/" + nvme.group()):
            raise Rejected("NVMe controller not in sysfs")
    elif not stat.S_ISBLK(st.st_mode):
        raise Rejected("target is not block device")
    if not st.st_rdev:
        raise Rejected("invalid device identity")
    return "nvme" if "/nvme" in path else "smartctl"


def _stop(proc):
    # The direct child may have exited while descendants still hold pipes.
    # Kill the entire dedicated group even after its leader has exited.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        if proc.poll() is None:
            proc.kill()


def _run_capture(argv, byte_limit, seconds):
    """Fixed-command process group with bounded stdout/stderr and wall time."""
    started = time.monotonic()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        start_new_session=True, cwd="/",
        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C", "LC_ALL":"C"})
    values = {"stdout":bytearray(), "stderr":bytearray()}
    omitted = {"stdout":0, "stderr":0}
    limited = False
    timeout = False
    selector = selectors.DefaultSelector()
    try:
        for label, stream in (("stdout",proc.stdout),("stderr",proc.stderr)):
            os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,label)
        while selector.get_map():
            remain = seconds - (time.monotonic()-started)
            if remain <= 0:
                timeout = True
                _stop(proc)
                break
            for key,_ in selector.select(min(0.1,remain)):
                label = key.data
                try:
                    block = os.read(key.fileobj.fileno(),65536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                cap = max(0, byte_limit-sum(map(len,values.values())))
                keep = min(cap,len(block))
                values[label].extend(block[:keep])
                if keep < len(block):
                    limited = True
                    omitted[label] += len(block)-keep
                    _stop(proc)
                    break
            if limited:
                break
        if proc.poll() is None:
            if seconds-(time.monotonic()-started) <= 0:
                timeout = True
            if timeout or limited:
                _stop(proc)
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            _stop(proc)
            proc.wait(timeout=0.5)
    finally:
        selector.close()
        for pipe in (proc.stdout,proc.stderr):
            pipe.close()
        if proc.poll() is None:
            _stop(proc)
            proc.wait(timeout=1)
    return {
        "returncode": proc.returncode,
        "elapsed_seconds": time.monotonic()-started,
        "timed_out": timeout,
        "exceeded_limit": limited,
        "stdout_b64": base64.b64encode(values["stdout"]).decode("ascii"),
        "stderr_b64": base64.b64encode(values["stderr"]).decode("ascii"),
        "stdout_omitted_at_least": omitted["stdout"],
        "stderr_omitted_at_least": omitted["stderr"],
    }


def _execute_health(msg):
    kind = _device_kind(msg["target"])
    binary = _resolve_fixed_executable(kind)
    if kind == "smartctl":
        argv = (binary,"-i","-H",msg["target"])
    else:
        argv = (binary,"smart-log",msg["target"])
    return _run_capture(argv, msg["max_bytes"],float(msg["max_seconds"]))


def _send(pipe, frame):
    encoded = (json.dumps(frame,sort_keys=True,separators=(",",":"),
                          allow_nan=False)+"\n").encode("utf-8")
    if len(encoded) > STDOUT_MAX:
        raise Rejected("response frame exceeds maximum")
    pipe.write(encoded)
    pipe.flush()


def _limit_run_request(msg, usage):
    """Independently enforce cumulative G4-07 SRC-13 limits per run.

    An already exhausted run never executes a device command. The original
    per-target bound remains in effect in addition to the run-wide budget.
    """
    used = usage.get(msg["run_id"], (0, 0.0))
    remaining_bytes = MAX_RUN_BYTES - used[0]
    remaining_seconds = MAX_RUN_SECONDS - used[1]
    if remaining_bytes <= 0 or remaining_seconds <= 0:
        raise Rejected("RUN_BUDGET_EXHAUSTED")
    limited = dict(msg)
    limited["max_bytes"] = min(msg["max_bytes"], remaining_bytes)
    limited["max_seconds"] = min(float(msg["max_seconds"]), remaining_seconds)
    return limited


def serve(tag, source, sink, executor=None):
    """Bounded line protocol. Injectable executor for tests; no runtime injection."""
    if type(tag) is not str or not SESSION_RE.fullmatch(tag):
        raise Rejected("invalid helper session tag")
    execute = _execute_health if executor is None else executor
    _send(sink, {"protocol": PROTOCOL,"session":tag,"ready":True})
    sequence = 1
    counts = {}
    run_usage = {}
    while True:
        raw = source.readline(REQUEST_MAX+2)
        if raw == b"":
            return 0
        if not raw.endswith(b"\n") or len(raw)>REQUEST_MAX+1:
            _send(sink,{"protocol":PROTOCOL,"session":tag,"error":"INVALID_FRAME"})
            return 64
        try:
            msg = _validate(raw[:-1],tag,sequence,counts)
        except Rejected as exc:
            _send(sink,{"protocol":PROTOCOL,"session":tag,"error":str(exc)})
            return 65
        # Reserve before touching any device; even a rejected budget consumes
        # its sequence number, so the caller cannot retry the same request.
        sequence += 1
        counts[msg["run_id"]] = counts.get(msg["run_id"],0)+1
        try:
            bounded = _limit_run_request(msg, run_usage)
        except Rejected:
            _send(sink,{"protocol":PROTOCOL,"session":tag,
                        "sequence":msg["sequence"],
                        "error":"RUN_BUDGET_EXHAUSTED"})
            continue
        started = time.monotonic()
        try:
            captured = execute(bounded)
        except (OSError, Rejected) as exc:
            elapsed = max(0.0,time.monotonic()-started)
            previous = run_usage.get(msg["run_id"],(0,0.0))
            run_usage[msg["run_id"]] = (previous[0],previous[1]+elapsed)
            _send(sink,{"protocol":PROTOCOL,"session":tag,
                       "sequence":msg["sequence"],"error":type(exc).__name__})
            continue
        # The installed executor controls these fields; account for actual
        # original bytes and monotonic elapsed time even when no data returns.
        # The fixture executor has the same contract for offline tests.
        original_bytes = sum(len(base64.b64decode(captured[field]))
                             for field in ("stdout_b64","stderr_b64"))
        elapsed = max(float(captured["elapsed_seconds"]),
                      max(0.0,time.monotonic()-started))
        previous = run_usage.get(msg["run_id"],(0,0.0))
        run_usage[msg["run_id"]] = (
            previous[0]+original_bytes, previous[1]+elapsed)
        _send(sink, dict(protocol=PROTOCOL, session=tag,
                         sequence=msg["sequence"], **captured))


def main(argv):
    if len(argv)!=2 or argv[0]!="--session":
        return 64
    _verify_installed_code()
    return serve(argv[1],sys.stdin.buffer,sys.stdout.buffer)


if __name__=="__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (Rejected, OSError):
        raise SystemExit(77)
