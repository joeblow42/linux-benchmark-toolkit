"""Launch a bounded benchmark subprocess and reap it on timeout or cancellation."""
from dataclasses import dataclass
import math
import os
import selectors
import shutil
import signal
import subprocess
import time

from .workload_runtime import Unavailable


class ProcessLimit(Exception):
    """A workload tool reached a declared wall time or output limit."""

    def __init__(self, reason, buffers):
        super().__init__(reason)
        self.stdout = bytes(buffers["stdout"])
        self.stderr = bytes(buffers["stderr"])


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    seconds: float


def tool_path(name):
    path = shutil.which(name)
    if path is None:
        raise Unavailable(f"{name.upper()}_NOT_FOUND")
    return os.path.abspath(path)


def capture(context, argv, *, seconds, output_bytes=1024 * 1024):
    if not math.isfinite(seconds) or seconds <= 0 or output_bytes <= 0:
        raise ValueError("process bounds must be positive and finite")
    context.check_stop()
    started = time.monotonic()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    with subprocess.Popen(argv, cwd=context.scratch, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                          env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}) as process:
        try:
            with selectors.DefaultSelector() as selector:
                for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map() or process.poll() is None:
                    context.check_stop()
                    remaining = seconds - (time.monotonic() - started)
                    if remaining <= 0:
                        raise ProcessLimit("COMMAND_DEADLINE", buffers)
                    for key, _ in selector.select(min(.1, remaining)):
                        try:
                            data = os.read(key.fd, 65536)
                        except BlockingIOError:
                            continue
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        if sum(map(len, buffers.values())) + len(data) > output_bytes:
                            raise ProcessLimit("COMMAND_OUTPUT_LIMIT", buffers)
                        buffers[key.data].extend(data)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            raise
    return ProcessResult(process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]),
                         time.monotonic() - started)
