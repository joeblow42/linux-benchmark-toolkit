"""Bounded, opt-in imaging of an operator-supplied unencrypted DVD."""
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

from .core_workloads import IOPressureGuard, MIB, local_filesystem
from .workload_process import capture
from .workload_runtime import Context, Mode, Resources, Unavailable, Workload

SECTOR = 2048
CHUNK = 512 * SECTOR
MAX_DVD_BYTES = 8_600_000_000
DEVICE = re.compile(r"/dev/sr[0-9]+\Z")
BLKGETSIZE64 = 0x80081272  # Linux x86_64 block device byte capacity


@dataclass(frozen=True)
class DVD:
    device: str
    bytes: int
    authorized: bool
    read_retries: int = 1
    wall_seconds: int = 1800

    def __post_init__(self):
        if (self.authorized is not True or not DEVICE.fullmatch(self.device)
                or type(self.bytes) is not int or not 32 * SECTOR <= self.bytes <= MAX_DVD_BYTES
                or self.bytes % SECTOR):
            raise ValueError("DVD imaging requires a confirmed unencrypted disc, drive and capacity")
        if type(self.read_retries) is not int or not 0 <= self.read_retries <= 2:
            raise ValueError("DVD retry limit must be between 0 and 2")
        if type(self.wall_seconds) is not int or not 1 <= self.wall_seconds <= 3600:
            raise ValueError("DVD deadline must be between 1 and 3600 seconds")


def _read(fd, offset, count, retries, events):
    for attempt in range(retries + 1):
        try:
            data = os.pread(fd, count, offset)
            if len(data) != count:
                raise OSError(errno.EIO, "short optical read")
            return data
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
            events.append({"offset": offset, "bytes": count, "attempt": attempt + 1,
                           "will_retry": attempt < retries})
            if attempt == retries:
                return None
    raise AssertionError("unreachable retry state")


def image_disc(fd, size, image, recovery, retries):
    """Image a known device descriptor and compare all bytes to a second read."""
    started = time.monotonic()
    cpu_started = time.process_time()
    source_digest = hashlib.sha256()
    peaks = []
    attempted = []
    verified = False
    copied = 0
    write_seconds = 0.0
    with image.open("xb", buffering=0) as out, recovery.open("x", encoding="utf-8") as log:
        for offset in range(0, size, CHUNK):
            count = min(CHUNK, size - offset)
            tick = time.monotonic()
            events = []
            data = _read(fd, offset, count, retries, events)
            for event in events:
                log.write(json.dumps(event) + "\n")
            attempted.extend(events)
            if data is None:
                break
            peaks.append(count / MIB / max(1e-9, time.monotonic() - tick))
            writing = time.monotonic()
            if out.write(data) != count:
                raise OSError("incomplete DVD image write")
            write_seconds += time.monotonic() - writing
            source_digest.update(data)
            copied += count
        writing = time.monotonic()
        out.flush()
        os.fsync(out.fileno())
        write_seconds += time.monotonic() - writing
        read_seconds = time.monotonic() - started
        read_cpu = time.process_time() - cpu_started
        if copied == size:
            image_digest = hashlib.sha256()
            verification_digest = hashlib.sha256()
            with image.open("rb") as image_data:
                for offset in range(0, size, CHUNK):
                    count = min(CHUNK, size - offset)
                    events = []
                    data = _read(fd, offset, count, retries, events)
                    for event in events:
                        log.write(json.dumps({"phase": "verification", **event}) + "\n")
                    attempted.extend(events)
                    if data is None:
                        break
                    image_digest.update(image_data.read(count))
                    verification_digest.update(data)
                else:
                    verified = image_digest.digest() == verification_digest.digest() == source_digest.digest()
    return {"disc_bytes": size, "copied_bytes": copied, "verified": verified,
            "read_and_write_seconds": read_seconds,
            "read_phase_cpu_seconds": read_cpu, "read_phase_cpu_percent": 100 * read_cpu / read_seconds,
            "copy_average_mib_per_second": copied / MIB / read_seconds,
            "destination_write_mib_per_second": copied / MIB / max(1e-9, write_seconds),
            "peak_read_mib_per_second": max(peaks, default=None),
            "read_errors": len(attempted), "image_sha256": source_digest.hexdigest() if verified else None}


def _worker(config, output):
    owner = output.stat()
    if (os.geteuid() == 0 or output.is_symlink() or not output.is_dir()
            or owner.st_uid != os.geteuid() or owner.st_mode & 0o077):
        raise PermissionError("DVD output requires an owner-only directory and ordinary user")
    try:
        fd = os.open(config.device, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise Unavailable("OPTICAL_DRIVE_MISSING") from None
    except PermissionError:
        raise Unavailable("OPTICAL_DEVICE_NOT_READABLE") from None
    except OSError as error:
        if error.errno == errno.ENOMEDIUM:
            raise Unavailable("OPTICAL_MEDIA_MISSING") from None
        raise
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISBLK(metadata.st_mode) or os.major(metadata.st_rdev) != 11:
            raise Unavailable("OPTICAL_DEVICE_TYPE_UNSUPPORTED")
        try:
            capacity = struct.unpack("=Q", fcntl.ioctl(fd, BLKGETSIZE64, bytes(8)))[0]
        except OSError as error:
            if error.errno == errno.ENOMEDIUM:
                raise Unavailable("OPTICAL_MEDIA_MISSING") from None
            raise
        if capacity == 0:
            raise Unavailable("OPTICAL_MEDIA_MISSING")
        if capacity != config.bytes:
            raise Unavailable("OPTICAL_MEDIA_CAPACITY_MISMATCH")
        partial = output / "disc.partial"
        result = image_disc(fd, capacity, partial, output / "read-events.jsonl", config.read_retries)
        if result["verified"]:
            partial.rename(output / "disc.iso")
        return result
    finally:
        os.close(fd)


def run_dvd(context, config):
    if not os.access(config.device, os.R_OK):
        raise Unavailable("OPTICAL_DEVICE_NOT_READABLE")
    if context.evidence is None:
        raise ValueError("DVD imaging requires a private artifact directory")
    local_filesystem(context.evidence.parent)
    io_guard = IOPressureGuard(context.check_stop)
    guarded = Context(context.scratch, io_guard.poll, context.inventory, context.evidence)
    context.evidence.mkdir(mode=0o700)
    result = capture(guarded, (sys.executable, str(Path(__file__).resolve().with_name("optical_worker.py")),
                               config.device, str(config.bytes), str(config.read_retries),
                               str(context.evidence.resolve()), "--confirmed-unencrypted-dvd"), seconds=config.wall_seconds,
                     output_bytes=64 * 1024)
    if result.stderr:
        (context.evidence / "worker.stderr").write_bytes(result.stderr)
    if result.returncode == 3:
        raise Unavailable(json.loads(result.stdout)["reason"])
    if result.returncode:
        raise RuntimeError("DVD imaging worker failed")
    (context.evidence / "imaging.json").write_bytes(result.stdout)
    outcome = json.loads(result.stdout)
    if not outcome["verified"]:
        raise RuntimeError("DVD image incomplete or verification failed")
    io_guard.poll(force=True)
    return {**outcome, "peak_io_pressure_percent": io_guard.peak}


def dvd_workload(config):
    return Workload("dvd-image", "optical", Mode.EXTENDED,
                    Resources(cpu_workers=1, memory_bytes=8 * MIB, disk_bytes=config.bytes + 4 * MIB),
                    lambda context: run_dvd(context, config), requires_selection=True)
