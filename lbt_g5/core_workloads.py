"""RP-07 short CPU, memory and filesystem workloads for the shared runtime."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import random
import re
import stat
import threading
import time

from .local_space import LOCAL_TYPES, _unescape
from .workload_runtime import Mode, Resources, Unavailable, Workload

MIB = 1024 * 1024
BLOCK = 4096
_HASH_INPUT = bytes(64 * 1024)


@dataclass(frozen=True)
class ShortParameters:
    cpu_seconds: float = 1.0
    cpu_workers: int = 4
    memory_bytes: int = 8 * MIB
    memory_seconds: float = 1.0
    storage_bytes: int = 16 * MIB
    random_operations: int = 64

    def __post_init__(self):
        for value in (self.cpu_seconds, self.memory_seconds):
            if type(value) not in (int, float) or not 0.05 <= value <= 3:
                raise ValueError("short sample length must be between 0.05 and 3 seconds")
        for name, lo, hi in (("cpu_workers", 1, 64), ("memory_bytes", MIB, 64 * MIB),
                             ("storage_bytes", BLOCK, 128 * MIB),
                             ("random_operations", 1, 1024)):
            value = getattr(self, name)
            if type(value) is not int or not lo <= value <= hi:
                raise ValueError(f"{name} outside short workload bounds")
        if self.storage_bytes % BLOCK:
            raise ValueError("storage_bytes must be divisible by 4096")


def _fields(path, *, line=None):
    for row in Path(path).read_text().splitlines():
        fields = row.split()
        if not fields:
            continue
        if line is None:
            key, value = fields[:2]
            yield key.rstrip(":"), value
        elif fields[0] == line:
            yield from (part.split("=", 1) for part in fields[1:])
            return


def pressure(resource):
    try:
        values = dict(_fields(f"/proc/pressure/{resource}", line="some"))
        return {"avg10_percent": float(values["avg10"]), "total_us": int(values["total"])}
    except (OSError, KeyError, ValueError):
        return None


def check_pressure(resource, ceiling):
    observed = pressure(resource)
    if observed is None:
        raise Unavailable(f"{resource.upper()}_PRESSURE_UNAVAILABLE")
    if observed["avg10_percent"] >= ceiling:
        raise Unavailable(f"PREEXISTING_{resource.upper()}_PRESSURE")
    return observed


def _hash_sample(context, workers, seconds):
    stop = threading.Event()
    barrier = threading.Barrier(workers + 1)
    deadline = 0.0

    def measure():
        count = 0
        barrier.wait(timeout=5)
        while not stop.is_set() and time.monotonic() < deadline:
            hashlib.sha256(_HASH_INPUT).digest()
            count += 1
        return count

    with ThreadPoolExecutor(max_workers=workers) as executor:
        try:
            futures = [executor.submit(measure) for _ in range(workers)]
            started = time.monotonic()
            deadline = started + seconds
            barrier.wait(timeout=5)
            while not all(future.done() for future in futures):
                context.check_stop()
                stop.wait(0.025)
            elapsed = time.monotonic() - started
            count = sum(future.result() for future in futures)
        finally:
            stop.set()
            barrier.abort()
    if not count:
        raise Unavailable("NO_CPU_SAMPLE")
    return {"workers": workers, "operations": count, "elapsed_seconds": elapsed,
            "operations_per_second": count / elapsed}


def run_cpu(context, parameters):
    check_pressure("cpu", 25)
    affinity = len(os.sched_getaffinity(0))
    workers = min(affinity, parameters.cpu_workers)
    single = _hash_sample(context, 1, parameters.cpu_seconds)
    parallel = _hash_sample(context, workers, parameters.cpu_seconds)
    return {"algorithm": "sha256", "operation_bytes": len(_HASH_INPUT),
            "available_affinity_workers": affinity, "worker_cap": parameters.cpu_workers,
            "single": single, "parallel": parallel,
            "all_affinity_workers_used": workers == affinity,
            "scaling_ratio": parallel["operations_per_second"] / single["operations_per_second"]}


def _swap_counts():
    try:
        values = dict(_fields("/proc/vmstat"))
        return tuple(int(values[key]) for key in ("pswpin", "pswpout"))
    except (OSError, KeyError, ValueError):
        return None


def run_memory(context, parameters):
    before = check_pressure("memory", 10)
    try:
        free = int(dict(_fields("/proc/meminfo"))["MemAvailable"]) * 1024
    except (OSError, KeyError, ValueError):
        raise Unavailable("MEMORY_CAPACITY_UNAVAILABLE") from None
    size = parameters.memory_bytes
    if free < size * 16:
        raise Unavailable("MEMORY_HEADROOM")
    initial_swap = _swap_counts()
    try:
        data = bytearray(b"m") * size
        target = bytearray(size)
    except MemoryError:
        raise Unavailable("MEMORY_ALLOCATION_FAILED") from None
    started = time.monotonic()
    copies = 0
    while time.monotonic() - started < parameters.memory_seconds:
        context.check_stop()
        target[:] = data
        copies += 1
    elapsed = time.monotonic() - started
    after = pressure("memory")
    final_swap = _swap_counts()
    return {"operation": "buffer_copy", "working_set_bytes": 2 * size,
            "bytes_copied": copies * size, "elapsed_seconds": elapsed,
            "mib_per_second": copies * size / MIB / elapsed,
            "host_pressure_before": before, "host_pressure_after": after,
            "host_swap_pages_in": final_swap[0] - initial_swap[0] if initial_swap and final_swap else None,
            "host_swap_pages_out": final_swap[1] - initial_swap[1] if initial_swap and final_swap else None}


def _usb_block_source(source):
    device = Path(source)
    if device.parent != Path("/dev"):
        return False
    try:
        metadata = device.stat(follow_symlinks=False)
        if not stat.S_ISBLK(metadata.st_mode):
            return False
        number = f"{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}"
        sys_device = (Path("/sys/dev/block") / number).resolve(strict=True)
    except OSError:
        return False
    return any(re.fullmatch(r"usb[0-9]+", part) for part in sys_device.parts)


def local_filesystem(directory):
    try:
        rows = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        raise Unavailable("MOUNT_INVENTORY_UNAVAILABLE") from None
    directory = directory.resolve()
    candidates = []
    for row in rows:
        left, sep, right = row.partition(" - ")
        fields = left.split()
        filesystem_fields = right.split()
        if not sep or len(fields) < 5 or len(filesystem_fields) < 2:
            continue
        mount = Path(_unescape(fields[4]))
        if directory.is_relative_to(mount):
            filesystem, source = filesystem_fields[:2]
            candidates.append((len(mount.parts), filesystem, _unescape(source)))
    if not candidates:
        raise Unavailable("FILESYSTEM_UNAVAILABLE")
    # Stacked mounts of equal depth are recorded in mountinfo order.
    _, filesystem, source = max(
        enumerate(candidates), key=lambda entry: (entry[1][0], entry[0]))[1]
    if filesystem not in LOCAL_TYPES and not (
            filesystem in ("fuseblk", "ntfs3") and _usb_block_source(source)):
        raise Unavailable("LOCAL_STORAGE_REQUIRED")
    return filesystem


def _write_exact(file, data, offset):
    if os.pwrite(file, data, offset) != len(data):
        raise OSError("incomplete write")


def _read_exact(file, size, offset):
    value = os.pread(file, size, offset)
    if len(value) != size:
        raise OSError("incomplete read")
    return value


def _rate(started, total):
    elapsed = time.monotonic() - started
    return {"bytes": total, "elapsed_seconds": elapsed,
            "mib_per_second": total / MIB / elapsed}


def _random_sample(context, file, offsets, operation):
    latencies = []
    for offset in offsets:
        context.check_stop()
        started = time.monotonic_ns()
        operation(file, offset)
        latencies.append(max(1, time.monotonic_ns() - started) / 1000)
    ordered = sorted(latencies)
    return {"operations": len(ordered), "iops": len(ordered) * 1e6 / sum(ordered),
            "mean_latency_us": sum(ordered) / len(ordered),
            "p95_latency_us": ordered[math.ceil(len(ordered) * 0.95) - 1]}


def run_storage(context, parameters):
    filesystem = local_filesystem(context.scratch)
    check_pressure("io", 25)
    size = parameters.storage_bytes
    # Generate once outside timed regions. Do not write sparse or zero-fill data.
    pattern = random.Random(66).randbytes(min(size, MIB))
    offsets = range(0, size, len(pattern))
    rng = random.Random(67)
    random_offsets = [rng.randrange(size // BLOCK) * BLOCK
                      for _ in range(parameters.random_operations)]
    with (context.scratch / "bench-data").open("xb", buffering=0) as stream:
        started = time.monotonic()
        for offset in offsets:
            context.check_stop()
            _write_exact(stream.fileno(), pattern[:size - offset], offset)
        os.fsync(stream.fileno())
        sequential_write = _rate(started, size)
    with (context.scratch / "bench-data").open("r+b", buffering=0) as stream:
        started = time.monotonic()
        for offset in offsets:
            context.check_stop()
            _read_exact(stream.fileno(), min(len(pattern), size - offset), offset)
        sequential_read = _rate(started, size)
        random_read = _random_sample(context, stream.fileno(), random_offsets,
                                    lambda fd, offset: _read_exact(fd, BLOCK, offset))
        random_write = _random_sample(context, stream.fileno(), random_offsets,
                                     lambda fd, offset: _write_exact(fd, pattern[:BLOCK], offset))
        os.fsync(stream.fileno())
    return {"filesystem": filesystem, "io_mode": "buffered",
            "sequential_write_includes_fsync": True, "random_write_includes_fsync": False,
            "random_block_bytes": BLOCK, "sequential_write": sequential_write,
            "sequential_read": sequential_read, "random_read": random_read,
            "random_write": random_write}


def short_workloads(parameters=ShortParameters()):
    return (
        Workload("cpu-short", "cpu", Mode.STANDARD, Resources(cpu_workers=parameters.cpu_workers),
                 lambda c: run_cpu(c, parameters)),
        Workload("memory-short", "memory", Mode.STANDARD,
                 Resources(memory_bytes=2 * parameters.memory_bytes),
                 lambda c: run_memory(c, parameters)),
        Workload("storage-short", "storage", Mode.STANDARD,
                 Resources(memory_bytes=min(parameters.storage_bytes, MIB) * 2,
                           disk_bytes=parameters.storage_bytes),
                 lambda c: run_storage(c, parameters)),
    )
