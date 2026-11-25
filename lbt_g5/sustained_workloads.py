"""RP-07 sustained measurements, thermal limits and local load safeguards."""
from dataclasses import dataclass
import os
from pathlib import Path
import random
import time

from .core_workloads import (
    IOPressureGuard, MIB, _hash_sample, _rate, _write_exact, check_pressure, local_filesystem,
)
from .workload_runtime import Context, Mode, Resources, Unavailable, Unsafe, Workload

THERMAL = Path("/sys/class/thermal")
HWMON = Path("/sys/class/hwmon")
CPU = Path("/sys/devices/system/cpu")
CPU_ZONES = {"x86_pkg_temp", "cpu-thermal", "cpu_thermal", "soc_thermal"}
CPU_HWMON = {"coretemp", "k10temp", "zenpower"}


@dataclass(frozen=True)
class SustainedParameters:
    seconds: int = 30
    cpu_workers: int = 2
    max_celsius: int = 80
    storage_bytes: int = 16 * MIB
    storage_mib_per_second: int = 4

    def __post_init__(self):
        for name, low, high in (("seconds", 1, 300), ("cpu_workers", 1, 16),
                                ("max_celsius", 45, 90), ("storage_bytes", MIB, 64 * MIB),
                                ("storage_mib_per_second", 1, 16)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} outside sustained workload bounds")
        if self.storage_bytes % MIB:
            raise ValueError("storage_bytes must be a whole number of MiB")


def _integer(path):
    try:
        return int(path.read_text().strip())
    except (ValueError, OSError):
        return None


def _sensor_paths():
    sensors = []
    for zone in THERMAL.glob("thermal_zone*"):
        try:
            if (zone / "type").read_text().strip() in CPU_ZONES:
                sensors.append(zone / "temp")
        except OSError:
            continue
    for device in HWMON.glob("hwmon*"):
        try:
            if (device / "name").read_text().strip() in CPU_HWMON:
                sensors.extend(sorted(device.glob("temp[0-9]*_input")))
        except OSError:
            continue
    return tuple(sensors)


def _cpu_times():
    try:
        with open("/proc/stat", encoding="ascii") as file:
            values = list(map(int, file.readline().split()[1:9]))
        return sum(values), values[3] + values[4]
    except (OSError, ValueError, IndexError):
        return None


class Monitor:
    def __init__(self, context, limit):
        self.context = context
        self.limit = limit
        self.sensors = _sensor_paths()
        self.frequency = tuple(CPU.glob("cpu[0-9]*/cpufreq/scaling_cur_freq"))
        self.throttle = tuple(sorted(CPU.glob("cpu[0-9]*/thermal_throttle/core_throttle_count")))
        self.started = time.monotonic()
        self.last_tick = None
        self.prior_cpu = None
        self.samples = []
        self.poll(force=True)

    def poll(self, *, force=False):
        self.context.check_stop()
        now = time.monotonic()
        if not force and self.last_tick is not None and now - self.last_tick < .25:
            return
        temp = [v / 1000 for path in self.sensors if (v := _integer(path)) is not None
                and 0 < v <= 150_000]
        if not temp:
            if self.samples:
                raise Unsafe("THERMAL_TELEMETRY_LOST")
            raise Unavailable("CPU_TEMPERATURE_UNAVAILABLE")
        tick, idle = _cpu_times() or (None, None)
        utilization = None
        if tick is not None and self.prior_cpu is not None:
            prior_total, prior_idle = self.prior_cpu
            delta = tick - prior_total
            if delta > 0:
                utilization = 100 * max(0, min(delta, delta - idle + prior_idle)) / delta
        self.prior_cpu = (tick, idle) if tick is not None else None
        self.samples.append({
            "elapsed_seconds": now - self.started,
            "cpu_celsius_max": max(temp),
            "host_cpu_utilization_percent": utilization,
            "cpu_frequency_khz": [_integer(path) for path in self.frequency],
            "core_throttle_counters": [_integer(path) for path in self.throttle],
        })
        self.last_tick = now
        if max(temp) >= self.limit:
            raise Unsafe("CPU_THERMAL_LIMIT")

    def result(self):
        utilization = [s["host_cpu_utilization_percent"] for s in self.samples
                       if s["host_cpu_utilization_percent"] is not None]
        return {"temperature_stop_celsius": self.limit, "thermal_samples": self.samples,
                "host_cpu_utilization_mean_percent": sum(utilization) / len(utilization)
                if utilization else None,
                "host_cpu_utilization_peak_percent": max(utilization) if utilization else None}


def run_sustained_cpu(context, parameters):
    check_pressure("cpu", 15)
    monitor = Monitor(context, parameters.max_celsius)
    observed = Context(context.scratch, monitor.poll, context.inventory)
    workers = min(len(os.sched_getaffinity(0)), parameters.cpu_workers)
    rounds = []
    remaining = parameters.seconds
    while remaining:
        window = min(5, remaining)
        rounds.append(_hash_sample(observed, workers, window))
        remaining -= window
    monitor.poll(force=True)
    first = rounds[0]["operations_per_second"]
    return {"cpu_samples": rounds,
            "throughput_retention_percent": 100 * rounds[-1]["operations_per_second"] / first
            if len(rounds) > 1 else None, **monitor.result()}


def run_sustained_storage(context, parameters):
    filesystem = local_filesystem(context.scratch)
    io_guard = IOPressureGuard(context.check_stop)
    guarded = Context(context.scratch, io_guard.poll, context.inventory, context.evidence)
    monitor = Monitor(guarded, parameters.max_celsius)
    block = random.Random(69).randbytes(MIB)
    samples = []
    started = time.monotonic()
    deadline = started + parameters.seconds
    interval = 1 / parameters.storage_mib_per_second
    written = 0
    sample_start = started
    sample_bytes = 0
    with (context.scratch / "sustained-data").open("xb", buffering=0) as file:
        while time.monotonic() < deadline:
            monitor.poll()
            _write_exact(file.fileno(), block, written % parameters.storage_bytes)
            written += MIB
            sample_bytes += MIB
            if time.monotonic() - sample_start >= 1:
                os.fsync(file.fileno())
                samples.append(_rate(sample_start, sample_bytes))
                sample_start, sample_bytes = time.monotonic(), 0
            next_block = min(deadline, time.monotonic() + interval)
            while time.monotonic() < next_block:
                monitor.poll()
                time.sleep(min(.05, max(0, next_block - time.monotonic())))
        if sample_bytes:
            os.fsync(file.fileno())
            samples.append(_rate(sample_start, sample_bytes))
    monitor.poll(force=True)
    io_guard.poll(force=True)
    return {"filesystem": filesystem, "io_mode": "buffered", "includes_fsync": True,
            "maximum_write_mib_per_second": parameters.storage_mib_per_second,
            "sampled_bytes": written, "storage_samples": samples,
            "peak_io_pressure_percent": io_guard.peak, **monitor.result()}


def sustained_workloads(parameters=SustainedParameters()):
    return (
        Workload("cpu-sustained", "cpu", Mode.EXTENDED, Resources(cpu_workers=parameters.cpu_workers),
                 lambda c: run_sustained_cpu(c, parameters)),
        Workload("storage-sustained", "storage", Mode.EXTENDED,
                 Resources(memory_bytes=2 * MIB, disk_bytes=parameters.storage_bytes),
                 lambda c: run_sustained_storage(c, parameters)),
    )
