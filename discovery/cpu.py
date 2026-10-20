"""CPU inventory from kernel procfs and sysfs (no benchmark execution)."""
import platform
from pathlib import Path

from .core import CollectionStatus, CollectorResult
from .readers import integer, kv_lines, read_text


def collect(context, *, proc_root="/proc", sys_root="/sys"):
    cpuinfo, status = read_text(Path(proc_root) / "cpuinfo")
    data = {"architecture": platform.machine()}
    sources = [{"path": str(Path(proc_root) / "cpuinfo"), "status": status.value}]
    if cpuinfo is not None:
        blocks = [kv_lines(b) for b in cpuinfo.split("\n\n") if b.strip()]
        primary = blocks[0] if blocks else {}
        for source, target in (
            ("vendor_id", "vendor"), ("model name", "model"),
            ("CPU implementer", "implementer"), ("Hardware", "hardware"),
        ):
            if primary.get(source):
                data[target] = primary[source]
        flags = primary.get("flags", primary.get("Features", ""))
        if flags:
            data["instruction_sets"] = sorted(set(flags.split()))
        data["logical_processors_visible"] = sum(
            1 for block in blocks if "processor" in block
        ) or None
    base = Path(sys_root) / "devices/system/cpu"
    for key, name in (
        ("online", "online_cpu_list"),
        ("possible", "possible_cpu_list"),
    ):
        value, code = read_text(base / key)
        if value is not None:
            data[name] = value.strip()
        sources.append({"path": str(base / key), "status": code.value})
    # Kernel topology is used only if it is readable, without inferring socket count.
    topology = base / "cpu0/topology"
    for source, target in (
        ("physical_package_id", "package_id_cpu0"),
        ("core_id", "core_id_cpu0"),
    ):
        value, code = read_text(topology / source)
        if value is not None:
            number = integer(value)
            if number is not None and number >= 0:
                data[target] = number
        sources.append({"path": str(topology / source), "status": code.value})
    usable = cpuinfo is not None or any(k.endswith("_cpu_list") for k in data)
    return CollectorResult("cpu", CollectionStatus.COMPLETE if usable else status,
                           data=data, sources=sources,
                           reason="" if usable else "CPU inventory sources inaccessible")
