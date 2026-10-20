"""Physical memory, swap, and memory-pressure inventory."""
from pathlib import Path

from .core import CollectionStatus, CollectorResult
from .readers import integer, read_text


def parse_meminfo(text):
    metrics = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, remainder = line.partition(":")
        parts = remainder.split()
        if not parts:
            continue
        number = integer(parts[0])
        if number is None:
            continue
        unit = parts[1] if len(parts) > 1 else ""
        if unit == "kB":
            metrics[name] = {"value": number * 1024, "unit": "bytes"}
        elif not unit:
            metrics[name] = {"value": number, "unit": "count"}
    return metrics


def collect(context, *, proc_root="/proc"):
    root = Path(proc_root)
    content, status = read_text(root / "meminfo")
    sources = [{"path": str(root / "meminfo"), "status": status.value}]
    data = {"metrics": parse_meminfo(content) if content is not None else {}}
    swaps, swap_status = read_text(root / "swaps")
    sources.append({"path": str(root / "swaps"), "status": swap_status.value})
    if swaps is not None:
        # Paths can expose usernames or mounted private paths; do not persist them.
        rows = [line.split() for line in swaps.splitlines()[1:] if line.strip()]
        data["swap_devices"] = [
            {"type": row[1], "capacity_bytes": int(row[2]) * 1024,
             "used_bytes": int(row[3]) * 1024}
            for row in rows if len(row) >= 4 and row[2].isdigit() and row[3].isdigit()
        ]
    pressure, pressure_status = read_text(root / "pressure/memory")
    sources.append({"path": str(root / "pressure/memory"), "status": pressure_status.value})
    if pressure is not None:
        data["pressure"] = pressure.strip()
    return CollectorResult("memory", CollectionStatus.COMPLETE if content is not None else status,
                           data=data, sources=sources,
                           reason="" if content is not None else "meminfo inaccessible")
