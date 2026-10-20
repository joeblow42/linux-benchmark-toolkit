"""Read-only storage topology from Linux sysfs and mountinfo.

Does not open block devices, issue SMART commands, or read filesystem data.
"""
from pathlib import Path
import re

from .core import CollectionStatus, CollectorResult
from .readers import integer, read_text


def _read(path):
    value, _ = read_text(path, max_bytes=4096)
    return value.strip() if value is not None else None


def _is_partition(node):
    return (node / "partition").exists()


def _transport(node, name):
    """Transport inferred only from a positive sysfs indicator."""
    try:
        location = str((node / "device").resolve(strict=True)).lower()
    except (OSError, RuntimeError):
        location = ""
    if "/usb" in location or re.search(r"/[0-9]+-[0-9]+(?:\.[0-9]+)*(/|$)", location):
        return "usb"
    if "/nvme" in location or name.startswith("nvme"):
        return "nvme"
    if "/ata" in location:
        return "ata"
    if "/virtio" in location or name.startswith("vd"):
        return "virtio"
    return "unknown"


def _mounts(proc_root, detailed):
    """Index mountinfo by major:minor; redact mount paths unless opted in."""
    raw, _ = read_text(Path(proc_root) / "self/mountinfo", max_bytes=1024 * 1024)
    mapping = {}
    if raw is None:
        return mapping
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            continue
        middle = fields.index("-")
        if middle + 2 >= len(fields):
            continue
        key = fields[2]
        if not re.fullmatch(r"\d+:\d+", key):
            continue
        # Mountinfo escapes spaces, tabs, newlines and backslashes.
        mountpoint = fields[4] if detailed else "[REDACTED]"
        mapping.setdefault(key, []).append({
            "mountpoint": mountpoint,
            "filesystem": fields[middle + 1],
        })
    return mapping


def collect(context, *, sys_root="/sys", proc_root="/proc"):
    root = Path(sys_root) / "class/block"
    if not root.is_dir():
        return CollectorResult("storage", CollectionStatus.UNAVAILABLE,
                               reason="block sysfs class unavailable",
                               sources=[{"path": str(root), "status": "UNAVAILABLE"}])
    mounted = _mounts(proc_root, context.include_identifiers)
    devices = []
    partitions = []
    try:
        nodes = sorted(root.iterdir(), key=lambda p: p.name)
    except PermissionError:
        return CollectorResult("storage", CollectionStatus.PERMISSION_DENIED,
                               reason="block inventory not accessible")
    except OSError:
        return CollectorResult("storage", CollectionStatus.FAILED,
                               reason="block inventory enumeration failed")
    for node in nodes:
        name = node.name
        # Do not report hostile names or paths if a fixture or malformed sysfs
        # entry contains unexpected characters.
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            continue
        partition = _is_partition(node)
        size = integer(_read(node / "size"))
        sector_size = integer(_read(node / "queue/logical_block_size"))
        record = {
            "name": name,
            "type": "partition" if partition else "disk",
            "capacity_bytes": (size * 512 if size is not None and size >= 0 else None),
            "device_number": _read(node / "dev"),
        }
        if not partition:
            record["transport"] = _transport(node, name)
            record["model"] = _read(node / "device/model")
            record["rotational"] = (
                None if _read(node / "queue/rotational") not in ("0", "1")
                else _read(node / "queue/rotational") == "1"
            )
            if sector_size is not None and sector_size > 0:
                record["logical_block_size_bytes"] = sector_size
            record["virtual"] = name.startswith(("loop", "ram", "dm-", "zram", "md"))
            # SMART/NVMe health requires separate optional probe/permissions.
            record["health_status"] = "NOT_COLLECTED"
        else:
            record["partition_number"] = integer(_read(node / "partition"))
        key = record["device_number"]
        if key is not None and key in mounted:
            record["mounts"] = mounted[key]
        (partitions if partition else devices).append(record)
    return CollectorResult(
        "storage", CollectionStatus.COMPLETE,
        data={"devices": devices, "partitions": partitions},
        sources=[
            {"path": str(root), "status": "COMPLETE"},
            {"path": str(Path(proc_root) / "self/mountinfo"),
             "status": "COMPLETE" if (Path(proc_root) / "self/mountinfo").exists()
             else "UNAVAILABLE"},
        ],
    )
