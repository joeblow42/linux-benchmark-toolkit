"""Read-only DRM/PCI GPU and kernel-driver inventory.

No attempt to infer working video decode/encode from vendor IDs or drivers.
"""
from pathlib import Path
import re

from .core import CollectionStatus, CollectorResult
from .readers import read_text


_CARD = re.compile(r"card[0-9]+$")
_PCI_ID = re.compile(r"0x[0-9a-fA-F]{4}$")
_DRIVER = re.compile(r"[A-Za-z0-9_.-]+$")


def _field(path):
    value, status = read_text(path, max_bytes=4096)
    return (value.strip() if value is not None else None), status


def _driver_name(device):
    try:
        # Resolve symlink only; never load kernel modules.
        target = (device / "driver").resolve(strict=True)
        return target.name if _DRIVER.fullmatch(target.name) else None
    except (OSError, RuntimeError):
        return None


def collect(context, *, sys_root="/sys"):
    root = Path(sys_root) / "class/drm"
    if not root.is_dir():
        return CollectorResult("gpu", CollectionStatus.UNAVAILABLE,
                               data={"devices": []},
                               reason="DRM sysfs class unavailable")
    try:
        cards = sorted((p for p in root.iterdir() if _CARD.fullmatch(p.name)),
                       key=lambda p: int(p.name[4:]))
    except PermissionError:
        return CollectorResult("gpu", CollectionStatus.PERMISSION_DENIED,
                               data={"devices": []}, reason="DRM inventory inaccessible")
    except OSError:
        return CollectorResult("gpu", CollectionStatus.FAILED,
                               data={"devices": []}, reason="DRM inventory enumeration failed")

    devices, sources = [], [{"path": str(root), "status": "COMPLETE"}]
    seen = set()
    for card in cards:
        device = card / "device"
        if not device.exists():
            continue
        try:
            canonical = str(device.resolve(strict=True))
        except (OSError, RuntimeError):
            continue
        if canonical in seen:
            continue
        seen.add(canonical)
        record = {"card": card.name, "kernel_driver": _driver_name(device),
                  "video_acceleration": "NOT_TESTED"}
        for filename in ("vendor", "device", "subsystem_vendor", "subsystem_device"):
            value, status = _field(device / filename)
            sources.append({"path": str(device / filename), "status": status.value})
            record[filename + "_id"] = value.lower() if value and _PCI_ID.fullmatch(value) else None
        # PCI bus addresses can be identifying in detailed host inventories;
        # keep them gated behind the explicit opt-in.
        if context.include_identifiers:
            record["sysfs_device_path"] = canonical
        devices.append(record)
    return CollectorResult(
        "gpu", CollectionStatus.COMPLETE if devices else CollectionStatus.UNAVAILABLE,
        data={"devices": devices}, sources=sources,
        reason="" if devices else "no DRM GPU cards detected")
