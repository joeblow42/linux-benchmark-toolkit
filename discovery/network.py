"""Read-only network-interface inventory using sysfs.

Does not collect MAC addresses, IP addresses, or interface statistics that
could inadvertently identify users. No active network traffic is generated.
"""
from pathlib import Path
import re

from .core import CollectionStatus, CollectorResult
from .readers import integer, read_text

_NAME = re.compile(r"[A-Za-z0-9_.:@-]{1,64}$")


def _read(path):
    value, status = read_text(path, max_bytes=4096)
    return value.strip() if value is not None else None, status


def collect(context, *, sys_root="/sys"):
    root = Path(sys_root) / "class/net"
    if not root.is_dir():
        return CollectorResult("network", CollectionStatus.UNAVAILABLE,
                               data={"interfaces": []},
                               reason="network sysfs class unavailable")
    try:
        nodes = sorted(root.iterdir(), key=lambda p: p.name)
    except PermissionError:
        return CollectorResult("network", CollectionStatus.PERMISSION_DENIED,
                               data={"interfaces": []},
                               reason="network sysfs inventory inaccessible")
    except OSError:
        return CollectorResult("network", CollectionStatus.FAILED,
                               data={"interfaces": []},
                               reason="network sysfs enumeration failed")
    interfaces = []
    sources = [{"path": str(root), "status": "COMPLETE"}]
    for node in nodes:
        if not _NAME.fullmatch(node.name):
            continue
        item = {"name": node.name}
        for field in ("type", "operstate", "carrier", "speed", "duplex", "mtu"):
            raw, status = _read(node / field)
            sources.append({"path": str(node / field), "status": status.value})
            if field in ("type", "carrier", "speed", "mtu"):
                numeric = integer(raw)
                item[field] = numeric if numeric is not None and numeric >= 0 else None
            else:
                item[field] = raw
        # Speed is negotiated Mbps where the driver supplies it; not throughput.
        try:
            driver = (node / "device/driver").resolve(strict=True).name
        except (OSError, RuntimeError):
            driver = None
        item["kernel_driver"] = driver if driver and _NAME.fullmatch(driver) else None
        # Potentially identifying hardware/network addresses require explicit opt-in.
        if context.include_identifiers:
            value, status = _read(node / "address")
            sources.append({"path": str(node / "address"), "status": status.value})
            item["mac_address"] = value if value and re.fullmatch(
                r"[0-9a-fA-F:]{17}", value) else None
        interfaces.append(item)
    return CollectorResult("network", CollectionStatus.COMPLETE,
                           data={"interfaces": interfaces}, sources=sources)
