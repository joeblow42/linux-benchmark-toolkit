"""Read-only optical-drive discovery from Linux sysfs and procfs."""
from pathlib import Path
import re

from .core import CollectionStatus, CollectorResult
from .readers import read_text


def _read(path):
    value, _ = read_text(path, max_bytes=4096)
    return value.strip() if value is not None else None


def _cdrom_capabilities(proc_root):
    """Linux /proc/sys/dev/cdrom/info is tab-aligned by drive index."""
    content, status = read_text(Path(proc_root) / "sys/dev/cdrom/info")
    if content is None:
        return {}, status
    fields = {}
    for line in content.splitlines():
        if ":" in line:
            key, _, values = line.partition(":")
            fields[key.strip()] = values.split()
    names = fields.get("drive name", [])
    drives = {}
    for idx, name in enumerate(names):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            continue
        capabilities = {}
        for key, values in fields.items():
            if key.startswith(("Can read", "Can write", "Can eject")) and idx < len(values):
                capabilities[key.lower().replace(" ", "_")] = values[idx] == "1"
        drives[name] = capabilities
    return drives, status


def collect(context, *, sys_root="/sys", proc_root="/proc"):
    root = Path(sys_root) / "class/block"
    if not root.is_dir():
        return CollectorResult("optical", CollectionStatus.UNAVAILABLE,
                               reason="block sysfs class unavailable")
    capabilities, cap_status = _cdrom_capabilities(proc_root)
    try:
        nodes = sorted(root.iterdir(), key=lambda p: p.name)
    except PermissionError:
        return CollectorResult("optical", CollectionStatus.PERMISSION_DENIED,
                               reason="block inventory not accessible")
    except OSError:
        return CollectorResult("optical", CollectionStatus.FAILED,
                               reason="block inventory enumeration failed")
    drives = []
    for node in nodes:
        name = node.name
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            continue
        dtype = _read(node / "device/type")
        if name not in capabilities and dtype != "5":
            continue
        drives.append({
            "name": name,
            "model": _read(node / "device/model"),
            "device_type": "optical",
            "capabilities": capabilities.get(name, {}),
            "media_present": None,
            "media_status": "NOT_CHECKED",
        })
    status = CollectionStatus.COMPLETE if drives else CollectionStatus.UNAVAILABLE
    return CollectorResult(
        "optical", status, data={"drives": drives},
        sources=[
            {"path": str(root), "status": "COMPLETE"},
            {"path": str(Path(proc_root) / "sys/dev/cdrom/info"),
             "status": cap_status.value},
        ],
        reason="" if drives else "no optical drives detected",
    )
