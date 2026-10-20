"""Linux operating system and nonidentifying firmware inventory."""
from pathlib import Path
import platform

from .core import CollectionStatus, CollectorResult
from .readers import kv_lines, read_text


def collect(context, *, etc_root="/etc", sys_root="/sys"):
    data = {
        "os": platform.system(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
    }
    sources = []
    path = Path(etc_root) / "os-release"
    content, status = read_text(path)
    sources.append({"path": str(path), "status": status.value})
    if content is not None:
        parsed = kv_lines(content, separator="=")
        for key in ("ID", "VERSION_ID", "PRETTY_NAME", "VERSION_CODENAME"):
            if key in parsed:
                data[key.lower()] = parsed[key]
    firmware = Path(sys_root) / "firmware/efi"
    data["efi_boot"] = firmware.is_dir()
    sources.append({"path": str(firmware), "status": (
        CollectionStatus.COMPLETE if firmware.is_dir() else CollectionStatus.UNAVAILABLE
    ).value})
    # Avoid sysfs product serials, machine IDs, hostnames and DMI UUIDs.
    for key in ("bios_vendor", "bios_version", "bios_date",
                "board_vendor", "product_name"):
        path = Path(sys_root) / "class/dmi/id" / key
        value, field_status = read_text(path)
        sources.append({"path": str(path), "status": field_status.value})
        if value is not None:
            data[key] = value.strip()
    return CollectorResult("system", CollectionStatus.COMPLETE, data=data, sources=sources)
