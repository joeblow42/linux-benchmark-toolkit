"""Read-only power-supply and battery inventory.

Uses kernel sysfs units (microvolts, microamps, microwatt-hours etc.), with
no inference that a battery is healthy from presence or capacity alone.
"""
from pathlib import Path
import re

from .core import CollectionStatus, CollectorResult
from .readers import integer, read_text

_NAME = re.compile(r"[A-Za-z0-9_.-]+$")
_NUMERIC = {
    "capacity": "percent",
    "energy_now": "microwatt_hours",
    "energy_full": "microwatt_hours",
    "energy_full_design": "microwatt_hours",
    "charge_now": "microamp_hours",
    "charge_full": "microamp_hours",
    "charge_full_design": "microamp_hours",
    "power_now": "microwatts",
    "current_now": "microamps",
    "voltage_now": "microvolts",
}
_TEXT = ("type", "status", "online", "present", "technology")


def _read(path):
    value, status = read_text(path, max_bytes=4096)
    return value.strip() if value is not None else None, status


def collect(context, *, sys_root="/sys"):
    root = Path(sys_root) / "class/power_supply"
    if not root.is_dir():
        return CollectorResult("power", CollectionStatus.UNAVAILABLE,
                               data={"supplies": []}, reason="power sysfs class unavailable")
    try:
        nodes = sorted(root.iterdir(), key=lambda p: p.name)
    except PermissionError:
        return CollectorResult("power", CollectionStatus.PERMISSION_DENIED,
                               data={"supplies": []}, reason="power sysfs inventory inaccessible")
    except OSError:
        return CollectorResult("power", CollectionStatus.FAILED,
                               data={"supplies": []}, reason="power sysfs enumeration failed")
    supplies = []
    sources = [{"path": str(root), "status": "COMPLETE"}]
    for node in nodes:
        if not _NAME.fullmatch(node.name):
            continue
        record = {"name": node.name, "metrics": {}}
        for field in _TEXT:
            value, status = _read(node / field)
            sources.append({"path": str(node / field), "status": status.value})
            if value is not None:
                record[field] = value
        for field, unit in _NUMERIC.items():
            value, status = _read(node / field)
            sources.append({"path": str(node / field), "status": status.value})
            number = integer(value)
            if number is not None:
                record["metrics"][field] = {"value": number, "unit": unit}
        # Manufacturer, model, and serial strings may identify an individual
        # removable battery; omit unless detailed reporting is requested.
        if context.include_identifiers:
            for field in ("manufacturer", "model_name", "serial_number"):
                value, status = _read(node / field)
                sources.append({"path": str(node / field), "status": status.value})
                if value is not None:
                    record[field] = value
        supplies.append(record)
    return CollectorResult("power", CollectionStatus.COMPLETE,
                           data={"supplies": supplies}, sources=sources)
