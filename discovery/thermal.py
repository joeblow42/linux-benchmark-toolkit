"""Read-only thermal-zone and hwmon sensor inventory."""
from pathlib import Path
import re

from .core import CollectionStatus, CollectorResult
from .readers import integer, read_text

_ZONE = re.compile(r"thermal_zone[0-9]+$")
_HWMON = re.compile(r"hwmon[0-9]+$")
_INPUT = re.compile(r"(temp|fan)[0-9]+_input$")


def _read(path):
    data, status = read_text(path, max_bytes=4096)
    return data.strip() if data is not None else None, status


def collect(context, *, sys_root="/sys"):
    root = Path(sys_root)
    sensors = []
    sources = []
    available = False
    denied = False
    for base, kind, pattern in (
        (root / "class/thermal", "thermal_zone", _ZONE),
        (root / "class/hwmon", "hwmon", _HWMON),
    ):
        if not base.is_dir():
            sources.append({"path": str(base), "status": "UNAVAILABLE"})
            continue
        try:
            entries = sorted(base.iterdir(), key=lambda p: p.name)
        except PermissionError:
            denied = True
            sources.append({"path": str(base), "status": "PERMISSION_DENIED"})
            continue
        except OSError:
            sources.append({"path": str(base), "status": "FAILED"})
            continue
        available = True
        sources.append({"path": str(base), "status": "COMPLETE"})
        for node in entries:
            if not pattern.fullmatch(node.name):
                continue
            if kind == "thermal_zone":
                label, _ = _read(node / "type")
                raw, status = _read(node / "temp")
                reading = integer(raw)
                sources.append({"path": str(node / "temp"), "status": status.value})
                sensors.append({
                    "source": kind, "name": node.name, "label": label,
                    "temperature_millidegrees_c": reading,
                    "reading_status": status.value if reading is not None
                    else ("FAILED" if status == CollectionStatus.COMPLETE else status.value),
                })
            else:
                label, _ = _read(node / "name")
                try:
                    inputs = sorted((p for p in node.iterdir() if _INPUT.fullmatch(p.name)),
                                    key=lambda p: p.name)
                except OSError:
                    continue
                for path in inputs:
                    raw, status = _read(path)
                    reading = integer(raw)
                    sources.append({"path": str(path), "status": status.value})
                    sensors.append({
                        "source": kind, "name": node.name, "label": label,
                        "channel": path.name, "value": reading,
                        "unit": "millidegrees_c" if path.name.startswith("temp") else "rpm",
                        "reading_status": status.value if reading is not None
                        else ("FAILED" if status == CollectionStatus.COMPLETE else status.value),
                    })
    status = (CollectionStatus.COMPLETE if available else
              CollectionStatus.PERMISSION_DENIED if denied else CollectionStatus.UNAVAILABLE)
    return CollectorResult("thermal", status, data={"sensors": sensors},
                           sources=sources, reason="" if available
                           else "thermal and hwmon classes unavailable")
