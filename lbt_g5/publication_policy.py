"""Saved-session publication configuration and public field projection."""
from dataclasses import dataclass
import json
import os
from pathlib import Path

BLOCKED = "BLOCKED / UNCLASSIFIED_PUBLIC_FIELD"
PUBLIC_FACTS = frozenset((
    "os.kernel.system", "os.kernel.machine", "os.kernel.release", "os.release.PRETTY_NAME",
    "firmware.efi.present", "memory.meminfo.MemTotal", "memory.meminfo.MemAvailable",
    "platform.dmi.sys_vendor", "platform.dmi.product_name", "platform.dmi.bios_version",
))
SENSITIVE_FACTS = frozenset(("platform.dmi.product_serial", "platform.dmi.board_serial"))
OUTPUTS = frozenset(("json", "csv"))
METRICS = frozenset((
    "initial", "incremental", "integrity", "bytes", "files", "seconds", "mib_per_second",
    "files_per_second", "verified", "mismatched_files", "peak_io_pressure_percent",
    "elapsed_seconds", "frames", "media_seconds", "realtime_factor", "concurrent_streams",
))


@dataclass(frozen=True)
class Policy:
    enabled: bool
    masks: frozenset
    outputs: frozenset


def settings(path, default, *, private=False):
    if not path.exists():
        return default
    meta = path.lstat()
    if not path.is_file() or path.is_symlink() or meta.st_size > 32768:
        raise ValueError(f"{path.name} must be a regular configuration file up to 32 KiB")
    if private and (meta.st_uid != os.geteuid() or meta.st_mode & 0o077):
        raise PermissionError(f"{path.name} must be owner-only")
    content = path.read_text(encoding="utf-8")
    try:
        return json.loads(content)
    except ValueError:
        try:
            import yaml
        except ImportError:
            raise ValueError(f"{path.name} needs PyYAML for non-JSON YAML syntax") from None
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError:
            raise ValueError(f"invalid YAML in {path.name}") from None


def load_policy(path):
    path = Path(path)
    privacy = settings(path / "privacy.yaml",
                       {"version": 1, "enabled": True, "mask": dict.fromkeys(SENSITIVE_FACTS, True)},
                       private=True)
    outputs = settings(path / "outputs.yaml", {"version": 1, "selected": []})
    if (type(privacy) is not dict or set(privacy) != {"version", "enabled", "mask"}
            or type(privacy["version"]) is not int or privacy["version"] != 1
            or type(privacy["enabled"]) is not bool or type(privacy["mask"]) is not dict
            or set(privacy["mask"]) != SENSITIVE_FACTS
            or any(type(value) is not bool for value in privacy["mask"].values())):
        raise ValueError("invalid privacy.yaml version, sensitive fields, or Boolean flags")
    if (type(outputs) is not dict or set(outputs) != {"version", "selected"}
            or type(outputs["version"]) is not int or outputs["version"] != 1
            or type(outputs["selected"]) is not list
            or any(type(value) is not str or value not in OUTPUTS for value in outputs["selected"])
            or len(set(outputs["selected"])) != len(outputs["selected"])):
        raise ValueError("invalid outputs.yaml version or unsupported output selection")
    masks = frozenset(key for key, enabled in privacy["mask"].items() if enabled)
    return Policy(privacy["enabled"], masks, frozenset(outputs["selected"]))


def public_inventory(inventory, policy):
    facts = []
    withheld = 0
    for fact in inventory["facts"]:
        datum = fact["datum_path"]
        if datum not in PUBLIC_FACTS | SENSITIVE_FACTS:
            withheld += 1
            continue
        value = fact["normalized_value"]
        if type(value) not in (str, int, float, bool, type(None)):
            withheld += 1
            continue
        facts.append({"datum_path": datum,
                      "normalized_value": "MASKED" if policy.enabled and datum in policy.masks else value,
                      "unit": fact.get("unit")})
    limits = ["Inventory is limited to fields classified for publication."]
    if withheld:
        limits.append(f"{BLOCKED} ({withheld} inventory values)")
    return {"completion_state": inventory["completion_state"], "facts": facts,
            "source_outcomes": inventory["source_outcomes"], "limitations": limits}


def public_measurements(data, *, mark=True):
    output = {}
    for key, value in data.items():
        if key in METRICS and type(value) is dict:
            output[key] = public_measurements(value, mark=mark)
        elif key in METRICS and type(value) in (bool, int, float):
            output[key] = value
        elif mark:
            output["withheld"] = BLOCKED
    return output
