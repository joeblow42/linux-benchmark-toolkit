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
SENSITIVE_IDS = frozenset((
    "host.hostname",
    "host.system_uuid",
    "host.system_serial",
    "host.board_serial",
    "host.firmware_serial",
    "cpu.processor_serial",
    "storage.disk_serial",
    "storage.disk_wwn",
    "storage.device_node",
    "filesystem.uuid",
    "filesystem.label",
    "filesystem.mount_point",
    "optical.drive_serial",
    "optical.media_identifier",
    "gpu.device_serial",
    "network.mac_address",
    "network.ipv4_address",
    "network.ipv6_address",
    "network.route_gateway",
    "network.route_destination",
    "network.interface_name",
    "power.battery_serial",
    "thermal.sensor_label",
    "tool.executable_path",
    "software.local_path",
))
SENSITIVE_FACTS = {
    "platform.dmi.product_serial": "host.system_serial",
    "platform.dmi.board_serial": "host.board_serial",
    "platform.dmi.chassis_serial": "host.system_serial",
    "platform.dmi.product_uuid": "host.system_uuid",
    "platform.dmi.bios_serial": "host.firmware_serial",
}
OUTPUTS = {
    "PUB-01": "system_report.html",
    "PUB-02": "system_public.json",
    "PUB-03": "inventory.csv",
    "PUB-04": "collection_status.csv",
    "PUB-05": "benchmark_results.csv",
    "PUB-06": "recommendations.csv",
    "PUB-07": "validation_public.json",
    "PUB-08": "validation_public.csv",
    "PUB-09": "validation_public.html",
    "PUB-10": "validation_public.md",
}
OPTIONAL_OUTPUTS = frozenset(OUTPUTS) - {"PUB-01"}
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
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if not isinstance(key, str) or key == "<<" or key in result:
                raise ValueError(f"invalid or duplicate key in {path.name}")
            result[key] = value
        return result

    try:
        return json.loads(content, object_pairs_hook=unique)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError:
            raise ValueError(f"{path.name} needs PyYAML for non-JSON YAML syntax") from None

        class StrictLoader(yaml.SafeLoader):
            def construct_mapping(self, node, deep=False):
                return unique(self.construct_pairs(node, deep=deep))

        StrictLoader.yaml_implicit_resolvers = {
            key: [(tag, pattern) for tag, pattern in values
                  if tag != "tag:yaml.org,2002:bool"]
            for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
        }
        import re
        StrictLoader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(true|false)$"), "tf")
        try:
            for token in yaml.scan(content):
                if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)):
                    raise ValueError(f"aliases, anchors and tags are forbidden in {path.name}")
            return yaml.load(content, Loader=StrictLoader)
        except yaml.YAMLError:
            raise ValueError(f"invalid YAML in {path.name}") from None


def load_policy(path):
    path = Path(path)
    privacy = settings(path / "privacy.yaml",
                       {"schema_version": "1.0", "global_privacy_enabled": True,
                        "mask": dict.fromkeys(SENSITIVE_IDS, True)}, private=True)
    outputs = settings(path / "outputs.yaml",
                       {"schema_version": "1.0", "exports": dict.fromkeys(OPTIONAL_OUTPUTS, False)})
    if (type(privacy) is not dict or set(privacy) != {"schema_version", "global_privacy_enabled", "mask"}
            or privacy["schema_version"] != "1.0"
            or type(privacy["global_privacy_enabled"]) is not bool or type(privacy["mask"]) is not dict
            or set(privacy["mask"]) != SENSITIVE_IDS
            or any(type(value) is not bool for value in privacy["mask"].values())):
        raise ValueError("invalid privacy.yaml version, sensitive fields, or Boolean flags")
    if (type(outputs) is not dict or set(outputs) != {"schema_version", "exports"}
            or outputs["schema_version"] != "1.0" or type(outputs["exports"]) is not dict
            or set(outputs["exports"]) != OPTIONAL_OUTPUTS
            or any(type(value) is not bool for value in outputs["exports"].values())):
        raise ValueError("invalid outputs.yaml version or output flags")
    masks = frozenset(key for key, enabled in privacy["mask"].items() if enabled)
    selected = frozenset(key for key, enabled in outputs["exports"].items() if enabled)
    return Policy(privacy["global_privacy_enabled"], masks, selected)


def public_inventory(inventory, policy):
    facts = []
    withheld = 0
    for fact in inventory["facts"]:
        datum = fact["datum_path"]
        if datum not in PUBLIC_FACTS | SENSITIVE_FACTS.keys():
            withheld += 1
            continue
        value = fact["normalized_value"]
        if type(value) not in (str, int, float, bool, type(None)):
            withheld += 1
            continue
        masked = policy.enabled and SENSITIVE_FACTS.get(datum) in policy.masks
        facts.append({"datum_path": datum,
                      "normalized_value": "MASKED" if masked else value,
                      "publication_state": "MASKED" if masked else "NOT_OBSERVED" if value is None else "VISIBLE",
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


def editable_settings(policy):
    return {
        "privacy.yaml": {"schema_version": "1.0", "global_privacy_enabled": policy.enabled,
                         "mask": {key: key in policy.masks for key in sorted(SENSITIVE_IDS)}},
        "outputs.yaml": {"schema_version": "1.0",
                         "exports": {key: key in policy.outputs for key in sorted(OPTIONAL_OUTPUTS)}},
    }


def save_settings(path, filename, old, new):
    """Validate staged edits and atomically save one configuration file."""
    import fcntl
    import tempfile

    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("configuration directory cannot be a symlink")
    lock = os.open(path / ".publication-config.lock",
                   os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if editable_settings(load_policy(path)) != old:
            raise ValueError("publication settings changed during editing; reload and retry")
        with tempfile.TemporaryDirectory(prefix=".settings-", dir=path) as staging:
            stage = Path(staging)
            for name, content in new.items():
                fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(content, stream, indent=2)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            load_policy(stage)
            (stage / filename).replace(path / filename)
        directory = os.open(path, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(lock)
