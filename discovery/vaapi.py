"""VA-API advertised profile/entrypoint discovery; not a decode/encode test."""
import re

from .core import CollectionStatus, CollectorResult
from .probes import run_probe

_ENTRYPOINT = re.compile(
    r"^\s*(VAProfile[\w.-]+)\s*:\s*(VAEntrypoint[\w.-]+)\s*$"
)
_VERSION = re.compile(r"VA-API version\s*:\s*([^\r\n]+)", re.I)


def parse_vainfo(output):
    """Parse only profile/entrypoint rows; ignore display-driver diagnostic prose."""
    profiles = {}
    for line in output.splitlines():
        found = _ENTRYPOINT.match(line)
        if found:
            profiles.setdefault(found.group(1), set()).add(found.group(2))
    return [
        {"profile": name, "entrypoints": sorted(entries),
         "decode_advertised": "VAEntrypointVLD" in entries,
         "encode_advertised": bool(entries.intersection({
             "VAEntrypointEncSlice", "VAEntrypointEncSliceLP",
             "VAEntrypointEncPicture"}))}
        for name, entries in sorted(profiles.items())
    ]


def collect(context, *, device=None, probe=run_probe):
    """Query vainfo with no sudo and no attempt to install GPU libraries."""
    cmd = ["vainfo"]
    if device is not None:
        if not re.fullmatch(r"/dev/dri/renderD[0-9]+", device):
            raise ValueError("invalid VA-API render node")
        cmd += ["--display", "drm", "--device", device]
    result = probe(cmd, timeout=8, max_stdout=131072, max_stderr=4096)
    evidence = [{"tool": "vainfo", "status": result.status.value,
                 "exit_code": result.exit_code}]
    if result.status != CollectionStatus.COMPLETE:
        return CollectorResult(
            "vaapi", result.status, data={"profiles": [], "functional_test": False},
            sources=evidence, reason=result.reason)
    # vainfo versions may print the capabilities on either stream.
    text = result.stdout + "\n" + result.stderr
    profiles = parse_vainfo(text)
    version = _VERSION.search(text)
    return CollectorResult(
        "vaapi", CollectionStatus.COMPLETE,
        data={"profiles": profiles, "va_api_version": version.group(1).strip()
              if version else None, "functional_test": False,
              "advertisement_only": True},
        sources=evidence,
        reason="" if profiles else "vainfo returned no recognized profile rows")
