"""Pure bounded parsing of a sealed vainfo --display drm O1 stdout report.

The source reports VA-API profile+entrypoint pairs. A report is NOT evidence
that hardware can successfully decode/encode a particular workload or that
the current render node remains usable. No driver/device initialization.
"""
import re

MAX_BYTES=1024*1024
MAX_LINES=4096
MAX_LINE=8192
_TARGET=re.compile(r"/dev/dri/renderD[0-9]+\Z")
_ROW=re.compile(r"\s*(VAProfile[A-Za-z0-9_]+)\s*:\s*(VAEntrypoint[A-Za-z0-9_]+)\s*\Z")
_VERSION="vainfo: VA-API version: "
_DRIVER="vainfo: Driver version: "
_HEADER="vainfo: Supported profile and entrypoints"

class VainfoParseError(ValueError):
    """Malformed or unattributed source-reported VA-API profile listing."""

def parse_vainfo(raw, *, source_target):
    if type(source_target) is not str or _TARGET.fullmatch(source_target) is None:
        raise VainfoParseError("VAINFO_UNVERIFIED_RENDER_TARGET")
    if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES or not raw.endswith(b"\n"):
        raise VainfoParseError("VAINFO_INVALID_INPUT_OR_BOUNDARY")
    try:
        text=raw.decode("utf-8","strict")
    except UnicodeDecodeError as exc:
        raise VainfoParseError("VAINFO_NON_UTF8") from exc
    if ("\x00" in text or "\r" in text or any(
            ord(c)<32 and c not in ("\t","\n") for c in text)):
        raise VainfoParseError("VAINFO_CONTROL_BYTES")
    lines=text[:-1].split("\n")
    if len(lines)>MAX_LINES or any(not s or len(s)>MAX_LINE for s in lines):
        raise VainfoParseError("VAINFO_INVALID_ROWS_OR_SIZE")
    version=driver=None
    header=False
    shown_drm=False
    pairs=[]
    seen=set()
    for line in lines:
        if not header:
            if line == "Trying display: drm":
                if shown_drm:
                    raise VainfoParseError("VAINFO_DUPLICATE_DISPLAY_HEADER")
                shown_drm=True
            elif line.startswith(_VERSION):
                if version is not None or not line[len(_VERSION):].strip():
                    raise VainfoParseError("VAINFO_INVALID_VERSION")
                version=line[len(_VERSION):]
            elif line.startswith(_DRIVER):
                if driver is not None or not line[len(_DRIVER):].strip():
                    raise VainfoParseError("VAINFO_INVALID_DRIVER")
                driver=line[len(_DRIVER):]
            elif line == _HEADER:
                header=True
            else:
                raise VainfoParseError("VAINFO_UNSUPPORTED_PREAMBLE")
        else:
            match=_ROW.fullmatch(line)
            if match is None:
                raise VainfoParseError("VAINFO_INVALID_PROFILE_ENTRYPOINT")
            pair=match.groups()
            if pair in seen:
                raise VainfoParseError("VAINFO_DUPLICATE_PROFILE_ENTRYPOINT")
            seen.add(pair)
            pairs.append({"profile":pair[0],"entrypoint":pair[1]})
    if not header:
        raise VainfoParseError("VAINFO_MISSING_PROFILE_HEADER")
    return {"va_api_version":version,"driver_version":driver,
            "profile_entrypoints":pairs}
