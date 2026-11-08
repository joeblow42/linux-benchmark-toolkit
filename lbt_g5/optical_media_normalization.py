"""Pure, conservative parsing of sealed sg_get_config --current stdout.

The utility's decoded feature text is version-dependent. Preserve feature
details as opaque lines; do not infer media insertion, health, write capability,
or device state from an incomplete/current-profile description.
"""
import re

MAX_BYTES = 1024 * 1024
MAX_LINES = 4096
MAX_LINE = 8192
TARGET = re.compile(r"/dev/sr[0-9]+\Z")

class OpticalMediaParseError(ValueError):
    """Malformed or unattributed SRC-18 original stdout."""

def parse_optical_media(raw, *, source_target):
    if type(source_target) is not str or TARGET.fullmatch(source_target) is None:
        raise OpticalMediaParseError("OPTICAL_UNVERIFIED_TARGET")
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES or not raw.endswith(b"\n"):
        raise OpticalMediaParseError("OPTICAL_INVALID_BYTES_OR_BOUNDARY")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise OpticalMediaParseError("OPTICAL_NON_UTF8") from exc
    if ("\x00" in text or "\r" in text
            or any(ord(c) < 32 and c not in ("\n", "\t") for c in text)):
        raise OpticalMediaParseError("OPTICAL_CONTROL_BYTES")
    lines = text[:-1].split("\n")
    if len(lines) > MAX_LINES or any(not line or len(line) > MAX_LINE for line in lines):
        raise OpticalMediaParseError("OPTICAL_EMPTY_OR_OVERSIZED_LINE")
    index = 0
    profile = None
    if lines[0].startswith("Current profile: "):
        profile = lines[0][len("Current profile: "):]
        if not profile or len(profile) > 512 or profile != profile.strip():
            raise OpticalMediaParseError("OPTICAL_INVALID_PROFILE")
        index += 1
    if index >= len(lines) or lines[index] != "Features:":
        raise OpticalMediaParseError("OPTICAL_MISSING_FEATURE_HEADER")
    details = lines[index+1:]
    if any(line.startswith("Current profile:") or line == "Features:" for line in details):
        raise OpticalMediaParseError("OPTICAL_DUPLICATED_HEADER")
    return {"reported_profile": profile, "feature_lines": details}
