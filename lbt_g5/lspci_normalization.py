"""Pure, version-sensitive parser for sealed lspci -nn D1 stdout.

lspci's human-readable format is NOT a stable machine protocol per lspci(8).
Only a narrow documented/observed grammar is accepted. Unsupported variants
remain sealed original data and produce a parser failure, never a guessed ID.
"""
import re

MAX_BYTES=1024*1024
MAX_ROWS=4096
MAX_LINE=8192
_SLOT=r"(?:[0-9A-Fa-f]{4}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]"
_LINE=re.compile(
    rf"(?P<slot>{_SLOT}) (?P<class>.+?) \[(?P<class_id>[0-9A-Fa-f]{{4}})\]: "
    rf"(?P<desc>.+?) \[(?P<vendor>[0-9A-Fa-f]{{4}}):(?P<device>[0-9A-Fa-f]{{4}})\]"
    rf"(?: \(rev (?P<rev>[0-9A-Fa-f]{{2}})\))?\Z"
)

class LspciParseError(ValueError):
    """Malformed or unsupported lspci -nn version-dependent listing."""

def parse_lspci_nn(raw):
    if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES or not raw.endswith(b"\n"):
        raise LspciParseError("LSPCI_INVALID_INPUT_OR_BOUNDARY")
    try:
        text=raw.decode("utf-8","strict")
    except UnicodeDecodeError as exc:
        raise LspciParseError("LSPCI_NON_UTF8") from exc
    if ("\x00" in text or "\r" in text or "\t" in text
            or any(ord(c)<32 and c!="\n" for c in text)):
        raise LspciParseError("LSPCI_INVALID_CONTROL_BYTES")
    lines=text[:-1].split("\n")
    if len(lines)>MAX_ROWS or any(not line or len(line)>MAX_LINE for line in lines):
        raise LspciParseError("LSPCI_INVALID_ROW_COUNT_OR_SIZE")
    records=[]
    seen=set()
    for line in lines:
        m=_LINE.fullmatch(line)
        if m is None:
            raise LspciParseError("LSPCI_UNSUPPORTED_HUMAN_FORMAT")
        fields=m.groupdict()
        if (not fields["class"].strip() or not fields["desc"].strip()
                or fields["slot"] in seen):
            raise LspciParseError("LSPCI_DUPLICATE_SLOT_OR_EMPTY_IDENTITY")
        seen.add(fields["slot"])
        records.append({
          "slot":fields["slot"],
          "reported_class":fields["class"],
          "class_code":fields["class_id"].lower(),
          "reported_description":fields["desc"],
          "vendor_id":fields["vendor"].lower(),
          "device_id":fields["device"].lower(),
          "revision":fields["rev"].lower() if fields["rev"] is not None else None
        })
    return records
