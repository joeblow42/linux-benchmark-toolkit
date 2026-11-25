"""G5-01: declarative initial G4-01/G4-07 catalog; no source execution.

Thirteen collectors and 28 source families are the approved INITIAL allocation,
not a fixed upper bound. The catalog alone never authorizes access or execution.
Executable G4-07 consent, bounds and preflight contracts belong to later G5 work.
"""
from dataclasses import dataclass
import re

class CatalogError(ValueError):
    """Invalid approved source allocation metadata."""

@dataclass(frozen=True)
class Collector:
    collector_id: str

@dataclass(frozen=True)
class Source:
    source_id: str
    collector_id: str
    authorization_class: str
    operation_id: str

INITIAL_COLLECTOR_IDS = (
    "COL-OS","COL-CPU","COL-MEM","COL-BLOCK","COL-FS","COL-OPTICAL",
    "COL-GPU","COL-VAAPI","COL-NET","COL-THERM","COL-POWER",
    "COL-TOOLS","COL-SOFTCODEC",
)
INITIAL_SOURCE_ROWS = (
    ("SRC-01","COL-OS","D0","LOCAL_API"),
    ("SRC-02","COL-OS","D0","OS_RELEASE"),
    ("SRC-03","COL-OS","D0","EFI_PRESENCE"),
    ("SRC-04","COL-OS","D0","DMI_PUBLIC"),
    ("SRC-05","COL-CPU","D1","LSCPU"),
    ("SRC-06","COL-CPU","D0","CPUINFO"),
    ("SRC-07","COL-CPU","D0","CPU_SYSFS"),
    ("SRC-08","COL-MEM","D0","MEMINFO"),
    ("SRC-09","COL-MEM","D0","SWAPS"),
    ("SRC-10","COL-MEM","D0","MEM_PRESSURE"),
    ("SRC-11","COL-BLOCK","D1","LSBLK"),
    ("SRC-12","COL-BLOCK","D0","BLOCK_SYSFS"),
    ("SRC-13","COL-BLOCK","O1","DEVICE_HEALTH"),
    ("SRC-14","COL-FS","D0","MOUNTINFO"),
    ("SRC-15","COL-FS","D1","FS_STAT"),
    ("SRC-16","COL-OPTICAL","D0","CDROM_INFO"),
    ("SRC-17","COL-OPTICAL","D0","OPTICAL_SYSFS"),
    ("SRC-18","COL-OPTICAL","O1","OPTICAL_MEDIA"),
    ("SRC-19","COL-GPU","D0","DRM_PCI_SYSFS"),
    ("SRC-20","COL-GPU","D1","LSPCI"),
    ("SRC-21","COL-VAAPI","O1","VAINFO"),
    ("SRC-22","COL-NET","D0","NET_SYSFS"),
    ("SRC-23","COL-NET","D1","IP_LOCAL"),
    ("SRC-24","COL-THERM","D0","THERM_SYSFS"),
    ("SRC-25","COL-THERM","D0","HWMON_SYSFS"),
    ("SRC-26","COL-POWER","D0","POWER_SYSFS"),
    ("SRC-27","COL-TOOLS","D0","TOOL_RESOLVER"),
    ("SRC-28","COL-SOFTCODEC","D1","OFFLINE_METADATA"),
)

def validate_catalog(collector_ids, source_rows):
    """Return immutable records without importing collectors or reading a host."""
    if not isinstance(collector_ids,(tuple,list)) or not collector_ids:
        raise CatalogError("collector registry required")
    if not isinstance(source_rows,(tuple,list)) or not source_rows:
        raise CatalogError("source registry required")
    seen_collectors=set()
    collectors=[]
    for cid in collector_ids:
        if type(cid) is not str or not re.fullmatch(r"COL-[A-Z][A-Z0-9-]*",cid) or cid in seen_collectors:
            raise CatalogError("invalid or duplicate collector")
        seen_collectors.add(cid)
        collectors.append(Collector(cid))
    seen_sources=set()
    sources=[]
    for row in source_rows:
        if not isinstance(row,(tuple,list)) or len(row)!=4:
            raise CatalogError("invalid source record")
        sid,cid,auth,op=row
        if type(sid) is not str or not re.fullmatch(r"SRC-[0-9]{2,}",sid) or sid in seen_sources:
            raise CatalogError("invalid or duplicate source ID")
        if cid not in seen_collectors:
            raise CatalogError("unknown collector owner")
        if type(auth) is not str or auth not in ("D0","D1","O1"):
            raise CatalogError("prohibited or unknown executable authorization class")
        if type(op) is not str or not re.fullmatch(r"[A-Z][A-Z0-9_]*",op):
            raise CatalogError("invalid operation ID")
        seen_sources.add(sid)
        sources.append(Source(sid,cid,auth,op))
    if {s.collector_id for s in sources} != seen_collectors:
        raise CatalogError("collector without source allocation")
    return tuple(collectors),tuple(sources)

def initial_catalog():
    """Approved initial allocation; no side effects or hardcoded count ceiling."""
    return validate_catalog(INITIAL_COLLECTOR_IDS,INITIAL_SOURCE_ROWS)
