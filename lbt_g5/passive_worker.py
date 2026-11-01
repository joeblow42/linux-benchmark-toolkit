"""G5-02 isolated D0 reader worker: static host roots and per-source attributes.

No shell, network, device-node reads, privilege changes or writes. Invoked with
one fixed registered SRC ID. Worker emits base64 of exact bytes per acquired file
inside a private transport JSON line; parent seals decoded ORIGINAL bytes.
Worker output is not a public representation. Caller MUST apply its G4-07 hard
deadline/output cap and validate this transport before preserving artifacts.
"""
import base64
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path

ROOTS = {
    "SRC-02":"/etc/os-release", "SRC-03":"/sys/firmware/efi",
    "SRC-04":"/sys/class/dmi/id", "SRC-06":"/proc/cpuinfo",
    "SRC-07":"/sys/devices/system/cpu", "SRC-08":"/proc/meminfo",
    "SRC-09":"/proc/swaps", "SRC-10":"/proc/pressure/memory",
    "SRC-12":"/sys/class/block","SRC-14":"/proc/self/mountinfo",
    "SRC-16":"/proc/sys/dev/cdrom/info","SRC-17":"/sys/class/block",
    "SRC-19":"/sys/class/drm","SRC-22":"/sys/class/net",
    "SRC-24":"/sys/class/thermal","SRC-25":"/sys/class/hwmon",
    "SRC-26":"/sys/class/power_supply",
}
STATIC_FILES = {"SRC-02","SRC-06","SRC-08","SRC-09","SRC-10","SRC-14","SRC-16"}
DMI = frozenset(("sys_vendor","product_name","product_version","product_family",
    "board_vendor","board_name","board_version","bios_vendor","bios_version",
    "bios_date","chassis_type","chassis_vendor","chassis_version"))
ATTRS = {
 "SRC-07": ("topology/core_id","topology/physical_package_id",
   "topology/thread_siblings_list","topology/core_siblings_list",
   "online","cpufreq/scaling_cur_freq","cpufreq/cpuinfo_max_freq",
   "cpufreq/scaling_min_freq","cpufreq/scaling_max_freq"),
 "SRC-12": ("size","ro","removable","queue/logical_block_size",
   "queue/physical_block_size","device/vendor","device/model","device/rev"),
 "SRC-17": ("removable","device/type","device/vendor","device/model"),
 "SRC-19": ("device/vendor","device/device","device/subsystem_vendor",
   "device/subsystem_device","device/revision"),
 "SRC-22": ("address","operstate","carrier","mtu","speed","type","duplex","ifindex"),
 "SRC-24": ("type","temp"),
 "SRC-26": ("type","status","capacity","voltage_now","current_now",
   "power_now","energy_now","energy_full","energy_full_design",
   "charge_now","charge_full","charge_full_design","manufacturer",
   "model_name","serial_number","technology","cycle_count"),
}
HWMON = re.compile(r"(temp[0-9]+_(input|label)|fan[0-9]+_(input|label)|in[0-9]+_(input|label)|power[0-9]+_(input|label)|name)")
CPU_ROOT = frozenset(("online","possible","present"))
_ALLOWED_SYS_PREFIX = ("/sys/devices/","/sys/class/","/sys/firmware/efi")
# Hard safety guard within worker as well as parent-controlled cap.
MAX_PER_FILE = 1024*1024

def _under(path, allowed):
    real = os.path.realpath(path)
    return any(real == root or real.startswith(root.rstrip("/")+"/") for root in allowed)

def _read_regular(path, allowed, limit=MAX_PER_FILE):
    """Open only regular, allowlisted attributes and read up to a hard limit."""
    if not _under(path,allowed):
        raise PermissionError("source path escapes approved realpath allowlist")
    resolved=os.path.realpath(path)
    fd=os.open(resolved,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        mode=os.fstat(fd).st_mode
        if not stat.S_ISREG(mode):
            raise PermissionError("nonregular source is prohibited")
        blocks=[]
        count=0
        while count<limit:
            chunk=os.read(fd,min(65536,limit-count))
            if not chunk: break
            blocks.append(chunk)
            count+=len(chunk)
        # Exact limit means possible unseen remainder; report conservatively.
        return b"".join(blocks),count>=limit
    finally: os.close(fd)

def _paths(source, roots):
    root=roots[source]
    if source in STATIC_FILES:
        yield root
        return
    if source=="SRC-03":
        # Presence only; never open firmware variables.
        return
    if source=="SRC-04":
        for field in sorted(DMI):
            yield os.path.join(root,field)
        return
    if source=="SRC-07":
        for attr in sorted(CPU_ROOT):
            yield os.path.join(root,attr)
    try:
        names=sorted(os.listdir(root))
    except (FileNotFoundError,PermissionError,NotADirectoryError):
        return
    for entry in names:
        if "/" in entry or entry.startswith("."): continue
        if source=="SRC-07" and re.fullmatch(r"cpu[0-9]+",entry):
            attrs=ATTRS[source]
        elif source=="SRC-12" and re.fullmatch(r"[a-zA-Z0-9_.:-]+",entry):
            attrs=ATTRS[source]
        elif source=="SRC-17" and re.fullmatch(r"sr[0-9]+",entry):
            attrs=ATTRS[source]
        elif source=="SRC-19" and re.fullmatch(r"card[0-9]+",entry):
            attrs=ATTRS[source]
        elif source=="SRC-22" and re.fullmatch(r"[a-zA-Z0-9_.:-]+",entry):
            attrs=ATTRS[source]
        elif source=="SRC-24" and re.fullmatch(r"thermal_zone[0-9]+",entry):
            attrs=ATTRS[source]
        elif source=="SRC-25" and re.fullmatch(r"hwmon[0-9]+",entry):
            try: attrs=tuple(n for n in sorted(os.listdir(os.path.join(root,entry))) if HWMON.fullmatch(n))
            except OSError: continue
        elif source=="SRC-26" and re.fullmatch(r"[a-zA-Z0-9_.:-]+",entry):
            attrs=ATTRS[source]
        else: continue
        for attr in attrs:
            yield os.path.join(root,entry,attr)

def collect(source, *, roots=None, max_bytes=None, max_entries=None):
    """Generator for bounded restricted transport records; roots injectable ONLY for tests."""
    if source=="SRC-01":
        value=json.dumps({"system":platform.system(),"machine":platform.machine(),
                          "release":platform.release()},sort_keys=True).encode("utf-8")
        yield {"path":"LOCAL_API","bytes_b64":base64.b64encode(value).decode("ascii"),"limited":False}
        yield {"end":True,"entries":1,"bytes":len(value),"limited":False}
        return
    if source=="SRC-27":
        # Discover only fixed registered tools. No version subprocess or env dump.
        import shutil
        allowed=("lscpu","lsblk","lspci","ip","smartctl","nvme","vainfo",
                 "python3","dpkg-query","rpm")
        acquired_bytes=0
        for name in allowed:
            resolved=shutil.which(name, path="/usr/bin:/bin:/usr/sbin:/sbin")
            value=json.dumps({"tool":name,"path":resolved},sort_keys=True).encode()
            acquired_bytes+=len(value)
            yield {"path":"TOOL_RESOLVER/"+name,"bytes_b64":base64.b64encode(value).decode("ascii"),"limited":False}
        yield {"end":True,"entries":len(allowed),"bytes":acquired_bytes,"limited":False}
        return
    if source not in ROOTS:
        raise ValueError("not an approved D0 worker source")
    roots=ROOTS if roots is None else roots
    path=roots[source]
    if source=="SRC-03":
        # Record source presence, not a firmware-variable read.
        value=b"present\n" if os.path.isdir(path) else b"absent\n"
        yield {"path":"EFI_PRESENCE","bytes_b64":base64.b64encode(value).decode(),"limited":False}
        yield {"end":True,"entries":1,"bytes":len(value),"limited":False}
        return
    allowed=(os.path.realpath(path),)
    if roots is ROOTS and path.startswith("/sys/"):
        allowed=tuple(os.path.realpath(x.rstrip("/")) for x in _ALLOWED_SYS_PREFIX)
    count=0
    captured=0
    for candidate in _paths(source,roots):
        if max_entries is not None and count>=max_entries: break
        if max_bytes is not None and captured>=max_bytes: break
        try:
            data,at_limit=_read_regular(candidate,allowed,
                  min(MAX_PER_FILE,max_bytes-captured if max_bytes is not None else MAX_PER_FILE))
        except (OSError,PermissionError) as exc:
            yield {"path":candidate,"error":type(exc).__name__}
            continue
        count+=1
        captured+=len(data)
        yield {"path":candidate,"bytes_b64":base64.b64encode(data).decode("ascii"),
               "limited":at_limit}
    # An explicit end record makes zero-read distinguishable from a truncated stream.
    yield {"end":True,"entries":count,"bytes":captured,
           "limited":(max_entries is not None and count>=max_entries)
             or (max_bytes is not None and captured>=max_bytes)}

def main():
    # No user-supplied roots, paths, flags, commands, or output destinations.
    if len(sys.argv)!=4:
        raise SystemExit(64)
    sid=sys.argv[1]
    if sid not in tuple(ROOTS)+("SRC-01","SRC-27"): raise SystemExit(64)
    try:
        byte_limit=int(sys.argv[2]);entry_limit=int(sys.argv[3])
    except ValueError: raise SystemExit(64)
    if not (0<byte_limit<=32*1024*1024 and 0<entry_limit<=4096):
        raise SystemExit(64)
    for item in collect(sid,max_bytes=byte_limit,max_entries=entry_limit):
        sys.stdout.write(json.dumps(item,separators=(",",":"),sort_keys=True)+"\n")
        sys.stdout.flush()

if __name__=="__main__": main()
