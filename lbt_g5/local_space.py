"""G5-02 local-only mount eligibility for bounded statvfs operations.

The worker must be invoked through the bounded process wrapper, not directly.
"""
import os
import re
import json
import sys

LOCAL_TYPES=frozenset(("ext2","ext3","ext4","xfs","btrfs","f2fs","zfs",
                       "overlay","squashfs","vfat"))
REMOTE_TYPES=frozenset(("nfs","nfs4","cifs","smb3","fuse","fuseblk","sshfs"))

def _unescape(text):
    return re.sub(r"\\([0-7]{3})",lambda m: chr(int(m.group(1),8)),text)

def eligible_mounts(content):
    """Select exact local mount points; exclude unknown and remote filesystems."""
    selected=[]
    for line in content.splitlines():
        before,sep,after=line.partition(" - ")
        if not sep: continue
        lhs=before.split();rhs=after.split()
        if len(lhs)<5 or len(rhs)<3: continue
        mount=_unescape(lhs[4])
        if rhs[0] not in LOCAL_TYPES or not mount.startswith("/") or "\x00" in mount:
            continue
        if os.path.realpath(mount)!=mount:
            continue
        selected.append(mount)
    return tuple(dict.fromkeys(selected))

def inspect_local_mount(path):
    if path not in eligible_mounts(open("/proc/self/mountinfo",encoding="utf-8",errors="replace").read()):
        raise PermissionError("nonlocal or unregistered mount")
    info=os.statvfs(path)
    return {"mount":path,"fragment_size":info.f_frsize,
            "block_size":info.f_bsize,"blocks":info.f_blocks,
            "free_blocks":info.f_bfree,"available_blocks":info.f_bavail,
            "files":info.f_files,"free_files":info.f_ffree}

def main():
    if len(sys.argv)!=2: raise SystemExit(64)
    print(json.dumps(inspect_local_mount(sys.argv[1]),sort_keys=True,separators=(",",":")))

if __name__=="__main__": main()
