"""Run bounded copies in fresh scratch directories supplied by the backup workload."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

MIB = 1024 ** 2
SMALL_BYTES = 4096


def available(path):
    stats = os.statvfs(path)
    return stats.f_bavail * stats.f_frsize, max(1, stats.f_frsize)


def footprint(sizes, block):
    return sum(((size + block - 1) // block + 1) * block for size in sizes)


def make_file(path, size, *, replace=False):
    with path.open("wb" if replace else "xb") as stream:
        while size:
            count = min(size, MIB)
            stream.write(os.urandom(count))
            size -= count


def copy(source, target, name):
    with (source / name).open("rb") as incoming, (target / name).open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, length=MIB)
        outgoing.flush()
        os.fsync(outgoing.fileno())


def transfer(source, target, names, rsync, *, concurrent=False):
    started = time.monotonic()
    if rsync:
        # Whole-file mode makes changed-file bytes meaningful for local rsync.
        command = [rsync, "--recursive", "--times", "--checksum", "--whole-file",
                   "--itemize-changes", "--out-format=%i", "--",
                   str(source) + "/", str(target) + "/"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        changed = sum(line.startswith(b">f") for line in result.stdout.splitlines())
        if result.returncode or changed != len(names):
            return {"error": "RSYNC_TRANSFER_FAILED", "rsync_exit_code": result.returncode,
                    "changed_files": changed}
    elif concurrent:
        with ThreadPoolExecutor(max_workers=2) as pool:
            for _ in pool.map(lambda name: copy(source, target, name), names):
                pass
    else:
        for name in names:
            copy(source, target, name)
    byte_count = 0
    for name in names:
        with (target / name).open("rb") as stream:
            if rsync:
                os.fsync(stream.fileno())
            byte_count += os.fstat(stream.fileno()).st_size
    elapsed = time.monotonic() - started
    return {"bytes": byte_count, "files": len(names), "seconds": elapsed,
            "mib_per_second": byte_count / MIB / elapsed, "files_per_second": len(names) / elapsed}


def digest(stream):
    checksum = hashlib.sha256()
    for block in iter(lambda: stream.read(MIB), b""):
        checksum.update(block)
    return checksum.digest()


def verify(source, target, names):
    started = time.monotonic()
    mismatches = 0
    checked = 0
    for name in names:
        with (source / name).open("rb") as incoming, (target / name).open("rb") as outgoing:
            expected = digest(incoming)
            actual = digest(outgoing)
            mismatches += expected != actual
            checked += os.fstat(outgoing.fileno()).st_size
    elapsed = time.monotonic() - started
    return {"verified": mismatches == 0, "mismatched_files": mismatches, "bytes": checked,
            "seconds": elapsed, "mib_per_second": checked / MIB / elapsed}


def run(case, source, target, large_mib, small_files, reserve, rsync):
    if case in ("backup-large", "backup-concurrent"):
        sizes = [large_mib * MIB] * (2 if case == "backup-concurrent" else 1)
    else:
        sizes = [SMALL_BYTES] * small_files
    source_free, source_block = available(source)
    target_free, target_block = available(target)
    source_bytes = footprint(sizes, source_block)
    target_bytes = footprint(sizes, target_block)
    if rsync:
        target_bytes += footprint(sizes[:max(1, len(sizes) // 10)], target_block)
    if source.stat().st_dev == target.stat().st_dev:
        target_bytes += source_bytes
    if min(source_free - source_bytes, target_free - target_bytes) < reserve:
        return {"unavailable": "DISK_RESERVE"}
    names = [f"test-{i:05d}.bin" for i in range(len(sizes))]
    for name, size in zip(names, sizes):
        make_file(source / name, size)
    initial = transfer(source, target, names, rsync, concurrent=case == "backup-concurrent")
    if "error" in initial:
        return initial
    outcome = {"initial": initial, "integrity": verify(source, target, names),
               "destination_free_bytes_before": target_free, "capacity_reserve_bytes": reserve}
    if case == "backup-large":
        rate = initial["mib_per_second"]
        outcome["sequential_rate_band"] = "GOOD" if rate >= 80 else "MARGINAL" if rate >= 30 else "POOR"
    if case == "backup-concurrent":
        outcome["concurrent_streams"] = 2
    if rsync and outcome["integrity"]["verified"]:
        changed = names[:max(1, len(names) // 10)]
        for name in changed:
            make_file(source / name, SMALL_BYTES, replace=True)
        incremental = transfer(source, target, changed, rsync)
        outcome["incremental"] = incremental
        if "error" in incremental:
            outcome["error"] = incremental["error"]
        else:
            outcome["initial_integrity"] = outcome["integrity"]
            outcome["integrity"] = verify(source, target, names)
    return outcome


if __name__ == "__main__":
    case, source, target, large, small, reserve, rsync = sys.argv[1:]
    try:
        result = run(case, Path(source), Path(target), int(large), int(small), int(reserve), rsync)
    except OSError as error:
        result = {"error": "BACKUP_IO_ERROR", "errno": error.errno}
    print(json.dumps(result, allow_nan=False))
