"""Transfer a generated fixture over SMB using the system Samba client library."""
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import sys
import time

MIB = 1024 ** 2
Auth = c.CFUNCTYPE(None, c.c_char_p, c.c_char_p, c.c_void_p, c.c_int,
                   c.c_void_p, c.c_int, c.c_void_p, c.c_int)


@Auth
def guest(server, share, group, group_size, user, user_size, password, password_size):
    for pointer, size in ((group, group_size), (user, user_size), (password, password_size)):
        if size:
            c.memset(pointer, 0, size)


def checked(result):
    if result < 0:
        raise OSError(c.get_errno(), "SMB operation failed")
    return result


def client():
    smb = c.CDLL("libsmbclient.so.0", use_errno=True)
    smb.smbc_init.argtypes = [Auth, c.c_int]
    smb.smbc_open.argtypes = [c.c_char_p, c.c_int, c.c_uint]
    smb.smbc_close.argtypes = [c.c_int]
    smb.smbc_unlink.argtypes = [c.c_char_p]
    for operation in (smb.smbc_write, smb.smbc_read):
        operation.argtypes = [c.c_int, c.c_void_p, c.c_size_t]
        operation.restype = c.c_ssize_t
    checked(smb.smbc_init(guest, 0))
    return smb


def transfer(smb, url, size, marker):
    block = c.create_string_buffer(MIB)
    expected = hashlib.sha256()
    started = time.monotonic()
    fd = checked(smb.smbc_open(url, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    try:
        marker.touch(exist_ok=False)
        for offset in range(0, size, MIB):
            data = os.urandom(min(MIB, size - offset))
            expected.update(data)
            c.memmove(block, data, len(data))
            written = checked(smb.smbc_write(fd, block, len(data)))
            if written != len(data):
                raise OSError("short SMB write")
    finally:
        checked(smb.smbc_close(fd))
    elapsed = time.monotonic() - started
    actual = hashlib.sha256()
    received = 0
    started = time.monotonic()
    fd = checked(smb.smbc_open(url, os.O_RDONLY, 0))
    try:
        while received <= size:
            count = checked(smb.smbc_read(fd, block, min(MIB, size + 1 - received)))
            if not count:
                break
            actual.update(block.raw[:count])
            received += count
    finally:
        checked(smb.smbc_close(fd))
    read_elapsed = time.monotonic() - started
    return {"initial": {"bytes": size, "seconds": elapsed, "mib_per_second": size / MIB / elapsed},
            "integrity": {"verified": received == size and expected.digest() == actual.digest(),
                          "bytes": received, "seconds": read_elapsed,
                          "mib_per_second": received / MIB / read_elapsed}}


if __name__ == "__main__":
    operation, url, size, marker = sys.argv[1:]
    try:
        smb = client()
        if operation == "delete":
            checked(smb.smbc_unlink(url.encode()))
            result = {"deleted": True}
        else:
            result = transfer(smb, url.encode(), int(size), Path(marker))
    except OSError as error:
        result = {"error": "SMB_OPERATION_FAILED", "errno": error.errno}
    print(json.dumps(result, allow_nan=False))
