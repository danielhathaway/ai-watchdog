"""Read UDP socket options when Linux permits access to the owning process."""
import ctypes
import errno
import json
import os
import platform
import socket
import stat
import time
from pathlib import Path

# Linux x86-64 and AArch64 use this number. Skip other ABIs.
PIDFD_GETFD = 438
SUPPORTED = platform.machine() in {"x86_64", "aarch64"} and ctypes.sizeof(ctypes.c_void_p) == 8
LIBC = ctypes.CDLL(None, use_errno=True)
MAX_SNAPSHOT_BYTES = 1024 * 1024
MAX_SNAPSHOT_AGE = 100


def helper_snapshot(path=None, now=None):
    path = path or Path(f"/run/ai-watchdog-multicast-{os.getuid()}/snapshot.json")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return {}
            data = stream.read(MAX_SNAPSHOT_BYTES + 1)
        if len(data) > MAX_SNAPSHOT_BYTES:
            return {}
        snapshot = json.loads(data)
        now = time.monotonic() if now is None else now
        if 0 <= now - snapshot["at"] <= MAX_SNAPSHOT_AGE and isinstance(snapshot["sockets"], dict):
            return snapshot["sockets"]
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        pass
    return {}


def helper_options(snapshot, inode, cookie):
    if not inode or not cookie:
        return None
    row = snapshot.get(f"{inode}:{cookie.lower()}")
    if not isinstance(row, dict):
        return None
    v4, v6, memberships = (row.get(key) for key in ("ipv4", "ipv6", "memberships"))
    if not all(type(value) is int and 0 <= value < 2**31 for value in (v4, v6)):
        return None
    if not isinstance(memberships, list) or len(memberships) > 16 or any(
        not isinstance(pair, list) or len(pair) != 2 or pair[0] not in (4, 6)
        or type(pair[1]) is not int or not 0 < pair[1] < 2**31 for pair in memberships
    ):
        return None
    return {"ipv4_index": v4, "ipv6": v6, "memberships": memberships, "source": "kernel helper"}


def socket_options(pid, fd, inode):
    if not SUPPORTED or not hasattr(os, "pidfd_open"):
        return None
    try:
        pidfd = os.pidfd_open(pid)
        try:
            duplicate = LIBC.syscall(PIDFD_GETFD, pidfd, fd, 0)
            if duplicate < 0:
                return None
        finally:
            os.close(pidfd)
    except OSError:
        return None
    try:
        if os.fstat(duplicate).st_ino != inode:
            return None
        sock = socket.socket(fileno=duplicate)
        duplicate = None
        with sock:
            if sock.type != socket.SOCK_DGRAM or sock.family not in (socket.AF_INET, socket.AF_INET6):
                return None
            result = {
                "device": sock.getsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16)
                .split(b"\0", 1)[0].decode(errors="replace"),
            }
            if sock.family == socket.AF_INET6:
                if index := sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF):
                    result["ipv6"] = index
            try:
                address = sock.getsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, 4)
                if len(address) == 4 and any(address):
                    result["ipv4"] = socket.inet_ntoa(address)
            except OSError as error:
                if error.errno not in (errno.ENOPROTOOPT, errno.EOPNOTSUPP):
                    raise
            return result
    except OSError:
        return None
    finally:
        if duplicate is not None:
            os.close(duplicate)
