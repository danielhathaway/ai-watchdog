"""Read UDP socket options when Linux permits access to the owning process."""
import ctypes
import errno
import os
import platform
import socket

# Linux x86-64 and AArch64 use this number. Skip other ABIs.
PIDFD_GETFD = 438
SUPPORTED = platform.machine() in {"x86_64", "aarch64"} and ctypes.sizeof(ctypes.c_void_p) == 8
LIBC = ctypes.CDLL(None, use_errno=True)


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
