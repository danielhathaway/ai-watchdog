"""Publish a read-only, per-UID snapshot of kernel UDP multicast metadata."""
import json
import os
import pwd
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BPFTRACE = "/usr/bin/bpftrace"
SS = "/usr/bin/ss"
MAX_SNAPSHOT_BYTES = 1024 * 1024


def parse_output(output):
    if len(output) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Multicast iterator output is too large")
    sockets = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        kind, *fields = line.split()
        inode, cookie, *values = map(int, fields)
        if not all(0 < value < 2**64 for value in (inode, cookie)):
            raise ValueError("Invalid socket identity from multicast iterator")
        key = f"{inode}:{cookie:x}"
        if kind == "S" and len(values) == 3 and key not in sockets:
            if any(not 0 <= index < 2**31 for index in values):
                raise ValueError("Invalid interface index from multicast iterator")
            bound, ipv4, ipv6 = values
            sockets[key] = {"bound": bound, "ipv4": ipv4, "ipv6": ipv6, "memberships": []}
        elif kind == "M" and len(values) == 2 and key in sockets:
            family, index = values
            members = sockets[key]["memberships"]
            if family not in (4, 6) or not 0 < index < 2**31 or len(members) >= 16:
                raise ValueError("Invalid multicast membership from iterator")
            members.append(values)
        else:
            raise ValueError("Unrecognized multicast iterator row")
    return sockets


def collect(uid):
    # The diagnostic query assigns a kernel cookie to newly created listener sockets.
    subprocess.run([SS, "-H", "-lun", "-e"], stdout=subprocess.DEVNULL, check=True, timeout=5)
    at = time.monotonic()
    trace = Path(__file__).with_name("multicast.bt")
    output = subprocess.check_output([BPFTRACE, "-q", str(trace), str(uid)], text=True, timeout=35)
    snapshot = {"at": at, "sockets": parse_output(output)}
    payload = json.dumps(snapshot, separators=(",", ":")).encode()
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Multicast snapshot is too large")
    path = Path(f"/run/ai-watchdog-multicast-{uid}") / "snapshot.json"
    group = pwd.getpwuid(uid).pw_gid
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(payload)
            stream.flush()
            os.fchown(stream.fileno(), 0, group)
            os.fchmod(stream.fileno(), 0o440)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    uid = int(sys.argv[1])
    if os.geteuid() != 0 or not 0 < uid < 2**32 - 1:
        sys.exit("Run the multicast helper as root for a non-root account.")
    collect(uid)
