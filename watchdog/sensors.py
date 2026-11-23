import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from .common import execute

IP = "/usr/sbin/ip"
JOURNAL = "/usr/bin/journalctl"
MAX_HASH_BYTES = 8 * 1024 * 1024
SSH_FAILURE = re.compile(r"^Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for .+ from ([0-9a-fA-F:.]+) port \d+")
SSH_MATCHES = (
    "_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth",
    "_SYSTEMD_UNIT=ssh.service", "_SYSTEMD_UNIT=sshd.service",
)


def traffic(previous, at, previous_at, interval):
    counters = {}
    for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
        name, _, data = line.rpartition(":")
        fields = data.split()
        if name.strip() != "lo" and len(fields) >= 16:
            counters[name.strip()] = (int(fields[0]), int(fields[8]))
    elapsed = at - previous_at
    if not previous or not 0 < elapsed <= 3 * interval:
        return counters, None, None
    rates = [0.0, 0.0]
    for name, totals in counters.items():
        if name in previous:
            for column, total in enumerate(totals):
                rates[column] += max(0, total - previous[name][column]) / elapsed
    return counters, *rates


def sockets():
    inbound_pending = set()
    outbound_pending = 0
    established = 0
    for filename in ("tcp", "tcp6"):
        path = Path("/proc/net") / filename
        if filename == "tcp6" and not path.exists():
            continue
        with path.open() as table:
            next(table)
            for line in table:
                fields = line.split()
                state = fields[3]
                if state == "01":
                    established += 1
                elif state == "02":
                    outbound_pending += 1
                elif state == "03":
                    inbound_pending.add(fields[2].split(":")[0])
    return established, outbound_pending, len(inbound_pending)


def neighbors():
    devices = []
    for entry in json.loads(execute(IP, "-j", "neigh", "show")):
        mac = entry.get("lladdr", "").lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            continue
        address = ipaddress.ip_address(entry["dst"])
        if address.is_multicast or address.is_unspecified:
            continue
        if {"FAILED", "INCOMPLETE", "NOARP"}.intersection(entry.get("state", [])):
            continue
        devices.append((mac, str(address), entry["dev"]))
    return devices


def ssh_failures(cursor, now):
    options = [JOURNAL, "-q", "--no-pager", "-o", "json", "--output-fields=MESSAGE", "-n", "201"]
    options.extend(["--after-cursor", cursor] if cursor else ["--since", f"@{int(now)-60}"])
    try:
        output = execute(*options, *SSH_MATCHES)
    except subprocess.CalledProcessError:
        if not cursor:
            raise
        return ssh_failures(None, now)[0:2] + (True,)
    entries = [json.loads(line) for line in output.splitlines()]
    next_cursor = entries[-1]["__CURSOR"] if entries else cursor
    failures = []
    for entry in entries:
        message = entry.get("MESSAGE")
        match = SSH_FAILURE.match(message) if isinstance(message, str) else None
        if match:
            try:
                address = str(ipaddress.ip_address(match[1]))
                at = int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000
                if now - 120 <= at <= now + 5:
                    failures.append((entry["__CURSOR"], address, at))
            except ValueError:
                continue
    return failures, next_cursor, len(entries) >= 201


def fingerprint(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return {"state": "dangling" if os.path.lexists(path) else "missing"}
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_HASH_BYTES:
            raise ValueError("Expected a regular file within the integrity size limit")
        data = stream.read(MAX_HASH_BYTES + 1)
        after = os.fstat(stream.fileno())
        fields = ("st_size", "st_mtime_ns", "st_ctime_ns", "st_ino", "st_dev")
        if len(data) != before.st_size or any(
            getattr(before, key) != getattr(after, key) for key in fields
        ):
            raise ValueError("File changed while it was read")
        return {
            "state": "present", "sha256": hashlib.sha256(data).hexdigest(),
            "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid, "gid": before.st_gid,
            "target": os.path.realpath(path),
        }
