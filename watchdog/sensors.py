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


def physical_interface(name):
    path = (Path("/sys/class/net") / name).resolve(strict=True)
    return path.is_relative_to("/sys/devices") and not path.is_relative_to("/sys/devices/virtual")


def select_uplinks(names):
    physical = []
    for name in sorted(names):
        try:
            if physical_interface(name):
                physical.append(name)
        except FileNotFoundError:
            # A device may disappear between the counter read and topology lookup.
            continue
    if physical:
        return {"method": "physical", "uplinks": physical}
    if len(names) == 1:
        return {"method": "single", "uplinks": sorted(names)}

    routes = []
    if names:
        for family in ("-4", "-6"):
            try:
                routes.extend(json.loads(execute(
                    IP, family, "-j", "route", "show", "table", "main", "default", timeout=1,
                )))
            except subprocess.CalledProcessError:
                continue
    candidates = [
        (route.get("metric", 0), hop.get("dev"))
        for route in routes for hop in route.get("nexthops", [route])
        if hop.get("dev") in names and "linkdown" not in hop.get("flags", ())
    ]
    if candidates:
        return {"method": "default", "uplinks": [min(candidates)[1]]}
    return {"method": "unavailable", "uplinks": []}


def interface_counters():
    counters = {}
    for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
        name, _, data = line.rpartition(":")
        fields = data.split()
        if name.strip() != "lo" and len(fields) >= 16:
            counters[name.strip()] = tuple(int(fields[index]) for index in (0, 8, 1, 9))
    return counters


def interface_rates(previous, counters, seconds):
    basis = select_uplinks(counters.keys())
    included = set(basis["uplinks"])
    rates = []
    for name, values in sorted(counters.items()):
        deltas = [None] * 4
        if seconds and name in previous:
            deltas = [value - old if value >= old else None for value, old in zip(values, previous[name])]
        rx, tx, rx_packets, tx_packets = deltas
        rates.append({
            "name": name, "counted": name in included,
            "rx": rx / seconds if rx is not None else None,
            "tx": tx / seconds if tx is not None else None,
            "rx_packets": rx_packets, "tx_packets": tx_packets,
        })
    totals = []
    for metric in ("rx", "tx"):
        observed = [interface[metric] for interface in rates if interface["counted"]]
        totals.append(sum(observed) if observed and None not in observed else None)
    return {**basis, "interfaces": rates, "rx": totals[0], "tx": totals[1]}


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
