import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .common import execute

SS = "/usr/bin/ss"
OWNER = re.compile(r",pid=(\d+),fd=\d+\)")
EXTENDED = re.compile(
    r"^(?:users:\(.*\)\s+)?(?:timer:\([^)]*\)\s+)?(?:uid:\d+\s+)?"
    r"(?:ino:(\d+)\s+)?sk:([0-9a-fA-F]+)(?:\s|$)"
)
COUNTER = re.compile(r"(?:^|\s)(bytes_received|bytes_sent|bytes_acked):(\d+)(?=\s|$)")


@dataclass(frozen=True)
class SocketReading:
    owner: int | None
    received: int
    sent: int


def loopback(endpoint):
    address = endpoint.rsplit(":", 1)[0].strip("[]").split("%", 1)[0]
    try:
        address = ipaddress.ip_address(address)
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_loopback


def parse(output):
    readings = {}
    mismatched = False
    for line in output.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not all(value.isdecimal() for value in fields[1:3]):
            mismatched = True
            continue
        _, _, _, local, remote, details = fields
        if loopback(local) or loopback(remote):
            continue
        match = EXTENDED.match(details)
        if not match:
            mismatched = True
            continue
        # An inode of zero means the socket has detached from its owner while closing.
        # Correlate it via the kernel cookie and endpoints to account for its last counters.
        key = (match[2], local, remote)
        owners = {int(pid) for pid in OWNER.findall(details[:match.start(2)])}
        counts = {metric: int(value) for metric, value in COUNTER.findall(details[match.end():])}
        readings[key] = SocketReading(
            next(iter(owners)) if len(owners) == 1 and match[1] not in (None, "0") else None,
            counts.get("bytes_received", 0),
            counts.get("bytes_sent", counts.get("bytes_acked", 0)),
        )
    if mismatched and not readings:
        raise ValueError("Unrecognized Linux socket statistics")
    return readings


def capture():
    return parse(execute(SS, "-H", "-O", "-t", "-i", "-n", "-p", "-e", "state", "connected", timeout=2))


def name(pid):
    try:
        label = Path(f"/proc/{pid}/comm").read_text(errors="replace").strip()
    except OSError:
        label = ""
    return "".join(char if char.isprintable() else " " for char in label)[:64] or "Process"


def tcp_rates(previous, current, elapsed, interval):
    if current is None:
        return "unavailable", {}, (0, 0)
    if previous is None or not 0 < elapsed <= 3 * interval:
        return "warming", {}, (0, 0)
    by_owner = defaultdict(lambda: [0, 0])
    for key, reading in current.items():
        old = previous.get(key)
        owner = reading.owner
        if old and old.owner != owner:
            owner = None
        by_owner[owner][0] += max(0, reading.received - (old.received if old else 0))
        by_owner[owner][1] += max(0, reading.sent - (old.sent if old else 0))
    unattributed = by_owner.pop(None, (0, 0))
    rates = {
        (pid, name(pid)): (rx / elapsed, tx / elapsed)
        for pid, (rx, tx) in by_owner.items() if rx or tx
    }
    return "ready", rates, tuple(value / elapsed for value in unattributed)


def summarize(previous, current, elapsed, interval, udp=None):
    tcp_state, tcp, unknown = tcp_rates(previous, current, elapsed, interval)
    udp = udp or {"state": "off"}
    protocols = {"tcp": tcp_state, "udp": udp["state"]}
    if "ready" not in protocols.values():
        return {"state": tcp_state, "protocols": protocols}
    udp_rates = udp.get("rates", {})
    rows = []
    for pid, label in tcp.keys() | udp_rates.keys():
        tcp_rx, tcp_tx = tcp.get((pid, label), (0, 0))
        udp_rx, udp_tx = udp_rates.get((pid, label), (0, 0))
        row = {"pid": pid, "name": label, "rx": round(tcp_rx + udp_rx, 1), "tx": round(tcp_tx + udp_tx, 1)}
        if udp["state"] == "ready":
            row.update(
                tcp_rx=round(tcp_rx, 1) if tcp_state == "ready" else None,
                tcp_tx=round(tcp_tx, 1) if tcp_state == "ready" else None,
                udp_rx=round(udp_rx, 1), udp_tx=round(udp_tx, 1),
            )
        rows.append(row)
    return {
        "state": "ready",
        "protocols": protocols,
        "top": sorted(rows, key=lambda row: (-(row["rx"] + row["tx"]), row["pid"], row["name"]))[:8],
        "rx": sorted((row for row in rows if row["rx"]), key=lambda row: (-row["rx"], row["pid"], row["name"]))[:5],
        "tx": sorted((row for row in rows if row["tx"]), key=lambda row: (-row["tx"], row["pid"], row["name"]))[:5],
        "unattributed": {"rx": round(unknown[0], 1), "tx": round(unknown[1], 1)},
    }
