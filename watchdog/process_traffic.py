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
COUNTER = re.compile(r"(?:^|\s)(bytes_received|bytes_sent|bytes_acked|segs_in|segs_out):(\d+)(?=\s|$)")


@dataclass(frozen=True)
class SocketReading:
    owner: int | None
    received: int
    sent: int
    segments: tuple[int | None, int | None] = (None, None)
    min_header_length: int | None = None


def endpoint_address(endpoint):
    address = endpoint.rsplit(":", 1)[0].strip("[]").split("%", 1)[0]
    try:
        address = ipaddress.ip_address(address)
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def parse(output):
    readings = {}
    mismatched = False
    for line in output.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not all(value.isdecimal() for value in fields[1:3]):
            mismatched = True
            continue
        _, _, _, local, remote, details = fields
        endpoints = [endpoint_address(value) for value in (local, remote)]
        if any(address and address.is_loopback for address in endpoints):
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
        segments = (counts.get("segs_in"), counts.get("segs_out"))
        peer = endpoints[1]
        minimum = 40 if peer and peer.version == 4 else 60 if peer else None
        readings[key] = SocketReading(
            next(iter(owners)) if len(owners) == 1 and match[1] not in (None, "0") else None,
            counts.get("bytes_received", 0),
            counts.get("bytes_sent", counts.get("bytes_acked", 0)),
            segments, minimum if any(value is not None for value in segments) else None,
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
        return "unavailable", {}, (0, 0), {}
    if previous is None or not 0 < elapsed <= 3 * interval:
        return "warming", {}, (0, 0), {}
    by_owner = defaultdict(lambda: [0, 0])
    framing = {}
    for key, reading in current.items():
        old = previous.get(key)
        owner = reading.owner
        if old and old.owner != owner:
            owner = None
        by_owner[owner][0] += max(0, reading.received - (old.received if old else 0))
        by_owner[owner][1] += max(0, reading.sent - (old.sent if old else 0))
        if owner is not None and reading.min_header_length:
            for index, segments in enumerate(reading.segments):
                prior = old.segments[index] if old else 0
                if segments is None or prior is None or segments < prior:
                    continue
                counts = framing.setdefault(owner, [[None, None], [None, None]])
                packets, headers = counts[index]
                delta = segments - prior
                counts[index] = [(packets or 0) + delta, (headers or 0) + delta * reading.min_header_length]
    unattributed = by_owner.pop(None, (0, 0))
    labels = {pid: name(pid) for pid, (rx, tx) in by_owner.items()
              if rx or tx or any(item[0] for item in framing.get(pid, []))}
    rates = {(pid, label): tuple(value / elapsed for value in by_owner[pid]) for pid, label in labels.items()}
    measurements = {(pid, label): framing[pid] for pid, label in labels.items() if pid in framing}
    return "ready", rates, tuple(value / elapsed for value in unattributed), measurements


def summarize(previous, current, elapsed, interval, udp=None):
    tcp_state, tcp, unknown, tcp_framing = tcp_rates(previous, current, elapsed, interval)
    udp = udp or {"state": "off"}
    protocols = {"tcp": tcp_state, "udp": udp["state"]}
    if "ready" not in protocols.values():
        return {"state": tcp_state, "protocols": protocols}
    udp_rates = udp.get("rates", {})
    udp_packets = udp.get("packets", {})
    rows = []
    framing = {"tcp": {}, "udp": {}}
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
        for protocol, measurements in (
            ("tcp", tcp_framing.get((pid, label), [])),
            ("udp", [(count, count * 8) for count in udp_packets.get((pid, label), ())]),
        ):
            for direction, (packets, headers) in zip(("rx", "tx"), measurements):
                if packets is None:
                    continue
                row[f"{protocol}_{direction}_packets"] = packets
                row[f"{protocol}_{direction}_header_bytes"] = headers
                total = framing[protocol].setdefault(direction, {"packets": 0, "header_bytes": 0})
                total["packets"] += packets
                total["header_bytes"] += headers
        rows.append(row)
    return {
        "state": "ready",
        "protocols": protocols,
        "framing": framing,
        "payload_rates": {
            protocol: {direction: round(sum(item[index] for item in rates.values()), 1)
                       for index, direction in enumerate(("rx", "tx"))}
            for protocol, rates in (("tcp", tcp), ("udp", udp_rates)) if protocols[protocol] == "ready"
        },
        "top": sorted(rows, key=lambda row: (-(row["rx"] + row["tx"]), row["pid"], row["name"]))[:8],
        "rx": sorted((row for row in rows if row["rx"]), key=lambda row: (-row["rx"], row["pid"], row["name"]))[:5],
        "tx": sorted((row for row in rows if row["tx"]), key=lambda row: (-row["tx"], row["pid"], row["name"]))[:5],
        "unattributed": {"rx": round(unknown[0], 1), "tx": round(unknown[1], 1)},
    }
