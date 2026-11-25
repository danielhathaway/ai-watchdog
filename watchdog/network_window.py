import logging
import subprocess
import time
from collections import defaultdict

from . import process_traffic, sensors, udp_traffic
from .common import uptime

BUCKET = udp_traffic.BUCKET_SECONDS
EDGE_TOLERANCE = 0.75
UDP_PUBLISH_GRACE = 2
SAMPLE_ERRORS = (OSError, ValueError, KeyError, subprocess.SubprocessError)


def combine_udp(buckets, start, end):
    required = [buckets.get(edge) for edge in range(start + BUCKET, end + 1, BUCKET)]
    if not all(sample and sample["state"] == "ready" for sample in required):
        return {"state": "off" if all(sample and sample["state"] == "off" for sample in required) else "unavailable"}
    totals = defaultdict(lambda: [0.0, 0.0])
    for sample in required:
        for key, (rx, tx) in sample["rates"].items():
            totals[key][0] += rx * BUCKET
            totals[key][1] += tx * BUCKET
    combined = {"state": "ready", "rates": {
        key: (rx / (end - start), tx / (end - start)) for key, (rx, tx) in totals.items()
    }}
    if all("packets" in sample for sample in required):
        packets = defaultdict(lambda: [0, 0])
        for sample in required:
            for key, (rx, tx) in sample["packets"].items():
                packets[key][0] += rx
                packets[key][1] += tx
        combined["packets"] = packets
    return combined


class NetworkSampler:
    def __init__(self, interval):
        self.seconds = ((interval + BUCKET - 1) // BUCKET) * BUCKET
        self.latest = None
        self.previous_edge = None
        self.buckets = {}

    def snapshot(self):
        sample = self.latest
        return sample if sample and 0 <= uptime() - sample["edge"] < 2 * self.seconds else None

    def run(self, stop):
        edge = (int(uptime()) // BUCKET + 1) * BUCKET
        while not stop.wait(max(0, edge - uptime())):
            now = uptime()
            if now - edge >= BUCKET:
                edge = int(now) // BUCKET * BUCKET
            try:
                self.capture(edge, stop)
            except Exception:
                logging.exception("Aligned network sampling failed")
            edge += BUCKET

    def capture(self, edge, stop):
        aligned = edge % self.seconds == 0
        if aligned:
            # Sample running counters near the same monotonic edge as the UDP collector.
            # A sensor that misses the edge cannot represent this window.
            counters = self.read_edge(sensors.interface_counters, edge)
            sockets = self.read_edge(process_traffic.capture, edge)

        self.buckets[edge] = self.wait_udp(edge, stop)
        self.buckets = {end: sample for end, sample in self.buckets.items() if end > edge - self.seconds}
        if not aligned:
            return

        previous = self.previous_edge
        self.previous_edge = (edge, counters, sockets)
        if previous is None or previous[0] != edge - self.seconds:
            return

        udp = combine_udp(self.buckets, edge - self.seconds, edge)
        interface = {"method": "unavailable", "uplinks": [], "interfaces": [], "rx": None, "tx": None}
        if counters is not None:
            try:
                interface = sensors.interface_rates(previous[1] or {}, counters, self.seconds)
            except SAMPLE_ERRORS:
                logging.exception("Traffic uplink selection failed")
        attribution = process_traffic.summarize(previous[2], sockets, self.seconds, self.seconds, udp)
        ended_at = time.time() - (uptime() - edge)
        self.latest = {
            "edge": edge, "at": ended_at, "window_start": ended_at - self.seconds,
            "window_seconds": self.seconds, "interface": interface, "attribution": attribution,
        }

    @staticmethod
    def read_edge(read, edge):
        if uptime() - edge <= EDGE_TOLERANCE:
            try:
                sample = read()
                if uptime() - edge <= EDGE_TOLERANCE:
                    return sample
            except SAMPLE_ERRORS:
                logging.exception("Network counter snapshot failed")
        return None

    @staticmethod
    def wait_udp(edge, stop):
        while True:
            try:
                snapshot = udp_traffic.read_snapshot()
            except SAMPLE_ERRORS + (TypeError, RecursionError):
                return {"state": "unavailable"}
            if snapshot["state"] == "off" or snapshot.get("ended") == edge:
                return snapshot
            if snapshot.get("ended", 0) > edge or uptime() >= edge + UDP_PUBLISH_GRACE or stop.wait(.08):
                return {"state": "unavailable"}
