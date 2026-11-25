import threading
import unittest
from unittest.mock import patch

from watchdog import network_window, process_traffic, sensors


class NetworkWindowTests(unittest.TestCase):
    def test_requires_every_udp_bucket_and_sums_bytes_over_the_shared_window(self):
        key = (7, "browser")
        buckets = {
            100: {"state": "ready", "rates": {key: (10000, 10000)}},
            105: {"state": "ready", "rates": {key: (100, 20)}},
            110: {"state": "ready", "rates": {key: (300, 0), (9, "dns"): (2, 4)}},
        }
        self.assertEqual({"state": "ready", "rates": {key: (200, 10), (9, "dns"): (1, 2)}},
                         network_window.combine_udp(buckets, 100, 110))
        buckets[105]["packets"] = {key: (3, 2)}
        self.assertNotIn("packets", network_window.combine_udp(buckets, 100, 110))
        buckets[110]["packets"] = {key: (4, 3)}
        self.assertEqual([7, 5], network_window.combine_udp(buckets, 100, 110)["packets"][key])
        del buckets[105]
        self.assertEqual({"state": "unavailable"}, network_window.combine_udp(buckets, 100, 110))

    def test_uses_identical_edges_for_interface_tcp_and_udp_rates(self):
        stop = threading.Event()
        sampler = network_window.NetworkSampler(10)
        reading = process_traffic.SocketReading
        first = {"wifi0": (1000, 1000, 1, 1), "wg0": (1000, 1000, 1, 1)}
        last = {"wifi0": (9000, 4000, 10, 5), "wg0": (8000, 3500, 9, 4)}
        buckets = {
            100: {"state": "off"},
            105: {"state": "ready", "rates": {(7, "browser"): (100, 40)}},
            110: {"state": "ready", "rates": {(7, "browser"): (300, 20)}},
        }
        with (
            patch.object(sampler, "wait_udp", side_effect=lambda edge, _: buckets[edge]),
            patch.object(sampler, "read_edge", side_effect=lambda read, _: read()),
            patch.object(sensors, "interface_counters", side_effect=[first, last]),
            patch.object(sensors, "physical_interface", side_effect=lambda name: name == "wifi0"),
            patch.object(process_traffic, "capture", side_effect=[{"a": reading(7, 0, 0)}, {"a": reading(7, 3000, 2000)}]),
            patch.object(process_traffic, "name", return_value="browser"),
            patch.object(network_window, "uptime", return_value=111),
            patch.object(network_window.time, "time", return_value=1001),
        ):
            for edge in (100, 105, 110):
                sampler.capture(edge, stop)
            report = sampler.snapshot()
        self.assertEqual((990, 1000, 10), (report["window_start"], report["at"], report["window_seconds"]))
        self.assertEqual(800, report["interface"]["rx"])
        self.assertEqual(700, next(item for item in report["interface"]["interfaces"] if item["name"] == "wg0")["rx"])
        self.assertEqual((300, 200), tuple(report["attribution"]["top"][0][metric] for metric in ("tcp_rx", "udp_rx")))
        self.assertEqual((200, 30), tuple(report["attribution"]["top"][0][metric] for metric in ("tcp_tx", "udp_tx")))

    def test_does_not_substitute_an_older_udp_window(self):
        with (
            patch.object(network_window.udp_traffic, "read_snapshot", return_value={
                "state": "ready", "ended": 105, "rates": {(7, "browser"): (300, 20)},
            }),
            patch.object(network_window, "uptime", return_value=113),
        ):
            self.assertEqual({"state": "unavailable"}, network_window.NetworkSampler.wait_udp(110, threading.Event()))
