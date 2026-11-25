import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import analysis, monitor, process_traffic, sensors, store
from watchdog.common import configuration


class ProcessTrafficTests(unittest.TestCase):
    def test_socket_parser_skips_loopback_and_handles_kernel_ownership_and_counters(self):
        output = '\n'.join((
            'ESTAB 0 0 10.0.0.2:41000 203.0.113.3:443 users:(("web",pid=7,fd=3),("web",pid=7,fd=4)) '
            'timer:(keepalive,10sec,0) uid:1000 ino:12 sk:ac <-> cubic bytes_sent:200 bytes_acked:120 bytes_received:1024',
            'ESTAB 0 0 [::ffff:127.0.0.1]:41000 [::ffff:127.0.0.1]:8765 ino:13 sk:ad <-> bytes_sent:42',
            'ESTAB 0 0 10.0.0.2:41001 203.0.113.3:443 users:(("web",pid=7,fd=5),("worker",pid=8,fd=7)) '
            'ino:15 sk:ae <-> bytes_acked:300',
            'TIME-WAIT 0 0 10.0.0.2:41002 203.0.113.3:443 timer:(timewait,10sec,0) sk:af',
        ))
        readings = {key[0]: value for key, value in process_traffic.parse(output).items()}
        self.assertEqual({
            "ac": process_traffic.SocketReading(7, 1024, 200),
            "ae": process_traffic.SocketReading(None, 0, 300),
            "af": process_traffic.SocketReading(None, 0, 0),
        }, readings)

    def test_tcp_segment_deltas_supply_a_minimum_header_estimate(self):
        base = 'ESTAB 0 0 10.0.0.2:41000 203.0.113.3:443 users:(("web",pid=7,fd=3)) ino:12 sk:ac <-> cubic '
        previous = process_traffic.parse(base + "segs_in:10 segs_out:15 bytes_received:1024")
        current = process_traffic.parse(base + "segs_in:27 segs_out:26 bytes_received:2048")
        with patch.object(process_traffic, "name", return_value="web"):
            summary = process_traffic.summarize(previous, current, 10, 10)
        self.assertEqual({"packets": 17, "header_bytes": 680}, summary["framing"]["tcp"]["rx"])
        self.assertEqual(11, summary["top"][0]["tcp_tx_packets"])
        self.assertEqual(440, summary["top"][0]["tcp_tx_header_bytes"])
        self.assertEqual(102.4, summary["payload_rates"]["tcp"]["rx"])

    def test_deltas_rank_owners_and_do_not_assign_a_socket_that_changed_hands(self):
        row = process_traffic.SocketReading
        previous = {"a": row(7, 200, 50), "b": row(9, 1000, 20), "c": row(8, 40, 80)}
        current = {"a": row(7, 1200, 100), "b": row(7, 1200, 20), "c": row(8, 10, 1080), "d": row(7, 500, 0)}
        with patch.object(process_traffic, "name", side_effect=lambda pid: f"process-{pid}"):
            report = process_traffic.summarize(previous, current, 10, 10)
        self.assertEqual([7], [item["pid"] for item in report["rx"]])
        self.assertEqual(150, report["rx"][0]["rx"])
        self.assertEqual([8, 7], [item["pid"] for item in report["tx"]])
        self.assertEqual({"rx": 20, "tx": 0}, report["unattributed"])
        self.assertEqual("warming", process_traffic.summarize(None, current, 10, 10)["state"])

    def test_monitor_saves_directional_attribution_on_traffic_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = configuration(root / "missing.json")
            app = monitor.Monitor(settings, root / "db", root, baseline=root / "missing.json")
            row = process_traffic.SocketReading
            with patch.object(process_traffic, "name", return_value="web"):
                attribution = process_traffic.summarize({"a": row(7, 1024, 0)}, {"a": row(7, 2001024, 0)}, 10, 10)
            window = {"at": 100, "window_start": 90, "window_seconds": 10, "attribution": attribution,
                      "interface": {"method": "physical", "uplinks": ["eth0"], "interfaces": [], "rx": 300000, "tx": 100}}
            with (
                patch.object(app, "response", return_value={
                    "status": "observing", "reason": "", "watchdog_alive": True, "blocked": [],
                }),
                patch.object(monitor, "uptime", return_value=100),
                patch.object(monitor.time, "time", return_value=100),
                patch.object(app.network, "snapshot", return_value=window),
                patch.object(sensors, "sockets", return_value=(1, 0, 0)),
                patch.object(sensors, "neighbors", return_value=[]),
                patch.object(sensors, "ssh_failures", return_value=([], None, False)),
                patch.object(analysis, "deviations", return_value=[{"metric": "rx", "observed": 300000, "threshold": 250000}]),
            ):
                app.scan()
            with store.connect(app.database) as db:
                dashboard = store.snapshot(db, 0)
            report = dashboard["events"][0]["attribution"]
            self.assertEqual("rx", report["direction"])
            self.assertEqual([{"pid": 7, "name": "web", "rx": 200000, "tx": 0}], report["processes"])
