import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import analysis, monitor, process_traffic, sensors, store, udp_traffic
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
            app.previous_sockets = {"a": row(7, 1024, 0)}
            app.previous_socket_at = 90
            with (
                patch.object(app, "response", return_value={
                    "status": "observing", "reason": "", "watchdog_alive": True, "blocked": [],
                }),
                patch.object(monitor, "uptime", return_value=100),
                patch.object(sensors, "traffic", return_value=({}, 300000, 100, {"method": "physical", "uplinks": ["eth0"], "interfaces": []})),
                patch.object(sensors, "sockets", return_value=(1, 0, 0)),
                patch.object(sensors, "neighbors", return_value=[]),
                patch.object(sensors, "ssh_failures", return_value=([], None, False)),
                patch.object(udp_traffic, "read_snapshot", return_value={"state": "off"}),
                patch.object(process_traffic, "capture", return_value={"a": row(7, 2001024, 0)}),
                patch.object(process_traffic, "name", return_value="web"),
                patch.object(analysis, "deviations", return_value=[{"metric": "rx", "observed": 300000, "threshold": 250000}]),
            ):
                app.scan()
            with store.connect(app.database) as db:
                dashboard = store.snapshot(db, 0)
            report = dashboard["events"][0]["attribution"]
            self.assertEqual("rx", report["direction"])
            self.assertEqual([{"pid": 7, "name": "web", "rx": 200000, "tx": 0}], report["processes"])
