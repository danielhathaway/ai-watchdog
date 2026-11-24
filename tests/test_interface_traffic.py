import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import monitor, process_traffic, sensors, store, udp_traffic
from watchdog.common import configuration


def counters_line(name, received, sent):
    return f"{name}: {received} 0 0 0 0 0 0 0 {sent} 0 0 0 0 0 0 0"


class InterfaceTrafficTests(unittest.TestCase):
    def test_vpn_and_bridge_are_recorded_without_entering_physical_total(self):
        counters = "\n".join((
            "header", "header", counters_line("wifi0", 3000, 20000),
            counters_line("wg0", 2000, 19000), counters_line("bridge0", 0, 1500),
            counters_line("lo", 0, 50000),
        ))
        previous = {"wifi0": (1000, 10000), "wg0": (1000, 10000), "bridge0": (0, 500)}
        with (
            patch.object(sensors.Path, "read_text", return_value=counters),
            patch.object(sensors, "physical_interface", side_effect=lambda name: name == "wifi0"),
        ):
            observed, rx, tx, breakdown = sensors.traffic(previous, 110, 100, 10)
        self.assertEqual((200, 1000, 10), (rx, tx, breakdown["window_seconds"]))
        self.assertNotIn("lo", observed)
        self.assertEqual({
            "wifi0": (True, 1000), "wg0": (False, 900), "bridge0": (False, 100),
        }, {item["name"]: (item["counted"], item["tx"]) for item in breakdown["interfaces"]})

    def test_virtual_only_host_uses_one_main_default_route(self):
        with (
            patch.object(sensors, "physical_interface", return_value=False),
            patch.object(sensors, "execute", side_effect=[
                '[{"dev":"eth0","metric":100},{"dev":"wg0","metric":500}]', "[]",
            ]),
        ):
            self.assertEqual({"method": "default", "uplinks": ["eth0"]}, sensors.select_uplinks({"eth0", "wg0"}))

    def test_spike_breakdowns_survive_event_cooldown_and_old_samples_do_not_train_traffic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = monitor.Monitor(configuration(root / "missing"), root / "db", root, baseline=root / "missing")
            current = 1_700_000_000
            with store.connect(app.database) as db:
                db.executemany("INSERT INTO samples(at,rx,tx,connections,failures,risk,training) VALUES (?,?,?,?,0,0,1)",
                               [(current - 40 - i, 1, 2, 5) for i in range(35)])
            breakdown = {"method": "physical", "uplinks": ["wifi0"], "window_seconds": 10,
                         "interfaces": [{"name": "wifi0", "counted": True, "rx": 0, "tx": 500000}]}
            with (
                patch.object(monitor.time, "time", side_effect=[current, current + 10, current + 20]),
                patch.object(app, "response", return_value={"status": "observing", "reason": "",
                                                          "watchdog_alive": True, "blocked": []}),
                patch.object(sensors, "traffic", return_value=({}, 0, 500000, breakdown)),
                patch.object(process_traffic, "capture", return_value={}),
                patch.object(udp_traffic, "read_snapshot", return_value={"state": "off"}),
                patch.object(sensors, "sockets", return_value=(5, 0, 0)),
                patch.object(sensors, "neighbors", return_value=[
                    ("00:11:22:33:44:55", "192.168.1.4", "wifi0")
                ]),
                patch.object(sensors, "ssh_failures", return_value=([], None, False)),
            ):
                first = app.scan(active=True)
                self.assertEqual({"rx": 0, "tx": 0, "connections": 35}, first["baseline_samples"])
                self.assertEqual([], first["deviations"])
                with store.connect(app.database) as db:
                    db.executemany("INSERT INTO samples(at,rx,tx,connections,failures,risk,training) VALUES (?,?,?,?,0,0,1)",
                                   [(current + i / 10, 5, 20, 5) for i in range(30)])
                app.scan(active=True)
                app.scan(active=True)
            with store.connect(app.database) as db:
                data = store.snapshot(db, current + 20)
            self.assertEqual(2, len(data["interface_spikes"]))
            self.assertEqual([500000, 500000], [item["interfaces"][0]["tx"] for item in data["interface_spikes"]])
            self.assertEqual(1, len([event for event in data["events"] if event["kind"] == "anomaly"]))
            self.assertIsNone(data["samples"][0]["tx"])
            self.assertEqual(5, data["samples"][0]["connections"])
