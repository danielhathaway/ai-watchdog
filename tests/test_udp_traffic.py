import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import process_traffic, udp_traffic

source = Path(__file__).resolve().parents[1] / "deploy" / "udp" / "collector.py"
spec = importlib.util.spec_from_file_location("watchdog_udp_collector", source)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class UDPTrafficTests(unittest.TestCase):
    def test_aggregated_probe_output_separates_receive_and_send(self):
        line = json.dumps({"type": "map", "data": {"@even": {"0": 20, "14": 1100, "15": 300, "19": 600}}})
        self.assertEqual((20, {7: [1100, 300], 9: [0, 600]}), collector.parse_map(line))
        self.assertEqual((21, {}), collector.parse_map('{"type":"map","data":{"@odd":{"0":21}}}'))

    def test_uses_only_fresh_private_collector_snapshots(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "snapshot.json"
            self.assertEqual("off", udp_traffic.read_snapshot(path)["state"])
            path.write_text(json.dumps({"ended": 100, "seconds": 5, "rows": [[7, "browser", 150, 45]]}))
            path.chmod(0o400)
            with patch.object(udp_traffic, "uptime", return_value=106):
                self.assertEqual({"state": "ready", "rates": {(7, "browser"): (30, 9)}},
                                 udp_traffic.read_snapshot(path))
            with patch.object(udp_traffic, "uptime", return_value=116):
                self.assertEqual("stale", udp_traffic.read_snapshot(path)["state"])
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                udp_traffic.read_snapshot(path)

    def test_udp_only_and_combined_processes_rank_by_total_and_keep_split_rates(self):
        row = process_traffic.SocketReading
        previous, current = {"a": row(7, 100, 20)}, {"a": row(7, 200, 70)}
        udp = {"state": "ready", "rates": {(7, "browser"): (10, 200), (8, "helper"): (40, 3)}}
        with patch.object(process_traffic, "name", return_value="browser"):
            report = process_traffic.summarize(previous, current, 5, 10, udp)
            udp_only = process_traffic.summarize(None, current, 5, 10, udp)
        self.assertEqual({"tcp": "ready", "udp": "ready"}, report["protocols"])
        self.assertEqual([7, 8], [row["pid"] for row in report["top"]])
        self.assertEqual([8, 7], [row["pid"] for row in report["rx"]])
        self.assertEqual({"pid": 7, "name": "browser", "rx": 30, "tx": 210,
                          "tcp_rx": 20, "tcp_tx": 10, "udp_rx": 10, "udp_tx": 200}, report["top"][0])
        self.assertEqual(200, udp_only["top"][0]["udp_tx"])
        self.assertIsNone(udp_only["top"][0]["tcp_tx"])
