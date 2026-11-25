import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from watchdog import analysis, monitor, responder, sensors, store
from watchdog.common import BOOT_ID, blockable, configuration, write_json
from watchdog.server import Handler


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.config = configuration(self.directory / "missing.json")

    def test_baseline_flags_sustained_deviation_and_handles_cold_start(self):
        current = {"rx": 900_000, "tx": 12_000, "connections": 20}
        history = {"rx": [1000] * 29, "tx": [10_000] * 30, "connections": [18] * 30}
        self.assertEqual([], analysis.deviations(current, history))
        history["rx"].append(1000)
        self.assertEqual(
            [{"metric": "rx", "observed": 900_000, "threshold": 251_000}],
            analysis.deviations(current, history),
        )

    def test_fingerprints_capture_permissions_and_missing_files(self):
        path = self.directory / "file"
        self.assertEqual({"state": "missing"}, sensors.fingerprint(path))
        path.write_text("trusted")
        path.chmod(0o644)
        original = sensors.fingerprint(path)
        path.chmod(0o600)
        self.assertEqual(original["sha256"], sensors.fingerprint(path)["sha256"])
        self.assertNotEqual(original, sensors.fingerprint(path))

    def test_heartbeat_rejects_symlinks_stale_and_foreign_boot(self):
        runtime = self.directory
        path = runtime / "heartbeat.json"
        packet = {"boot_id": BOOT_ID, "at": 100, "blocks": {}, "isolate": False}
        with patch.object(responder, "MONITOR_RUNTIME", runtime):
            write_json(path, packet)
            self.assertEqual(packet, responder.heartbeat(os.getuid(), 114, self.config))
            with self.assertRaises(ValueError):
                responder.heartbeat(os.getuid(), 146, self.config)
            with self.assertRaises(ValueError):
                responder.heartbeat(os.getuid() + 1, 110, self.config)
            write_json(path, {**packet, "boot_id": "different"})
            with self.assertRaises(ValueError):
                responder.heartbeat(os.getuid(), 110, self.config)
            target = path.with_suffix(".other")
            path.rename(target)
            path.symlink_to(target)
            with self.assertRaises(OSError):
                responder.heartbeat(os.getuid(), 110, self.config)

    def test_firewall_rule_scope_expiry_and_protected_addresses(self):
        config_path = self.directory / "config.json"
        write_json(config_path, {"protected_networks": ["1.1.1.0/24"]})
        protected = configuration(config_path)["protected_networks"]
        for address in ("1.1.1.1", "127.0.0.1", "192.168.0.1", "224.0.0.1",
                        "::ffff:8.8.8.8", "2606:4700::1%eth0", "8.8.8.8 counter accept"):
            self.assertIsNone(blockable(address, protected))
        self.assertEqual("8.8.8.8", blockable("8.8.8.8", protected))
        rules = responder.ruleset({"8.8.8.8": 900, "2001:4860::1": 300}, False, ("00:11:22:33:44:55",))
        self.assertIn("8.8.8.8 timeout 900s", rules)
        self.assertIn("2001:4860::1 timeout 300s", rules)
        self.assertIn("ether saddr 00:11:22:33:44:55", rules)
        self.assertNotIn("flush ruleset", rules)
        isolated = responder.ruleset({}, True)
        self.assertIn('iifname != "lo" counter drop', isolated)
        self.assertIn('oifname != "lo" counter drop', isolated)

    def test_missing_heartbeat_isolates_in_enforcement_and_observe_only_reports(self):
        for enforcement in (False, True):
            with self.subTest(enforcement=enforcement):
                for path in self.directory.glob("*.json"):
                    path.unlink()
                settings = {**self.config, "enforce": enforcement}
                with (
                    patch.object(responder, "RESPONSE_STATE", self.directory),
                    patch.object(responder, "RESPONSE_RUNTIME", self.directory),
                    patch.object(responder, "uptime", side_effect=[10, 110, 111]),
                    patch.object(responder.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=os.getuid())),
                    patch.object(responder, "heartbeat", side_effect=FileNotFoundError),
                    patch.object(responder, "notify"),
                    patch.object(responder, "apply_firewall") as firewall,
                    patch.object(responder, "isolate_links", return_value=[]) as bring_down,
                    patch.object(responder.time, "sleep", side_effect=InterruptedError),
                ):
                    with self.assertLogs(level="CRITICAL"), self.assertRaises(InterruptedError):
                        responder.loop(settings)
                state = json.loads((self.directory / "status.json").read_text())
                self.assertEqual("isolated" if enforcement else "would-isolate", state["status"])
                self.assertEqual(enforcement, (self.directory / "isolation.json").exists())
                self.assertEqual(enforcement, firewall.called)
                self.assertEqual(enforcement, bring_down.called)

    def test_user_supervisor_never_enforces_even_if_configuration_requests_it(self):
        settings = {**self.config, "enforce": True}
        response_dir = self.directory / "response"
        response_dir.mkdir()
        request = {"isolate": True, "blocks": {"8.8.8.8": 500}}
        with (
            patch.object(responder, "uptime", side_effect=[10, 11, 12]),
            patch.object(responder, "heartbeat", return_value=request),
            patch.object(responder, "dashboard_alive", return_value=True),
            patch.object(responder, "notify"),
            patch.object(responder, "apply_firewall") as firewall,
            patch.object(responder, "isolate_links") as change_links,
            patch.object(responder.time, "sleep", side_effect=InterruptedError),
        ):
            with self.assertLogs(level="CRITICAL"), self.assertRaises(InterruptedError):
                responder.loop(settings, user_directory=self.directory)
        status = json.loads((response_dir / "status.json").read_text())
        self.assertEqual(("observe", "would-isolate"), (status["mode"], status["status"]))
        firewall.assert_not_called()
        change_links.assert_not_called()

    def test_unmitigated_abuse_triggers_link_containment_after_three_failures(self):
        settings = {**self.config, "enforce": True}
        request = {"isolate": False, "blocks": {"8.8.8.8": 500}}
        with (
            patch.object(responder, "RESPONSE_STATE", self.directory),
            patch.object(responder, "RESPONSE_RUNTIME", self.directory),
            patch.object(responder, "uptime", side_effect=[10, 11, 12, 16, 17, 21, 22]),
            patch.object(responder.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=os.getuid())),
            patch.object(responder, "heartbeat", return_value=request),
            patch.object(responder, "dashboard_alive", return_value=True),
            patch.object(responder, "protected_addresses", return_value=set()),
            patch.object(responder, "notify"),
            patch.object(responder, "apply_firewall", side_effect=PermissionError),
            patch.object(responder, "isolate_links", return_value=[]) as bring_down,
            patch.object(responder.time, "sleep", side_effect=[None, None, InterruptedError()]),
        ):
            with self.assertLogs(level="CRITICAL"), self.assertRaises(InterruptedError):
                responder.loop(settings)
        state = json.loads((self.directory / "isolation.json").read_text())
        self.assertIn("mitigating SSH abuse", state["reason"])
        self.assertEqual(1, bring_down.call_count)

    def test_monitor_persists_neighbors_and_deduplicates_ssh_failures(self):
        db_path = self.directory / "monitor.sqlite3"
        app = monitor.Monitor(self.config, db_path, self.directory, baseline=self.directory / "missing")
        observed = 1_700_000_000
        failures = [(f"cursor-{index}", "8.8.8.8", observed - 1) for index in range(12)]
        with (
            patch.object(app, "response", return_value={
                "status": "observing", "reason": "", "watchdog_alive": True, "blocked": [],
            }),
            patch.object(monitor.time, "time", return_value=observed),
            patch.object(sensors, "sockets", return_value=(12, 0, 0)),
            patch.object(sensors, "neighbors", return_value=[("00:11:22:33:44:55", "192.168.1.4", "eth0")]),
            patch.object(sensors, "ssh_failures", return_value=(failures, "cursor-11", False)),
        ):
            for _ in range(2):
                result = app.scan()
                self.assertEqual(12, result["failed_ssh"])
                self.assertEqual(1, result["block_candidates"])
        with store.connect(db_path) as db:
            data = store.snapshot(db, observed)
        self.assertEqual(2, len(data["samples"]))
        self.assertEqual(1, data["device_count"])
        self.assertEqual(1, data["alert_count"])
        self.assertIn("8.8.8.8", json.loads((self.directory / "heartbeat.json").read_text())["blocks"])

    def test_console_rejects_anonymous_access_cross_origin_and_invalid_hosts(self):
        handler = Handler.__new__(Handler)
        handler.server = SimpleNamespace(authority="127.0.0.1:8765", origin="http://127.0.0.1:8765", token="secret")
        handler.path = "/api/check"
        cases = [
            ("evil.test:8765", None, "Bearer secret", False, 421),
            ("127.0.0.1:8765", "http://evil.test", "Bearer secret", True, 403),
            ("127.0.0.1:8765", None, "", False, 401),
            ("127.0.0.1:8765", "http://127.0.0.1:8765", "Bearer secret", True, None),
        ]
        for host, origin, auth, mutation, expected in cases:
            handler.headers = SimpleNamespace(
                get_all=lambda key: [host] if key == "Host" else [origin] if origin else None,
                get=lambda *_: auth,
            )
            with patch.object(handler, "reply") as reply:
                self.assertEqual(expected is None, handler.authorized(mutation))
                if expected:
                    self.assertEqual(expected, reply.call_args.args[0])
                else:
                    reply.assert_not_called()
