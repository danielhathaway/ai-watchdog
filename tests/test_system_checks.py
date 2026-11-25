import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from watchdog import store, system_checks as checks
from watchdog.common import BOOT_ID, configuration, write_json


class SystemChecksTests(unittest.TestCase):
    def setUp(self):
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        self.directory = Path(state.name)
        self.database = self.directory / "monitor.sqlite3"
        store.initialize(self.database)

    def test_listener_allowlist_ignores_both_loopbacks(self):
        output = """tcp LISTEN 0 128 127.0.0.1:8765 0.0.0.0:*
tcp LISTEN 0 128 [::1]:1234 [::]:*
tcp LISTEN 0 128 [::ffff:127.0.0.1]:4321 [::]:*
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
udp UNCONN 0 0 [ff02::fb%eth0]:5353 [::]:*
"""
        with patch.object(checks, "execute", return_value=output):
            check = checks.port_check(["tcp/22"])
            self.assertEqual("warn", check["status"])
            self.assertIn("udp/5353", check["detail"])
            self.assertNotIn("8765", check["detail"])
            self.assertEqual("pass", checks.port_check(["tcp/22", "udp/5353"])["status"])
        with patch.object(checks, "execute", side_effect=PermissionError):
            self.assertEqual("unknown", checks.port_check([])["status"])

    def test_ssh_effective_settings_and_unavailable_config(self):
        binary = self.directory / "sshd"
        binary.touch()
        output = "permitrootlogin no\npasswordauthentication yes\nkbdinteractiveauthentication no\npermitemptypasswords no\n"
        with patch.object(checks, "SSHD", binary):
            with patch.object(checks, "execute", return_value=output):
                row = checks.ssh_check()
                self.assertEqual("warn", row["status"])
                self.assertIn("passwordauthentication=yes", row["detail"])
            with patch.object(checks, "execute", side_effect=PermissionError):
                self.assertEqual("unknown", checks.ssh_check()["status"])

    def test_integrity_flags_drift_new_files_and_unsafe_baseline(self):
        baseline = self.directory / "watchdog-integrity.json"
        tracked = self.directory / "app.py"
        added = self.directory / "new.py"
        tracked.write_text("trusted")
        with patch.object(checks, "targets", return_value=[tracked]) as targets:
            self.assertEqual("unknown", checks.integrity(baseline, tracked, self.directory)["status"])
            checks.record_baseline(baseline, tracked, self.directory)
            self.assertEqual("pass", checks.integrity(baseline, tracked, self.directory)["status"])
            tracked.write_text("changed")
            added.touch()
            targets.return_value = [tracked, added]
            finding = checks.integrity(baseline, tracked, self.directory)
            self.assertEqual("fail", finding["status"])
            self.assertIn("2 added or changed files", finding["detail"])
            baseline.chmod(0o666)
            self.assertIn("invalid", checks.integrity(baseline, tracked, self.directory)["detail"])

    def test_health_reports_stale_heartbeat_and_insecure_state(self):
        settings = configuration(self.directory / "missing.json")
        config = self.directory / "config.json"
        token = self.directory / "token"
        token.touch(mode=0o600)
        self.database.chmod(0o600)
        monitor = SimpleNamespace(runtime=self.directory, database=self.database, settings=settings,
                                  response=lambda: {"watchdog_alive": True, "status": "observing"},
                                  baseline=self.directory / "baseline.json", config=config,
                                  observe_directory=self.directory)
        path = self.directory / "heartbeat.json"
        write_json(path, {"boot_id": BOOT_ID, "at": 100, "blocks": {}, "isolate": False})
        with patch.object(checks, "uptime", return_value=110):
            rows = {x["id"]: x["status"] for x in checks.health(monitor)}
        self.assertEqual(("pass", "pass"), (rows["heartbeat"], rows["state"]))
        token.chmod(0o644)
        with patch.object(checks, "uptime", return_value=160):
            rows = {x["id"]: x["status"] for x in checks.health(monitor)}
        self.assertEqual(("fail", "fail"), (rows["heartbeat"], rows["state"]))

    def test_scheduler_runs_only_due_groups_and_records_changes(self):
        settings = configuration(self.directory / "missing.json")
        warn = checks.result("ports", "Listeners", "warn", "tcp/22")
        checks.save(self.database, "health", 100, [])
        checks.save(self.database, "hardening", 100, [warn])
        checks.save(self.database, "hardening", 120, [warn])
        monitor = SimpleNamespace(database=self.database, settings=settings,
                                  stop=Mock(), ready=Mock())
        monitor.stop.wait.side_effect = [False, True]
        row = checks.result("supervisor", "Supervisor", "fail", "Stale")
        with patch.object(checks.time, "time", return_value=500), \
             patch.object(checks, "health", return_value=[row]) as health, \
             patch.object(checks, "hardening") as hardening:
            checks.run(monitor)
        health.assert_called_once_with(monitor)
        hardening.assert_not_called()
        with store.connect(self.database) as db:
            report = checks.read(db, settings)
            self.assertEqual(500, report["health"]["at"])
            self.assertEqual(120, report["hardening"]["at"])
            events = db.execute("SELECT severity FROM events ORDER BY id").fetchall()
        self.assertEqual(["medium", "high"], [row["severity"] for row in events])

    def test_configuration_rejects_invalid_listener_allowlist(self):
        path = self.directory / "config.json"
        path.write_text(json.dumps({"allowed_listeners": ["tcp/65536"]}))
        with self.assertRaisesRegex(ValueError, "allowed_listeners"):
            configuration(path)
