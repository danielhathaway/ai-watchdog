import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from deploy.udp.multicast_collector import parse_output
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

    def test_scoped_ipv6_merges_owners_and_saves_successful_inventory(self):
        output = """udp UNCONN 0 0 [ff02::c]%wlp5s0:3702 [::]:* users:(("python3",pid=14,fd=7)) ino:51 cgroup:/user.slice/user@1000.service/session.slice/gvfs-daemon.service
udp UNCONN 0 0 [ff02::c%wlp5s0]:3702 [::]:* users:(("helper",pid=20,fd=8)) ino:52 cgroup:/system.slice/helper.service
udp UNCONN 0 0 [fe80::a]%wlp5s0:3702 [::]:* ino:53 cgroup:/system.slice/discovery.service
udp UNCONN 0 0 [::]:5353 [::]:* cgroup:/system.slice/avahi-daemon.service
udp UNCONN 0 0 *:9999 *:*
"""
        with patch.object(checks, "execute", return_value=output) as execute, \
             patch.object(checks, "interface_lookup", return_value=({}, {})), \
             patch.object(checks, "process_app", side_effect=lambda name, *args: "wsdd" if name == "python3" else name):
            check = checks.port_check(["udp/5353"])
        execute.assert_called_once_with(checks.SS, "-H", "-lntu", "-p", "-e")
        entries = {row["address"]: row for row in check["listeners"]}
        scoped = entries["ff02::c%wlp5s0"]
        self.assertEqual(2, scoped["socket_count"])
        self.assertEqual(["wsdd", "helper"], [row["app"] for row in scoped["processes"]])
        self.assertEqual(["gvfs-daemon.service", "helper.service"], scoped["services"])
        self.assertEqual(["discovery.service"], entries["fe80::a%wlp5s0"]["services"])
        self.assertTrue(entries["::"]["allowed"])
        self.assertIn("owner unavailable", check["detail"])
        checks.save(self.database, "hardening", 100, [check])
        with store.connect(self.database) as db:
            saved = db.execute("SELECT listeners FROM listener_inventory WHERE at = 100").fetchone()[0]
            self.assertEqual(check["listeners"], json.loads(saved))
            store.expire(db, 86401 + 100, 1)
            self.assertEqual(0, db.execute("SELECT count(*) FROM listener_inventory").fetchone()[0])

    def test_service_interface_allowlist_does_not_approve_ambiguous_or_shared_sockets(self):
        import ipaddress

        def row(address, process="wsdd", pid=2):
            return (f'udp UNCONN 0 0 {address}:3702 0.0.0.0:* users:(("{process}",pid={pid},fd=7)) '
                    "ino:51 cgroup:/user.slice/gvfs-daemon.service")

        output = "\n".join((
            row("192.168.1.20"), row("[ff02::c]%wlp5s0"), row("10.5.0.2"), row("172.17.0.1"),
            row("0.0.0.0"), row("239.255.255.250"), row("192.168.1.21"),
            row("192.168.1.22"), row("192.168.1.22", "other", 3),
        ))
        addresses = {ipaddress.ip_address(ip): names for ip, names in {
            "192.168.1.20": {"wlp5s0"}, "10.5.0.2": {"nordlynx"}, "172.17.0.1": {"docker0"},
            "192.168.1.21": {"wlp5s0", "docker0"}, "192.168.1.22": {"wlp5s0"},
        }.items()}
        rules = [{"service": "gvfs-daemon.service", "app": "wsdd", "interface": "wlp5s0", "protocol": "udp"}]
        entries = {row["address"]: row for row in checks.listeners(output, rules=rules, interfaces=(addresses, {}))}
        self.assertEqual({"ff02::c%wlp5s0"},
                         {name for name, row in entries.items() if row["allowed"]})
        self.assertEqual("nordlynx", entries["10.5.0.2"]["interface"])
        self.assertEqual("docker0", entries["172.17.0.1"]["interface"])
        self.assertIsNone(entries["239.255.255.250"]["interface"])
        self.assertIsNone(entries["192.168.1.21"]["interface"])
        self.assertEqual(2, entries["192.168.1.22"]["socket_count"])

    def test_multicast_egress_is_saved_without_approving_unverified_receive_scope(self):
        import ipaddress

        output = """udp UNCONN 0 0 *:10000 *:* users:(("wsdd",pid=2,fd=7)) ino:51 cgroup:/user.slice/gvfs-daemon.service
udp UNCONN 0 0 *:10001 *:* users:(("wsdd",pid=2,fd=8)) ino:52 cgroup:/user.slice/gvfs-daemon.service
udp UNCONN 0 0 *:10001 *:* users:(("wsdd",pid=2,fd=9)) ino:53 cgroup:/user.slice/gvfs-daemon.service
udp UNCONN 0 0 *:10002 *:* users:(("wsdd",pid=2,fd=10)) ino:54 cgroup:/user.slice/gvfs-daemon.service
"""
        rule = {"service": "gvfs-daemon.service", "interface": "wlp5s0", "app": "wsdd"}
        interfaces = ({ipaddress.ip_address("192.0.2.1"): {"wlp5s0"}}, {"3": "nordlynx"})
        values = [
            {"device": "", "ipv4": "192.0.2.1"}, {"device": "wlp5s0"}, None,
            {"device": "wlp5s0", "ipv6": 3},
        ]
        with patch.object(checks.multicast, "socket_options", side_effect=values):
            entries = checks.listeners(output, rules=[rule], interfaces=interfaces)
        first, shared, scoped = entries
        self.assertFalse(first["allowed"])
        self.assertEqual("wlp5s0", first["sockets"][0]["multicast_send"]["ipv4"]["interface"])
        self.assertIsNone(first["sockets"][0]["receive_interface"])
        self.assertFalse(shared["allowed"])
        self.assertFalse(shared["sockets"][1]["socket_options_available"])
        self.assertTrue(scoped["allowed"])
        self.assertEqual("wlp5s0", scoped["sockets"][0]["receive_interface"])
        self.assertEqual("nordlynx", scoped["sockets"][0]["multicast_send"]["ipv6"]["interface"])

    def test_kernel_helper_matches_socket_cookie_and_never_allows_from_membership(self):
        snapshot = parse_output("S 51 185 3 4 0\nM 51 185 4 3\nM 51 185 6 4\n")
        output = """udp UNCONN 0 0 *:10000 *:* users:(("wsdd",pid=2,fd=7)) ino:51 sk:b9 cgroup:/user.slice/gvfs-daemon.service
udp UNCONN 0 0 *:10001 *:* users:(("wsdd",pid=2,fd=8)) ino:51 sk:ba cgroup:/user.slice/gvfs-daemon.service
"""
        rule = {"service": "gvfs-daemon.service", "interface": "wlp5s0", "app": "wsdd"}
        with patch.object(checks.multicast, "socket_options", return_value=None) as probe:
            current, reused = checks.listeners(output, rules=[rule], helper=snapshot,
                                               interfaces=({}, {"3": "wlp5s0", "4": "nordlynx"}))
        probe.assert_called_once_with(2, 8, 51)
        self.assertFalse(current["allowed"])
        socket = current["sockets"][0]
        self.assertIsNone(socket["receive_interface"])
        self.assertEqual("kernel helper", socket["socket_options_source"])
        self.assertEqual("nordlynx", socket["multicast_send"]["ipv4"]["interface"])
        self.assertEqual(["wlp5s0", "nordlynx"], [item["interface"] for item in socket["multicast_memberships"]])
        self.assertFalse(reused["sockets"][0]["socket_options_available"])

    def test_kernel_helper_rejects_stale_and_user_writable_snapshots(self):
        path = self.directory / "snapshot.json"
        sockets = {"51:b9": {"bound": 0, "ipv4": 3, "ipv6": 0, "memberships": []}}
        path.write_text(json.dumps({"at": 50, "sockets": sockets}))
        info = SimpleNamespace(st_uid=0, st_mode=0o100440)
        with patch.object(checks.multicast.os, "fstat", return_value=info):
            self.assertEqual(sockets, checks.multicast.helper_snapshot(path, now=51))
            self.assertEqual({}, checks.multicast.helper_snapshot(path, now=151))
            info.st_mode = 0o100460
            self.assertEqual({}, checks.multicast.helper_snapshot(path, now=51))

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
        warn["inventory_version"] = checks.LISTENER_INVENTORY_VERSION
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
