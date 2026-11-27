import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from deploy.udp.multicast_collector import parse_output
from watchdog import clamd_backend, store, system_checks as checks
from watchdog.common import BOOT_ID, configuration, write_json


class SystemChecksTests(unittest.TestCase):
    def setUp(self):
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        self.directory = Path(state.name)
        self.database = self.directory / "monitor.sqlite3"
        store.initialize(self.database)

    def test_clamav_reports_detections_and_scan_errors_separately(self):
        target = self.directory / "incoming files"

        def scan_output(code, report):
            def run(arguments, **options):
                self.assertEqual(["--", str(target)], arguments[-2:])
                self.assertIn("--follow-file-symlinks=0", arguments)
                self.assertIn("--fail-if-cvd-older-than=7", arguments)
                options["stdout"].write(report.encode())
                return subprocess.CompletedProcess(arguments, code)
            return run

        for code, output, status, detail in (
            (0, "Scanned files: 2\n", "pass", "2 scanned files"),
            (0, "Scanned files: 0\n", "skipped", "did not scan any files"),
            (1, "Infected files: 1\nTotal errors: 1\n", "fail", "test-signature FOUND"),
            (2, "", "warn", "could not complete"),
            (0, "Scanned files: 2\nTotal errors: 1\n", "warn", "could not complete"),
        ):
            with self.subTest(code=code, status=status):
                findings = f"{target}/sample: test-signature FOUND\n" if code == 1 else ""
                report = findings + "----------- SCAN SUMMARY -----------\n" + output
                with patch.object(checks.subprocess, "run", side_effect=scan_output(code, report)):
                    row = checks.antivirus([str(target)])
                self.assertEqual(status, row["status"])
                self.assertIn(detail, row["detail"])
                self.assertEqual(int("Total errors:" in output), row["scan_errors"])

        for failure, detail in ((FileNotFoundError(), "not found"), (subprocess.TimeoutExpired("clamscan", 900), "exceeded")):
            with patch.object(checks.subprocess, "run", side_effect=failure):
                row = checks.antivirus([str(target)])
            self.assertEqual("warn", row["status"])
            self.assertIn(detail, row["detail"])

    def test_antivirus_readiness_reads_the_daily_signature_timestamp(self):
        published = 1795588019
        output = "ClamAV 1.5.4/28194/Wed Nov 25 06:26:59 2026\n"
        with patch.object(checks.subprocess, "run", return_value=SimpleNamespace(stdout=output)) as run:
            self.assertEqual({"state": "ready", "engine": "ClamAV 1.5.4", "signatures_at": published,
                              "signature_version": "28194"}, checks.antivirus_readiness(published + 3600))
            self.assertEqual("UTC", run.call_args.kwargs["env"]["TZ"])
            self.assertEqual("stale-signatures", checks.antivirus_readiness(published + 8 * 86400)["state"])
        with patch.object(checks.subprocess, "run", return_value=SimpleNamespace(stdout="ClamAV 1.5.4\n")):
            self.assertEqual("missing-signatures", checks.antivirus_readiness(published)["state"])
        with patch.object(checks.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual("missing-scanner", checks.antivirus_readiness(published)["state"])

    def test_antivirus_coverage_distinguishes_limits_access_and_malware(self):
        marker = "\n----------- SCAN SUMMARY -----------\n"
        limit = "Heuristics.Limits.Exceeded.MaxFileSize"
        outputs = {
            "/clean": (0, "", "Scanned files: 2\nInfected files: 0\n"),
            "/denied": (2, "/denied: Can't open directory.\n", "Scanned files: 0\nTotal errors: 1\n"),
            "/limited": (2, f"/limited/large: {limit} FOUND\n", "Scanned files: 0\nInfected files: 0\nTotal errors: 1\n"),
            "/old-limit": (1, f"/old-limit/large: {limit} FOUND\n", "Scanned files: 1\nInfected files: 1\n"),
            "/mixed": (1, f"/mixed/large: {limit} FOUND\n/mixed/test: Eicar-Test-Signature FOUND\n",
                       "Scanned files: 1\nInfected files: 1\nTotal errors: 1\n"),
            "/found-text": (2, "/found-text/name: Fake-Signature FOUND\n", "Scanned files: 0\nInfected files: 0\n"),
        }

        def run(arguments, **options):
            self.assertIn("--alert-exceeds-max=yes", arguments)
            self.assertGreater(options["timeout"], 0)
            code, findings, summary = outputs[arguments[-1]]
            options["stdout"].write((findings + marker + summary).encode())
            return subprocess.CompletedProcess(arguments, code)

        with patch.object(checks.subprocess, "run", side_effect=run):
            report = checks.antivirus(["/clean", "/denied", "/limited", "/old-limit"])
            self.assertEqual("warn", report["status"])
            coverage = {row["path"]: row for row in report["coverage"]}
            self.assertEqual(2, coverage["/clean"]["files_scanned"])
            self.assertEqual(1, coverage["/denied"]["access_errors"])
            self.assertEqual(2, report["limit_hits"])
            self.assertEqual("warn", coverage["/old-limit"]["status"])
            detected = checks.antivirus(["/mixed", "/denied"])
            self.assertEqual("fail", detected["status"])
            self.assertIn("Eicar-Test-Signature FOUND", detected["detail"])
            self.assertNotIn(limit, detected["detail"])
            self.assertEqual(1, detected["limit_hits"])
            self.assertEqual("warn", checks.antivirus(["/found-text"])["status"])

    def test_antivirus_uses_one_scan_timeout_for_all_paths(self):
        with patch.object(checks.time, "monotonic", side_effect=[0, 0, checks.ANTIVIRUS_TIMEOUT, checks.ANTIVIRUS_TIMEOUT]), \
             patch.object(checks.subprocess, "run", side_effect=subprocess.TimeoutExpired("clamscan", 900)) as scanner:
            report = checks.antivirus(["/first", "/remaining"])
        scanner.assert_called_once()
        self.assertEqual("warn", report["status"])
        self.assertEqual(["/first", "/remaining"], [row["path"] for row in report["coverage"]])
        self.assertIn("before this path was scanned", report["coverage"][1]["detail"])
        self.assertEqual(checks.ANTIVIRUS_TIMEOUT, report["coverage"][0]["duration_seconds"])
        self.assertIsNone(report["coverage"][1]["duration_seconds"])

    def test_clamd_scan_uses_open_files_and_skips_symlinks(self):
        root = self.directory / "files"
        root.mkdir()
        (root / "safe").write_bytes(b"clean")
        (root / "limited").write_bytes(b"limit")
        (root / "detected").write_bytes(b"test")
        (root / "ignored").symlink_to(self.database)
        daemon = clamd_backend.ClamD()

        def query(command, deadline, fd):
            self.assertEqual(b"FILDES", command)
            import os
            content = os.read(fd, 50)
            return {"clean": "fd: OK", "limit": "fd: Heuristics.Limits.Exceeded.MaxFileSize FOUND",
                    "test": "fd: Eicar-Test-Signature FOUND"}[content.decode()]

        with patch.object(daemon, "query", side_effect=query) as scan:
            row = daemon.scan_path(str(root), float("inf"))
        self.assertEqual(3, scan.call_count)
        self.assertEqual(("fail", 2, 1, 1), (row["status"], row["files_scanned"], row["detections"], row["limit_hits"]))
        self.assertIn(str(root / "detected"), row["detail"])

    def test_clamd_rejects_unverified_signatures_and_falls_back(self):
        daemon = clamd_backend.ClamD()
        with patch.object(clamd_backend.subprocess, "Popen") as start, \
             patch.object(checks, "antivirus_readiness", return_value={"state": "stale-signatures"}), \
             patch.object(checks, "antivirus_path", return_value={"status": "warn", "files_scanned": 0,
                          "scan_errors": 0, "access_errors": 0, "limit_hits": 0, "detail": "Stale signatures"}):
            row, = checks.antivirus(["/downloads"], daemon=daemon)["coverage"]
        start.assert_not_called()
        self.assertEqual("clamscan", row["backend"])
        self.assertIn("signatures", row["fallback"])

    def test_clamd_socket_failure_falls_back_within_the_same_scan(self):
        daemon = Mock()
        daemon.scan_path.side_effect = clamd_backend.ClamDError("socket failed")
        clean = {"status": "pass", "files_scanned": 1, "scan_errors": 0,
                 "access_errors": 0, "limit_hits": 0, "detail": "Clean"}
        with patch.object(checks, "antivirus_path", return_value=clean) as standalone, \
             patch.object(checks, "antivirus_readiness", return_value={"state": "ready"}):
            report = checks.antivirus(["/first", "/next"], daemon=daemon)
        self.assertEqual("pass", report["status"])
        self.assertEqual(1, daemon.scan_path.call_count)
        self.assertEqual(2, standalone.call_count)
        self.assertTrue(all(row["fallback"] == "socket failed" for row in report["coverage"]))

    def test_clamd_detection_survives_interrupted_scan_and_incomplete_fallback(self):
        root = self.directory / "files"
        root.mkdir()
        for name in ("file-one", "file-two"):
            (root / name).write_text("test input")
        daemon = clamd_backend.ClamD()
        incomplete = {"status": "warn", "files_scanned": 0, "scan_errors": 0,
                      "access_errors": 0, "limit_hits": 0, "detail": "Timed out"}
        with patch.object(daemon, "prepare"), patch.object(daemon, "query", side_effect=[
                "fd: Eicar-Test-Signature FOUND", clamd_backend.ClamDError("socket failed")]), \
             patch.object(checks, "antivirus_readiness", return_value={"state": "ready"}), \
             patch.object(checks, "antivirus_path", return_value=incomplete) as standalone:
            report = checks.antivirus([str(root)], daemon=daemon)
        row, = report["coverage"]
        standalone.assert_called_once()
        self.assertEqual(("fail", 1, "clamd", "socket failed"),
                         (report["status"], row["detections"], row["backend"], row["fallback"]))
        self.assertIn("interrupted after this detection", row["detail"])

    def test_coverage_alerts_fire_once_and_recover_only_after_verified_coverage(self):
        path = "/downloads"
        fail = {"path": path, "status": "warn", "limit_hits": 1, "files_scanned": 1}
        ready = {"path": path, "status": "pass", "files_scanned": 2}
        unavailable = {"path": path, "status": "warn", "files_scanned": 0}
        empty = {"path": path, "status": "skipped", "files_scanned": 0}
        for at, row in enumerate([fail, fail, ready, fail, unavailable, fail, fail, fail, empty, ready, ready], 1):
            with store.connect(self.database) as db:
                checks.update_coverage_alerts(db, at, [row])
        with store.connect(self.database) as db:
            alerts = [tuple(row) for row in db.execute("SELECT at,severity,title,subject FROM events ORDER BY id")]
            self.assertEqual([
                (7, "medium", "Antivirus path coverage degraded", path),
                (10, "info", "Antivirus path coverage recovered", path),
            ], alerts)
            self.assertEqual({}, store.property_get(db, "antivirus_coverage_incidents"))

    def test_manual_antivirus_scan_shares_the_worker_and_preserves_the_alert(self):
        config = self.directory / "config.json"
        with store.connect(self.database) as db:
            self.assertNotIn("antivirus", checks.read(db, configuration(config)))
            store.property_set(db, "email_destination", {"minimum_severity": "high"})
        paths = [str(self.directory / "incoming")]
        write_json(config, {"antivirus_paths": paths})
        settings = configuration(config)
        detection = checks.result("clamav", "ClamAV malware scan", "fail", "test-signature FOUND")
        clean = checks.result("clamav", "ClamAV malware scan", "pass", "No malware reported.")
        worker = checks.AntivirusWorker(SimpleNamespace(database=self.database, settings=settings))
        with patch.object(checks, "antivirus", return_value=detection) as scanner, \
             patch.object(checks.time, "time", return_value=100):
            worker.scan_if_due()
            scanner.assert_called_once_with(paths)

        def scan(received_paths):
            self.assertEqual(paths, received_paths)
            self.assertFalse(worker.request())
            return clean

        with patch.object(checks, "antivirus", side_effect=scan) as scanner, \
             patch.object(checks.time, "time", return_value=200):
            worker.scan_if_due()
            scanner.assert_not_called()
            self.assertTrue(worker.request())
            self.assertFalse(worker.request())
            worker.scan_if_due()
            scanner.assert_called_once()
        with store.connect(self.database) as db:
            report = checks.read(db, settings)["antivirus"]
            self.assertEqual(1440, report["interval_minutes"])
            self.assertEqual(200, report["at"])
            self.assertEqual([clean], report["checks"])
            state = worker.status(report, 200)
            self.assertFalse(state["running"])
            self.assertEqual(86600, state["next_at"])
            self.assertEqual(paths, state["paths"])
            self.assertEqual([("high", "ClamAV detected malware"), ("info", "ClamAV malware scan: pass")],
                             [tuple(row) for row in db.execute("SELECT severity, title FROM events ORDER BY id")])
            self.assertEqual(1, db.execute("SELECT count(*) FROM email_outbox").fetchone()[0])
            self.assertNotIn("at", checks.read(db, {**settings, "antivirus_paths": ["/other"]})["antivirus"])
        write_json(config, {"antivirus_paths": ["relative/path"]})
        with self.assertRaisesRegex(ValueError, "antivirus_paths"):
            configuration(config)

    def test_incomplete_antivirus_scans_are_retried_early(self):
        report = {"at": 200, "boot_id": BOOT_ID, "interval_minutes": 1440}
        for check in ({"status": "warn"}, {"status": "fail", "scan_errors": 2}):
            self.assertEqual(500, checks.antivirus_next_at({**report, "checks": [check]}, 200))
        self.assertEqual(200, checks.antivirus_next_at({**report, "boot_id": "previous"}, 200))

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

    def test_integrity_tracks_wsdd_dpkg_hook_and_helpers(self):
        baseline = self.directory / "watchdog-integrity.json"
        config = self.directory / "config.json"
        hook = self.directory / "dpkg-hook"
        manifest = self.directory / "policy.json"
        helper = self.directory / "manage.py"
        with patch.object(checks, "WSDD_DPKG_HOOK", hook), \
             patch.object(checks.wsdd_policy, "STATE", manifest), \
             patch.object(checks.wsdd_policy, "trusted_file", side_effect=lambda path: bool(path.lstat())):
            paths = checks.wsdd_hook_files()
            self.assertTrue(paths.isdisjoint(checks.targets(config, self.directory)))
            for path in paths:
                path.write_text("trusted")
            checks.record_baseline(baseline, config, self.directory)
            finding = checks.integrity(baseline, config, self.directory)
            self.assertEqual("pass", finding["status"])
            self.assertIn("dpkg hook and both helper files match", finding["detail"])
            hook.write_text("changed")
            helper.unlink()
            finding = checks.integrity(baseline, config, self.directory)
            self.assertEqual("fail", finding["status"])
            self.assertIn("2 added or changed files", finding["detail"])
            self.assertIn(str(hook), finding["detail"])
            self.assertIn(str(helper), finding["detail"])

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
                                  stop=Mock(), ready=Mock(), observe_directory=None)
        monitor.stop.wait.side_effect = [False, True]
        row = checks.result("supervisor", "Supervisor", "fail", "Stale")
        with patch.object(checks.time, "time", return_value=500), \
             patch.object(checks, "health", return_value=[row]) as health, \
             patch.object(checks.backup_health, "refresh") as backup_health, \
             patch.object(checks, "hardening") as hardening:
            checks.run(monitor)
        health.assert_called_once_with(monitor)
        backup_health.assert_called_once_with(self.database, 500, 26, 170)
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
