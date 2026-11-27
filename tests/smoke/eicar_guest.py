#!/usr/bin/python3
"""Install and exercise real Watchdog services inside a disposable Ubuntu VM."""

import json
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

CURRENT = "/var/tmp/watchdog-source.tgz"
LEGACY = "/var/tmp/watchdog-legacy.tgz"
REPO = Path("/home/ubuntu/watchdog-smoke")
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def run(*args):
    subprocess.run(args, check=True)


class Guest:
    def __init__(self, port, mode):
        self.mode = mode
        self.desktop = mode != "system-upgrade"
        self.origin = f"http://127.0.0.1:{port}"
        self.port = port
        if self.desktop:
            uid = int(subprocess.check_output(["id", "-u", "ubuntu"]))
            run("loginctl", "enable-linger", "ubuntu")
            run("systemctl", "start", f"user@{uid}.service")
            self.user = ("runuser", "-u", "ubuntu", "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}",
                         f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus")
            self.control = (*self.user, "systemctl", "--user")
            self.service = "ai-watchdog-observe.service"
            self.state = REPO / ".watchdog"
            self.config = self.state / "config.json"
            self.scope = Path("/home/ubuntu/Downloads/Watchdog Scan")
        else:
            self.user = ()
            self.control = ("systemctl",)
            self.service = "ai-watchdog.service"
            self.state = Path("/var/lib/ai-watchdog")
            self.config = Path("/etc/ai-watchdog/config.json")
            self.scope = Path("/srv/watchdog-smoke/files")

    def install(self, archive):
        REPO.mkdir(exist_ok=True)
        run("tar", "-xzf", archive, "-C", str(REPO))
        if self.desktop:
            run("chown", "-R", "ubuntu:ubuntu", str(REPO))
        installer = "install-user.sh" if self.desktop else "install.sh"
        run(*self.user, str(REPO / "deploy" / installer))

    def configure(self, paths):
        config = json.loads(self.config.read_text())
        config.update(port=self.port, antivirus_paths=[str(path) for path in paths])
        self.config.write_text(json.dumps(config))
        self.restart()

    def restart(self):
        run(*self.control, "restart", self.service)

    def request(self, path="/api/status", method="GET"):
        token = (self.state / "token").read_text().strip()
        request = Request(self.origin + path, method=method, headers={
            "Authorization": "Bearer " + token, "Origin": self.origin,
        })
        with urlopen(request, timeout=5) as response:
            return json.load(response)

    def wait(self, predicate, description):
        deadline = time.monotonic() + 150
        latest = None
        while time.monotonic() < deadline:
            try:
                latest = self.request()
            except (FileNotFoundError, URLError):
                pass
            else:
                if predicate(latest):
                    return latest
            time.sleep(1)
        report = latest and latest["system_checks"].get("antivirus")
        raise AssertionError(f"Timed out waiting for {description}: {report}")

    def wait_scan(self, after, status, *, readiness=None):
        def completed(snapshot):
            report = snapshot["system_checks"].get("antivirus", {})
            return (report.get("at", 0) > after and not report.get("running")
                    and report["checks"][0]["status"] == status
                    and (readiness is None or report["readiness"]["state"] == readiness))
        return self.wait(completed, f"a {status} scan with readiness {readiness}")

    def scan(self, status, *, readiness=None):
        self.wait(lambda snapshot: snapshot["ready"] and not snapshot["system_checks"]["antivirus"]["running"],
                  "a ready monitor and idle scanner")
        started = time.time()
        self.request("/api/antivirus/scan", "POST")
        return self.wait_scan(started, status, readiness=readiness)

    def detection(self, snapshot, sample):
        report = snapshot["system_checks"]["antivirus"]
        detail = report["checks"][0]["detail"]
        if not re.search(re.escape(str(sample)) + r": [^\n]*eicar[^\n]* FOUND", detail, re.IGNORECASE):
            raise AssertionError(f"Unexpected antivirus report: {report}")
        event, = [item for item in snapshot["events"] if item["subject"] == "antivirus/clamav"
                  and item["severity"] == "high" and item["detail"] == detail and item["at"] == report["at"]]
        return report, event

    def verify_upgrade(self, report, event):
        config_bytes = self.config.read_bytes()
        self.install(CURRENT)
        assert self.config.read_bytes() == config_bytes, "Installer replaced the existing configuration"
        self.restart()
        upgraded = self.wait(lambda status: status["ready"], "the upgraded service")
        current = upgraded["system_checks"]["antivirus"]
        assert all(current[key] == report[key] for key in ("at", "checks", "paths", "interval_minutes")), current
        retained, = [item for item in upgraded["events"] if item["id"] == event["id"]]
        assert {key: retained[key] for key in event} == event, retained
        assert retained["review"]["acknowledged_at"] is None, retained
        print(f"WATCHDOG_EICAR_UPGRADE mode={self.mode} preserved configuration, scan history and event {event['id']}")

    def verify_rollback(self, report, event, older_event):
        ack = self.request(f"/api/alerts/{older_event['id']}/acknowledge", "POST")
        config = self.config.read_bytes()
        token = (self.state / "token").read_bytes()

        def replace(archive):
            run(*self.control, "stop", self.service)
            # Replace application files while retaining the live configuration and database.
            shutil.rmtree(REPO / "watchdog")
            if not self.desktop:
                shutil.rmtree("/opt/ai-watchdog/watchdog")
            self.install(archive)
            self.restart()
            assert self.config.read_bytes() == config, "Rollback or reinstall replaced the configuration"
            assert (self.state / "token").read_bytes() == token, "Rollback or reinstall replaced the token"
            state = self.wait(lambda status: status["ready"], "the restarted service")
            latest = state["system_checks"]["antivirus"]
            assert all(latest[key] == report[key] for key in ("at", "checks", "paths", "interval_minutes")), latest
            retained, = [item for item in state["events"] if item["id"] == event["id"]]
            assert all(retained[key] == value for key, value in event.items() if key != "review"), retained
            return state

        legacy_source = Path("/opt/watchdog-smoke-legacy")
        legacy_source.mkdir(mode=0o755)
        run("tar", "-xzf", LEGACY, "-C", str(legacy_source))
        command = (*self.user, "/usr/bin/python3", "-B", "-m", "watchdog", "rollback", str(legacy_source))
        if self.desktop:
            command += ("--desktop",)
        output = subprocess.check_output(command, cwd=REPO if self.desktop else "/opt/ai-watchdog", text=True)
        assert "dashboard health check passed" in output, output
        backup = Path(next(line.removeprefix("Rollback backup: ") for line in output.splitlines()
                           if line.startswith("Rollback backup: ")))
        assert stat.S_IMODE(backup.stat().st_mode) == 0o700, backup
        assert (backup / "state/config.json").read_bytes() == config
        assert (backup / "state/token").read_bytes() == token
        with sqlite3.connect(backup / "state/monitor.sqlite3") as database:
            assert database.execute("SELECT detail FROM events WHERE id=?", (event["id"],)).fetchone() == (event["detail"],)
            assert database.execute("SELECT count(*) FROM antivirus_path_history").fetchone()[0] > 0
        legacy = self.wait(lambda status: status["ready"], "the rolled-back service")
        assert self.config.read_bytes() == config and (self.state / "token").read_bytes() == token
        latest = legacy["system_checks"]["antivirus"]
        assert all(latest[key] == report[key] for key in ("at", "checks", "paths", "interval_minutes")), latest
        retained, = [item for item in legacy["events"] if item["id"] == event["id"]]
        assert all(retained[key] == value for key, value in event.items() if key != "review"), retained
        assert all("review" not in item for item in legacy["events"]), "The previous server was not running"
        with urlopen(self.origin, timeout=5) as response:
            assert b'id="findings"' not in response.read(), "The previous dashboard was not installed"
        current = replace(CURRENT)
        retained, = [item for item in current["events"] if item["id"] == older_event["id"]]
        assert retained["review"] == ack, retained
        assert self.request("/api/antivirus/history")["results"], "Coverage history was lost during rollback"
        print(f"WATCHDOG_EICAR_ROLLBACK mode={self.mode} backed up state, passed health checks and retained review history")

    def verify_coverage_recovery(self):
        hidden = Path("/home/ubuntu/watchdog-hidden")
        hidden.mkdir()
        (hidden / "hidden.txt").write_text("Hidden by the system service's ProtectHome setting.\n")
        started = time.time()
        self.configure([self.scope, hidden])
        blocked = self.wait_scan(started, "warn", readiness="ready")["system_checks"]["antivirus"]
        assert blocked["checks"][0]["files_scanned"] == 1, blocked
        assert blocked["next_at"] - blocked["at"] == 300, blocked
        coverage = {row["path"]: row["status"] for row in blocked["checks"][0]["coverage"]}
        assert coverage == {str(self.scope): "pass", str(hidden): "warn"}, blocked
        started = time.time()
        self.configure([self.scope])
        self.wait_scan(started, "pass", readiness="ready")
        print("WATCHDOG_EICAR_RECOVERY system service reported incomplete coverage for a protected home path")

        restricted = self.scope / "restricted"
        restricted.mkdir()
        (restricted / "readable-after-repair.txt").write_text("Temporary permission recovery fixture.\n")
        restricted.chmod(0o700)
        oversized = self.scope / "oversized.bin"
        with oversized.open("wb") as output:
            output.truncate(128 * 1024 * 1024)
        try:
            for _ in range(3):
                snapshot = self.scan("warn", readiness="ready")
            incomplete = snapshot["system_checks"]["antivirus"]
            path, = incomplete["checks"][0]["coverage"]
            assert path["path"] == str(self.scope) and path["access_errors"] > 0 and path["limit_hits"] == 1, path
            assert incomplete["next_at"] - incomplete["at"] == 300, incomplete
            degraded, = [item for item in snapshot["events"] if item["kind"] == "antivirus-coverage"
                         and item["subject"] == str(self.scope) and item["severity"] == "medium"]
            assert degraded["title"] == "Antivirus path coverage degraded", degraded
        finally:
            restricted.chmod(0o755)
            oversized.unlink()
        snapshot = self.scan("pass", readiness="ready")
        clean = snapshot["system_checks"]["antivirus"]
        assert clean["checks"][0]["files_scanned"] == 2, clean
        recovered, = [item for item in snapshot["events"] if item["kind"] == "antivirus-coverage"
                      and item["subject"] == str(self.scope) and item["severity"] == "info"]
        assert recovered["title"] == "Antivirus path coverage recovered", recovered
        (restricted / "readable-after-repair.txt").unlink()
        restricted.rmdir()
        print("WATCHDOG_EICAR_RECOVERY reported sustained coverage degradation and recovery in Activity")

    def verify_stale_recovery(self):
        # Advance only the disposable guest clock so ClamAV sees its real signed database as stale.
        run("timedatectl", "set-ntp", "false")
        run("systemctl", "stop", "clamav-freshclam.service")
        wall, elapsed = time.time(), time.monotonic()
        try:
            future = int(wall) + 8 * 86400
            run("date", "--set", f"@{future}")
            self.restart()
            stale = self.wait_scan(future - 1, "warn", readiness="stale-signatures")["system_checks"]["antivirus"]
            assert stale["next_at"] - stale["at"] == 300, stale
        finally:
            run("date", "--set", f"@{int(wall + time.monotonic() - elapsed)}")
            run("systemctl", "start", "clamav-freshclam.service")
        started = time.time()
        self.restart()
        self.wait_scan(started, "pass", readiness="ready")
        print("WATCHDOG_EICAR_RECOVERY stale signatures blocked a scan and recovered with a current signature age")

    def backups(self, *arguments):
        return subprocess.check_output((*self.user, "/usr/bin/python3", "-B", "-m", "watchdog",
                                        "backups", "--desktop", *arguments), cwd=REPO, text=True)

    def export_backup(self, event):
        self.request(f"/api/alerts/{event['id']}/acknowledge", "POST")
        self.scan("pass", readiness="ready")
        output = self.backups("create")
        backup = Path(output.strip().removeprefix("Backup created: "))
        assert backup.is_dir(), output
        assert json.loads(self.backups("list"))[0]["path"] == str(backup)
        assert "verification passed" in self.backups("verify", str(backup))
        (backup / "donor-machine-id").write_bytes(Path("/etc/machine-id").read_bytes())
        archive = Path("/var/tmp/watchdog-backup-export.tgz")
        archive.touch(mode=0o600, exist_ok=False)
        run("chown", "ubuntu:ubuntu", str(archive))
        run(*self.user, "tar", "-czf", str(archive), "-C", str(backup), ".")
        print("WATCHDOG_EICAR_BACKUP created, inventoried and verified donor backup")

    def restore_backup(self):
        self.scope.mkdir(mode=0o755, parents=True)
        (self.scope / "benign.txt").write_text("Benign file on the restored host.\n")
        self.configure([])
        self.wait(lambda status: status["ready"], "a newly installed destination")
        original_token = (self.state / "token").read_bytes()
        backup = self.state / "rollbacks/backup-import"
        backup.parent.mkdir(mode=0o700, exist_ok=True)
        backup.mkdir(mode=0o700)
        run("tar", "-xzf", "/var/tmp/watchdog-imported.tgz", "-C", str(backup))
        run("chown", "-R", "ubuntu:ubuntu", str(backup.parent))
        assert (backup / "donor-machine-id").read_bytes() != Path("/etc/machine-id").read_bytes()
        assert "verification passed" in self.backups("verify", str(backup))
        output = self.backups("restore", str(backup))
        assert "dashboard health check passed" in output, output
        assert self.config.read_bytes() == (backup / "state/config.json").read_bytes()
        token = (self.state / "token").read_bytes()
        assert token != original_token and token == (backup / "state/token").read_bytes()
        self.port = json.loads(self.config.read_text())["port"]
        self.origin = f"http://127.0.0.1:{self.port}"
        status = self.wait(lambda report: report["ready"], "the restored dashboard")
        event, = [item for item in status["events"] if item["title"] == "ClamAV detected malware"]
        assert event["review"]["acknowledged_at"] and "Eicar-Test-Signature FOUND" in event["detail"], event
        history = self.request("/api/antivirus/history")["results"]
        assert {item["status"] for item in history} >= {"pass", "fail"}, history
        assert all(item["duration_seconds"] is not None for item in history), history
        assert "manifest-present" in self.backups("list")
        print("WATCHDOG_EICAR_RESTORE distinct fresh VM restored configuration, token, alert review and coverage history")

    def exercise(self):
        upgrading = self.mode.endswith("-upgrade")
        self.install(LEGACY if upgrading else CURRENT)
        assert subprocess.check_output(["systemctl", "is-enabled", "clamav-freshclam.service"], text=True).strip() == "enabled"
        run("systemctl", "is-active", "--quiet", "clamav-freshclam.service")
        print(f"WATCHDOG_EICAR_INSTALL mode={self.mode} FreshClam is enabled and active")
        if self.mode == "backup-destination":
            self.restore_backup()
            return
        wait_for_signatures()
        self.scope.mkdir(mode=0o755, parents=True)
        (self.scope / "benign.txt").write_text("Benign file for the clean antivirus rescan.\n")
        sample = self.scope / ("legacy-eicar.com.txt" if upgrading else "eicar.com.txt")
        sample.write_bytes(EICAR)
        try:
            started = time.time()
            self.configure([self.scope])
            report, event = self.detection(self.wait_scan(started, "fail"), sample)
            if upgrading:
                older_event = event
                self.verify_upgrade(report, event)
        finally:
            sample.unlink()

        if self.mode == "system-upgrade":
            self.verify_coverage_recovery()
            self.verify_stale_recovery()

        if upgrading:
            sample = self.scope / "eicar.com.txt"
            sample.write_bytes(EICAR)
            try:
                report, event = self.detection(self.scan("fail", readiness="ready"), sample)
                assert event["review"]["scope_recorded"], event
                self.verify_rollback(report, event, older_event)
            finally:
                sample.unlink()
        if self.mode == "backup-source":
            self.export_backup(event)
        print(f"WATCHDOG_EICAR_ACTIVITY event={event['id']} severity={event['severity']} detail={event['detail']}")


def wait_for_signatures():
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if all(any(path.stat().st_size for path in Path("/var/lib/clamav").glob(name + ".c[vl]d"))
               for name in ("daily", "main", "bytecode")):
            print("WATCHDOG_EICAR_ENGINE", subprocess.check_output(["clamscan", "--version"], text=True).strip())
            return
        time.sleep(2)
    run("journalctl", "-u", "clamav-freshclam.service", "-n", "25", "--no-pager")
    raise AssertionError("FreshClam did not download the signature databases")


if __name__ == "__main__":
    try:
        release = platform.freedesktop_os_release()
        assert (release["ID"], release["VERSION_ID"]) == ("ubuntu", "24.04"), release
        assert not any(Path(path).exists() for path in ("/usr/bin/clamscan", "/usr/bin/freshclam", "/var/lib/clamav"))
        print(f"WATCHDOG_EICAR_PRECHECK {release['PRETTY_NAME']} has no ClamAV")
        Guest(int(sys.argv[1]), sys.argv[2]).exercise()
    except Exception:
        print("WATCHDOG_EICAR_GUEST_FAIL", flush=True)
        raise
    print("WATCHDOG_EICAR_GUEST_PASS", flush=True)
