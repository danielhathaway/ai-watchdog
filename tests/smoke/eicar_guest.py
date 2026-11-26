#!/usr/bin/python3
"""Install and exercise real Watchdog services inside a disposable Ubuntu VM."""

import json
from pathlib import Path
import platform
import re
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

    def verify_coverage_recovery(self):
        hidden = Path("/home/ubuntu/watchdog-hidden")
        hidden.mkdir()
        (hidden / "hidden.txt").write_text("Hidden by the system service's ProtectHome setting.\n")
        started = time.time()
        self.configure([self.scope, hidden])
        blocked = self.wait_scan(started, "warn", readiness="ready")["system_checks"]["antivirus"]
        assert blocked["checks"][0]["files_scanned"] == 1, blocked
        assert blocked["next_at"] - blocked["at"] == 300, blocked
        started = time.time()
        self.configure([self.scope])
        self.wait_scan(started, "pass", readiness="ready")
        print("WATCHDOG_EICAR_RECOVERY system service reported incomplete coverage for a protected home path")

        restricted = self.scope / "restricted"
        restricted.mkdir()
        (restricted / "readable-after-repair.txt").write_text("Temporary permission recovery fixture.\n")
        restricted.chmod(0o700)
        try:
            incomplete = self.scan("warn", readiness="ready")["system_checks"]["antivirus"]
            assert incomplete["checks"][0]["scan_errors"] > 0, incomplete
            assert incomplete["next_at"] - incomplete["at"] == 300, incomplete
        finally:
            restricted.chmod(0o755)
        clean = self.scan("pass", readiness="ready")["system_checks"]["antivirus"]
        assert clean["checks"][0]["files_scanned"] == 2, clean
        (restricted / "readable-after-repair.txt").unlink()
        restricted.rmdir()
        print("WATCHDOG_EICAR_RECOVERY unreadable directory recovered after permissions were repaired")

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

    def exercise(self):
        self.install(CURRENT if self.mode == "desktop" else LEGACY)
        assert subprocess.check_output(["systemctl", "is-enabled", "clamav-freshclam.service"], text=True).strip() == "enabled"
        run("systemctl", "is-active", "--quiet", "clamav-freshclam.service")
        print(f"WATCHDOG_EICAR_INSTALL mode={self.mode} FreshClam is enabled and active")
        wait_for_signatures()
        self.scope.mkdir(mode=0o755, parents=True)
        (self.scope / "benign.txt").write_text("Benign file for the clean antivirus rescan.\n")
        sample = self.scope / ("eicar.com.txt" if self.mode == "desktop" else "legacy-eicar.com.txt")
        sample.write_bytes(EICAR)
        try:
            started = time.time()
            self.configure([self.scope])
            report, event = self.detection(self.wait_scan(started, "fail"), sample)
            if self.mode != "desktop":
                self.verify_upgrade(report, event)
        finally:
            sample.unlink()

        if self.mode == "system-upgrade":
            self.verify_coverage_recovery()
            self.verify_stale_recovery()

        if self.mode != "desktop":
            sample = self.scope / "eicar.com.txt"
            sample.write_bytes(EICAR)
            try:
                _, event = self.detection(self.scan("fail", readiness="ready"), sample)
                assert event["review"]["scope_recorded"], event
            finally:
                sample.unlink()
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
