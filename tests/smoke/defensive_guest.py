#!/usr/bin/env python3
"""Exercise the installed monitor with disposable guest-only fixtures."""
import io
import json
import os
import pwd
import socket
import subprocess
import sys
import tarfile
import time
import traceback
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import URLError
from urllib.request import Request, urlopen

APP = Path("/opt/ai-watchdog")
STATE = Path("/var/lib/ai-watchdog")
WORK = Path("/var/tmp/watchdog-defensive")
REFRESH = "ai-watchdog-vulnerability-refresh.service"
TIMER = "ai-watchdog-vulnerability-refresh.timer"
OS = "Ubuntu:24.04:LTS"
TEST_CVE = "CVE-2099-12345"
TEST_UNIT = "watchdog-defensive-fixture.service"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, timeout=180, **kwargs)


def mark(message):
    print(f"WATCHDOG_DEFENSIVE_{message}", flush=True)


def await_result(description, condition, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = condition()
        except (FileNotFoundError, URLError, TimeoutError):
            value = None
        if value:
            return value
        time.sleep(1)
    raise AssertionError(f"Timed out waiting for {description}")


def dashboard():
    token = (STATE / "token").read_text().strip()
    request = Request("http://127.0.0.1:8765/api/status", headers={"Authorization": f"Bearer {token}"})
    with urlopen(request, timeout=4) as response:
        return json.load(response)


class Feed(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path not in {"/osv.tar.xz", "/kev.json"}:
            self.send_error(404)
        elif (WORK / "feeds-unavailable").exists():
            self.send_error(503)
        else:
            super().do_GET()


def prepare_feeds():
    source = {"id": f"UBUNTU-{TEST_CVE}", "affected": [{
        "package": {"name": "iproute2", "ecosystem": OS},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "999.0"}]}],
    }]}
    data = json.dumps(source).encode()
    with tarfile.open(WORK / "osv.tar.xz", "w:xz") as bundle:
        member = tarfile.TarInfo(f"osv/cve/2099/UBUNTU-{TEST_CVE}.json")
        member.size = len(data)
        bundle.addfile(member, io.BytesIO(data))
    (WORK / "kev.json").write_text(json.dumps({"count": 1, "vulnerabilities": [{"cveID": TEST_CVE}]}))
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Feed, directory=WORK))
    Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    wrapper = Path("/etc/ai-watchdog/defensive-refresh.py")
    wrapper.write_text(f"""import sys
sys.path.insert(0, {str(APP)!r})
from watchdog import vulnerabilities
from watchdog.__main__ import main
vulnerabilities.UBUNTU_FEED = {base + "/osv.tar.xz"!r}
vulnerabilities.KEV_FEED = {base + "/kev.json"!r}
sys.argv = ["watchdog", "vulnerabilities", "refresh"]
main()
""")
    for unit, override in (
        (REFRESH, f"[Service]\nExecStart=\nExecStart=/usr/bin/python3 -B {wrapper}\n"),
        (TIMER, "[Timer]\nOnCalendar=\nOnActiveSec=8s\nAccuracySec=1s\nRandomizedDelaySec=0\n"),
    ):
        directory = Path("/etc/systemd/system") / f"{unit}.d"
        directory.mkdir()
        (directory / "fixture.conf").write_text(override)
    return server


def events(kind, title):
    return [item for item in dashboard()["events"] if item["kind"] == kind and item["title"] == title]


def feeds():
    from watchdog import store, vulnerabilities

    run("systemctl", "is-active", "--quiet", TIMER)
    run("systemctl", "is-active", "--quiet", "ai-watchdog-userspace.timer")
    await_result("scheduled refresh", lambda: dashboard()["vulnerabilities"].get("known_exploited") == 1)
    stamps = dashboard()["vulnerabilities"]["sources"]
    assert all(stamps[name]["freshness"] == "fresh" for name in (OS, "kev"))
    assert dashboard()["vulnerabilities"]["priority_findings"][0]["advisory"] == TEST_CVE
    mark("TIMERS_PASS")

    marker = WORK / "feeds-unavailable"
    marker.touch()
    run("systemctl", "stop", TIMER)
    failed = subprocess.run(["systemctl", "start", REFRESH], timeout=90)
    assert failed.returncode
    with store.connect(STATE / "monitor.sqlite3") as db:
        db.execute("BEGIN IMMEDIATE")
        report = store.property_get(db, "vulnerabilities")
        summary = store.property_get(db, "vulnerability_summary")
        assert summary["known_exploited"] == 1
        for name in (OS, "kev"):
            assert report["sources"][name]["status"] == "failed"
            assert report["sources"][name]["online_at"] == stamps[name]["online_at"]
            old = time.time() - vulnerabilities.STALE_AFTER - 60
            report["sources"][name]["online_at"] = old
            summary["sources"][name]["online_at"] = old
        store.property_set(db, "vulnerabilities", report)
        store.property_set(db, "vulnerability_summary", summary)
    await_result("stale feed alerts", lambda: len(events("vulnerability-feed", "Vulnerability feed stale")) == 2)
    stale = dashboard()["vulnerabilities"]["sources"]
    assert all(stale[name]["freshness"] == "stale" for name in (OS, "kev")), stale
    mark("STALE_FEEDS_PASS")
    marker.unlink()
    run("systemctl", "start", TIMER)
    await_result("feed recovery", lambda: len(events("vulnerability-feed", "Vulnerability feed refreshed")) == 2)
    assert all(dashboard()["vulnerabilities"]["sources"][name]["freshness"] == "fresh" for name in (OS, "kev"))
    mark("FEED_RECOVERY_PASS")


def ssh_correlation():
    from watchdog import ssh_activity, store

    unit = Path("/etc/systemd/system") / TEST_UNIT
    unit.write_text("[Unit]\nDescription=Watchdog benign SSH fixture\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n")
    run("systemctl", "daemon-reload")
    account = pwd.getpwnam("ubuntu")
    key = WORK / "ssh-fixture"
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
    keys = Path(account.pw_dir) / ".ssh/authorized_keys"
    with keys.open("a") as stream:
        stream.write(key.with_suffix(".pub").read_text())
    run("systemctl", "start", "ssh.socket")
    def listening():
        with socket.create_connection(("127.0.0.1", 22), timeout=3):
            return True
    await_result("guest SSH socket", listening)
    run("ssh", "-T", "-i", str(key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", f"UserKnownHostsFile={WORK / 'ssh-known-hosts'}", "-o", "StrictHostKeyChecking=accept-new",
        "ubuntu@127.0.0.1", "sudo", "-n", "/usr/bin/systemctl", "start", TEST_UNIT)
    try:
        correlated = await_result("SSH sequence",
                                  lambda: events("ssh-activity", "SSH login followed by privileged change"), timeout=40)
    except AssertionError:
        now = time.time()
        result = run("journalctl", "-b", "--no-pager", "-o", "json", f"--output-fields={ssh_activity.FIELDS}",
                     "-n", "24", "_COMM=sshd", "+", "_COMM=sudo", "+", f"UNIT={TEST_UNIT}",
                     "+", f"MESSAGE_ID={ssh_activity.SESSION_STARTED}", capture_output=True)
        for line in result.stdout.splitlines():
            entry = json.loads(line)
            mark("SSH_JOURNAL " + json.dumps({"entry": entry, "signal": ssh_activity.signal(entry, now)}))
        with store.connect(STATE / "monitor.sqlite3") as db:
            state = store.property_get(db, ssh_activity.STATE, {})
        mark("SSH_SENSOR " + json.dumps({"status": state.get("status"), "signals": state.get("signals", [])[-12:]}))
        raise
    assert len(correlated) == 1 and TEST_UNIT in correlated[0]["detail"]
    assert "ubuntu from 127.0.0.1" in correlated[0]["detail"]
    assert not dashboard()["response"]["isolated"]
    mark("SSH_CORRELATION_PASS")


def certificates():
    def audit():
        process = subprocess.run(["runuser", "-u", "ai-watchdog", "--", "/usr/bin/python3", "-B", "-m",
                                  "watchdog", "certificates"], cwd=APP, capture_output=True, text=True, timeout=60)
        return process.returncode, json.loads(process.stdout)

    await_result("scheduled CA audit", lambda: any(
        row["id"] == "certificates" for row in dashboard()["system_checks"]["hardening"].get("checks", [])))
    certificate = Path("/usr/local/share/ca-certificates/watchdog-defensive-fixture.crt")
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj",
        "/CN=Watchdog Disposable CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-keyout", str(WORK / "ca.key"), "-out", str(certificate), capture_output=True)
    run("update-ca-certificates", capture_output=True)
    code, report = audit()
    fixture = next(row for row in report["findings"] if row["subject"] == "CN=Watchdog Disposable CA")
    assert code == 1 and "unapproved-fingerprint" in fixture["issues"]
    certificate.unlink()
    run("update-ca-certificates", "--fresh", capture_output=True)
    _, recovered = audit()
    assert all(row["sha256"] != fixture["sha256"] for row in recovered["findings"])
    mark("CA_AUDIT_PASS")


def main():
    hypervisor = run("systemd-detect-virt", "--vm", capture_output=True).stdout.strip()
    if socket.gethostname() != "watchdog-defensive" or hypervisor not in {"qemu", "kvm"}:
        raise RuntimeError("This check requires the disposable Watchdog guest")
    WORK.mkdir(mode=0o755)
    os.chdir(WORK)
    run("tar", "xzf", "/var/tmp/watchdog-source.tgz")
    if not Path("/usr/sbin/nft").exists():
        run("apt-get", "-q", "update")
        run("apt-get", "-qy", "install", "--no-install-recommends", "nftables")
    run("sh", "deploy/install.sh", "--without-clamav")
    sys.path.insert(0, str(APP))
    server = prepare_feeds()
    try:
        run("python3", "-B", "-m", "watchdog", "baseline", cwd=APP)
        run("systemctl", "daemon-reload")
        run("systemctl", "start", "ai-watchdog-response.service")
        await_result("ready dashboard", lambda: dashboard()["ready"])
        ssh_correlation()
        feeds()
        certificates()
    finally:
        server.shutdown()
    mark("GUEST_PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        subprocess.run(["journalctl", "--no-pager", "-n", "24", "-u", "ai-watchdog.service", "-u", REFRESH, "-u", "ssh.service"])
        mark("GUEST_FAIL")
        raise
