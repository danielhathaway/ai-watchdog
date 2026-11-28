"""Opt-in Firefox smoke test via the W3C WebDriver HTTP API."""
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from test_console_integration import TOKEN, running_console
from watchdog import notifications, store, userspace, vulnerabilities


@unittest.skipUnless(os.environ.get("WATCHDOG_BROWSER_SMOKE") == "1", "Set WATCHDOG_BROWSER_SMOKE=1")
class BrowserSmoke(unittest.TestCase):
    def test_authenticated_dashboard_and_settings(self):
        driver = shutil.which(os.environ.get("WATCHDOG_GECKODRIVER", "geckodriver"))
        self.assertIsNotNone(driver, "Install GeckoDriver and Firefox")
        with tempfile.TemporaryDirectory(prefix="watchdog-browser-") as directory:
            state = Path(directory)
            try:
                with running_console(state / "monitor.sqlite3") as console, socket.socket() as listener:
                    now = time.time()
                    settings = notifications.configuration({"host": "smtp.example.com", "sender": "from@example.com",
                                                           "recipient": "to@example.com", "coverage_notify_minutes": 60}, state)
                    with store.connect(console.monitor.database) as db:
                        notifications.prepare(db, settings)
                        queued = db.execute("INSERT INTO email_outbox(at,severity,title) VALUES (?,'medium','Coverage')", (now,))
                        db.execute("INSERT INTO coverage_email VALUES (?, ?)", ("/synthetic", queued.lastrowid))
                        store.property_set(db, "email_delivery", {"failures": 1, "next_at": now + 60})
                        store.property_set(db, "coverage_email_delivery", {"last_accepted_at": now - 60})
                        store.property_set(db, "system_checks", {"hardening": {"at": now, "checks": [{
                            "id": "certificates", "name": "System certificate authorities", "status": "fail",
                            "detail": "One certificate needs review.", "certificate_finding_count": 1,
                            "certificate_findings": [
                                {"subject": "CN=Test CA", "sha256": "a" * 64, "issues": ["unapproved-fingerprint"]},
                            ],
                        }]}})
                        store.property_set(db, "backup_health", {"upload": {"status": "overdue", "deadline": now - 60},
                                                                 "verifier": {"status": "failed", "failure_at": now - 30,
                                                                              "verifier": "verifier-test", "reported_at": now - 1300,
                                                                              "report_status": "overdue", "report_deadline": now - 100}})
                        vulnerability = {
                            "status": "recorded", "unresolved": 1, "known_exploited": 1,
                            "report_at": now,
                            "sources": {"kev": {"status": "failed", "online_at": now - vulnerabilities.STALE_AFTER}},
                            "fixes": {"reboot-required": 1, "service-restart-required": 1},
                            "priority_findings": [{"advisory": "CVE-2026-10001", "component": "linux-image-example",
                                                   "status": "affected", "fixed": "1.2",
                                                   "fix_verification": "reboot-required"}],
                        }
                        store.property_set(db, "vulnerability_summary", vulnerability)
                        store.property_set(db, userspace.SUMMARY_PROPERTY, {
                            "at": now, "report_at": now, "boot_id": userspace.BOOT_ID, "coverage": {"scope": "host"},
                            "vulnerabilities": {**vulnerability, "service_findings_total": 2, "service_findings": [
                                {"unit": "/system.slice/example.service", "component": "libexample",
                                 "status": "restart-required"},
                                {"unit": "/system.slice/restarted.service", "component": "libexample",
                                 "status": "active"},
                            ]},
                        })
                    listener.bind(("127.0.0.1", 0))
                    port = listener.getsockname()[1]
                    listener.close()
                    self.run_browser(driver, port, console.origin, state)
            except unittest.SkipTest as error:
                self.fail(str(error))

    def run_browser(self, driver, port, origin, state):
        base = f"http://127.0.0.1:{port}"

        def call(method, route, payload=None):
            data = json.dumps(payload).encode() if payload is not None else None
            request = Request(base + route, data=data, method=method, headers={"Content-Type": "application/json"})
            try:
                with urlopen(request, timeout=35) as response:
                    return json.load(response)["value"]
            except HTTPError as error:
                self.fail(f"WebDriver {route}: {error.read().decode(errors='replace')}")

        with (state / "geckodriver.log").open("w+") as log:
            child = subprocess.Popen([driver, "--host", "127.0.0.1", "--port", str(port)], stdout=log, stderr=log)
            session = None
            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        call("GET", "/status")
                        break
                    except URLError:
                        if child.poll() is not None or time.monotonic() >= deadline:
                            log.seek(0)
                            self.fail(f"GeckoDriver failed to start: {log.read()}")
                        time.sleep(.1)
                options = {"args": ["-headless"], "prefs": {
                    "network.proxy.type": 0, "network.dns.disablePrefetch": True,
                    "network.captive-portal-service.enabled": False,
                    "network.connectivity-service.enabled": False,
                }}
                if binary := os.environ.get("WATCHDOG_FIREFOX"):
                    options["binary"] = binary
                session = call("POST", "/session", {"capabilities": {"alwaysMatch": {
                    "browserName": "firefox", "moz:firefoxOptions": options,
                }}})["sessionId"]
                self.exercise_dashboard(lambda method, route, body=None: call(method, f"/session/{session}{route}", body), origin)
            finally:
                try:
                    if session:
                        call("DELETE", f"/session/{session}")
                finally:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()

    def exercise_dashboard(self, call, origin):
        def script(source):
            return call("POST", "/execute/sync", {"script": source, "args": []})

        def wait_for(expression):
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                if script(f"return Boolean({expression})"):
                    return
                time.sleep(.1)
            self.fail(f"Dashboard never satisfied {expression}")

        def element(selector):
            result = call("POST", "/element", {"using": "css selector", "value": selector})
            return "/element/" + result["element-6066-11e4-a52e-4f735466cecf"]

        def click(selector):
            call("POST", element(selector) + "/click", {})

        def fill(selector, value):
            target = element(selector)
            call("POST", target + "/clear", {})
            call("POST", target + "/value", {"text": value})

        call("POST", "/url", {"url": origin})
        wait_for("!document.querySelector('#unlock').hidden && document.querySelector('#dashboard').hidden")
        fill("#token", TOKEN)
        click("#unlock button")
        wait_for("!document.querySelector('#dashboard').hidden && !document.querySelector('#run').disabled")
        click("#run")
        wait_for("document.querySelector('#recent-events').innerText.includes('Active AI check completed')")
        for page in ("activity", "devices", "sensors", "settings"):
            click(f"[data-page='{page}']")
            wait_for(f"!document.querySelector('#{page}').hidden")
        click("[data-page='sensors']")
        wait_for("!document.querySelector('#backup-health-panel').hidden && "
                 "document.querySelector('#backup-health').innerText.includes('Overdue') && "
                 "document.querySelector('#backup-health').innerText.includes('verifier-test') && "
                 "document.querySelector('#backup-health').innerText.includes('Reports overdue') && "
                 "document.querySelector('#backup-health').innerText.includes('Report deadline') && "
                 "document.querySelector('#backup-health').innerText.includes('Last run failed')")
        wait_for("['CISA KEV', 'Stale', 'Refresh failed', 'CVE-2026-10001', 'reboot required', "
                 "'example.service', 'Restart required', 'restarted.service', 'Patched files loaded'].every("
                 "label => document.querySelector('#vulnerability-status').innerText.includes(label))")
        wait_for("document.querySelector('#health-check-time').textContent.includes('Every 5 min') && "
                 "document.querySelector('#hardening-check-time').textContent.includes('Every 60 min')")
        click(".certificate-inventory summary")
        wait_for("document.querySelector('.certificate-inventory').open && "
                 "document.querySelector('.certificate-inventory').textContent.includes('CN=Test CA') && "
                 "document.querySelector('.certificate-inventory').textContent.includes('unapproved fingerprint')")
        click("[data-page='settings']")
        wait_for("document.querySelector('#coverage-email-status').innerText.includes('Retrying') && "
                 "document.querySelector('#coverage-email-status').innerText.includes('Next retry') && "
                 "!document.querySelector('#coverage-email-status').innerText.includes('None yet')")
        fill("#schedule-minutes", "60")
        click("#schedule-form button")
        wait_for("document.querySelector('#next-check').innerText !== 'Off' && "
                 "!document.querySelector('#schedule-feedback').hidden")
        call("POST", "/refresh", {})
        wait_for("!document.querySelector('#dashboard').hidden && document.querySelector('#schedule-minutes').value === '60'")
        click("#lock")
        wait_for("!document.querySelector('#unlock').hidden && document.querySelector('#dashboard').hidden")
