"""Verify the live EICAR alert in the VM's Activity page with Firefox."""

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

from test_browser_smoke import BrowserSmoke


class EicarBrowser(BrowserSmoke):
    def __init__(self, token, scope):
        super().__init__()
        self.token = token
        self.scope = scope

    def exercise_dashboard(self, call, origin):
        def element(selector):
            result = call("POST", "/element", {"using": "css selector", "value": selector})
            return "/element/" + result["element-6066-11e4-a52e-4f735466cecf"]

        def wait_for(script, description, timeout=20):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                value = call("POST", "/execute/sync", {"script": script, "args": []})
                if value:
                    return value
                time.sleep(.2)
            self.fail(f"Dashboard did not show {description}")

        call("POST", "/url", {"url": origin})
        wait_for("return !document.querySelector('#unlock').hidden", "the unlock form")
        call("POST", element("#token") + "/value", {"text": self.token})
        call("POST", element("#unlock button") + "/click", {})
        wait_for("return !document.querySelector('#dashboard').hidden", "the unlocked dashboard")
        activity_alert = r"""
            if (document.querySelector('#activity').hidden) return null;
            const entry = [...document.querySelectorAll('#all-events > li')].find(row =>
                row.getClientRects().length &&
                row.querySelector('strong')?.textContent === 'ClamAV detected malware' &&
                row.querySelector('[aria-label="High severity"]') &&
                /\/eicar\.com\.txt: [^\n]*eicar[^\n]* FOUND/i.test(row.innerText));
            return entry?.dataset.eventId;
        """
        call("POST", element("[data-page='activity']") + "/click", {})
        event_id = int(wait_for(activity_alert, "the high-severity EICAR alert in Activity"))
        call("POST", element("[data-page='findings']") + "/click", {})
        alert = f'#finding-events > li[data-event-id="{event_id}"]'
        wait_for(f"return !document.querySelector('#findings').hidden && document.querySelector('{alert}')",
                 "the detection in Open findings")
        call("POST", element("#finding-status option[value='unreviewed']") + "/click", {})
        wait_for(f"return document.querySelector('{alert} button')?.textContent === 'Acknowledge'",
                 "the unreviewed detection")
        call("POST", element(f"{alert} button") + "/click", {})
        call("POST", element("#finding-status option[value='acknowledged']") + "/click", {})
        wait_for(f"return document.querySelector('{alert}')?.innerText.includes('Acknowledged')",
                 "the original detection in acknowledged findings")
        call("POST", element("[data-page='sensors']") + "/click", {})
        wait_for("""
            const readiness = document.querySelector('#antivirus-readiness').innerText;
            return !document.querySelector('#sensors').hidden &&
                readiness.includes('Ready') && readiness.includes('Signature age') &&
                readiness.includes(SCAN_SCOPE) &&
                document.querySelector('#antivirus-check-time').innerText.includes('Next scan') &&
                document.querySelector('#antivirus-checks strong')?.textContent === 'Detection';
        """.replace("SCAN_SCOPE", repr(self.scope)), "antivirus readiness and the original detection")
        call("POST", element("#scan-antivirus") + "/click", {})
        wait_for("""
            return document.querySelector('#antivirus-checks strong')?.textContent === 'Clean' &&
                /No malware reported across 1 scanned files/.test(document.querySelector('#antivirus-checks').innerText);
        """, "a clean scan after clicking Scan now", timeout=110)
        call("POST", element("#antivirus-coverage summary") + "/click", {})
        wait_for("""
            const coverage = document.querySelector('#antivirus-coverage');
            return coverage.open && coverage.innerText.includes(SCAN_SCOPE) &&
                coverage.innerText.includes('Files counted by ClamAV: 1');
        """.replace("SCAN_SCOPE", repr(self.scope)), "the coverage counts for the clean path")
        call("POST", element("[data-page='findings']") + "/click", {})
        wait_for(f"return document.querySelector('{alert} button')?.textContent === 'Resolve with clean scan'",
                 "the clean scan resolution action")
        call("POST", element(f"{alert} button") + "/click", {})
        wait_for(f"return !document.querySelector('{alert}')", "the resolved detection leaving the open queue")
        call("POST", element("#finding-status option[value='resolved']") + "/click", {})
        resolved = f'''const row = document.querySelector('{alert}');
            return row?.innerText.includes('Resolved') && row.innerText.includes('Clean scan') &&
                row.innerText.includes('No malware reported across 1 scanned files') &&
                row.innerText.includes('Eicar-Test-Signature FOUND');'''
        wait_for(resolved, "resolution evidence alongside the original detection")
        call("POST", "/refresh", {})
        wait_for("return !document.querySelector('#findings').hidden && !document.querySelector('#dashboard').hidden",
                 "the findings view after reloading")
        call("POST", element("#finding-status option[value='resolved']") + "/click", {})
        wait_for(resolved, "the preserved detection and resolution after a reload")
        call("POST", element("[data-page='activity']") + "/click", {})
        self.assertEqual(event_id, int(wait_for(activity_alert, "the original EICAR alert in Activity")))
        print(f"Firefox reviewed EICAR event {event_id} in Open findings and verified it remained in Activity.")


def main(work, ssh_port, dashboard_port, mode):
    driver = shutil.which(os.environ.get("WATCHDOG_GECKODRIVER", "geckodriver"))
    if not driver:
        raise SystemExit("Install Firefox and GeckoDriver or set WATCHDOG_GECKODRIVER.")
    if driver == "/snap/bin/geckodriver":
        bundled = Path("/snap/firefox/current/usr/lib/firefox")
        if all(os.access(bundled / name, os.X_OK) for name in ("firefox", "geckodriver")):
            driver = str(bundled / "geckodriver")
            os.environ.setdefault("WATCHDOG_FIREFOX", str(bundled / "firefox"))

    ssh = [
        "ssh", "-T", "-i", str(work / "vm-key"), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", f"UserKnownHostsFile={work / 'known_hosts'}", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=6", "-p", ssh_port,
    ]
    address = "ubuntu@127.0.0.1"
    system = mode == "system-upgrade"
    token_command = "sudo -n cat /var/lib/ai-watchdog/token" if system else "cat /home/ubuntu/watchdog-smoke/.watchdog/token"
    token = subprocess.check_output([*ssh, address, token_command], text=True, timeout=15).strip()
    scope = "/srv/watchdog-smoke/files" if system else "/home/ubuntu/Downloads/Watchdog Scan"
    forwarding = f"127.0.0.1:{dashboard_port}:127.0.0.1:{dashboard_port}"
    origin = f"http://127.0.0.1:{dashboard_port}"
    with subprocess.Popen([*ssh, "-L", forwarding, "-N", address]) as tunnel:
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with urlopen(origin, timeout=2):
                        break
                except URLError:
                    if tunnel.poll() is not None or time.monotonic() >= deadline:
                        raise
                    time.sleep(.2)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                driver_port = listener.getsockname()[1]
            EicarBrowser(token, scope).run_browser(driver, driver_port, origin, work)
        finally:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()


if __name__ == "__main__":
    main(Path(sys.argv[1]), *sys.argv[2:])
