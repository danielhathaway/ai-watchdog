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


@unittest.skipUnless(os.environ.get("WATCHDOG_BROWSER_SMOKE") == "1", "Set WATCHDOG_BROWSER_SMOKE=1")
class BrowserSmoke(unittest.TestCase):
    def test_authenticated_dashboard_and_settings(self):
        driver = shutil.which(os.environ.get("WATCHDOG_GECKODRIVER", "geckodriver"))
        self.assertIsNotNone(driver, "Install GeckoDriver and Firefox")
        with tempfile.TemporaryDirectory(prefix="watchdog-browser-") as directory:
            state = Path(directory)
            try:
                with running_console(state / "monitor.sqlite3") as console, socket.socket() as listener:
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
        wait_for("document.querySelector('#vulnerability-status').textContent.includes('No scan recorded')")
        click("[data-page='settings']")
        fill("#schedule-minutes", "60")
        click("#schedule-form button")
        wait_for("document.querySelector('#next-check').innerText !== 'Off' && "
                 "!document.querySelector('#schedule-feedback').hidden")
        call("POST", "/refresh", {})
        wait_for("!document.querySelector('#dashboard').hidden && document.querySelector('#schedule-minutes').value === '60'")
        click("#lock")
        wait_for("!document.querySelector('#unlock').hidden && document.querySelector('#dashboard').hidden")
