import http.client
import json
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path

from watchdog import monitor, store
from watchdog.server import Console

TOKEN = "integration-test-only-token"


@contextmanager
def running_console(database, *, workers=True):
    app = monitor.Monitor({"port": 0, "interval": 10, "ollama_model": ""}, database, database.parent, demo=True)
    try:
        console = Console(app, TOKEN)
    except PermissionError as error:
        raise unittest.SkipTest("Local socket access is unavailable") from error
    with console:
        thread = threading.Thread(target=console.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            if workers:
                console.start_workers()
                if not app.ready.wait(3):
                    raise RuntimeError("Demo monitor never became ready")
            yield console
        finally:
            app.stop.set()
            console.shutdown()
            thread.join(timeout=3)
            if workers:
                app.worker.join(timeout=3)


def request(console, method, path, *, authorized=True, body=None, headers=None):
    supplied = {"Origin": console.origin}
    if authorized:
        supplied["Authorization"] = f"Bearer {TOKEN}"
    if body is not None:
        supplied["Content-Type"] = "application/json"
    supplied.update(headers or {})
    connection = http.client.HTTPConnection("127.0.0.1", console.server_port, timeout=3)
    try:
        connection.request(method, path, body=body, headers=supplied)
        response = connection.getresponse()
        raw = response.read()
        result = json.loads(raw) if response.getheader("Content-Type", "").startswith("application/json") else raw
        return response.status, result, dict(response.getheaders())
    finally:
        connection.close()


class ConsoleIntegrationTests(unittest.TestCase):
    def setUp(self):
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        self.database = Path(state.name) / "watchdog.sqlite3"

    def wait_for_check(self, console, trigger):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status, data, _ = request(console, "GET", "/api/status")
            self.assertEqual(200, status)
            result = data["assessment"]
            if result and result["trigger"] == trigger and not data["assessing"]:
                self.assertNotIn("error", result)
                return data
            time.sleep(.03)
        self.fail(f"No completed {trigger} check")

    def test_public_assets_and_private_api_on_the_real_http_server(self):
        with running_console(self.database, workers=False) as console:
            code, body, _ = request(console, "GET", "/health", authorized=False)
            self.assertEqual((503, b"starting\n"), (code, body))
            self.assertEqual(503, request(console, "POST", "/api/check")[0])
            code, html, headers = request(console, "GET", "/", authorized=False)
            self.assertEqual(200, code)
            self.assertIn(b"Run AI check", html)
            self.assertIn(b"Traffic spikes by interface", html)
            self.assertEqual("no-store", headers["Cache-Control"])
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertEqual(200, request(console, "GET", "/app.js", authorized=False)[0])
            self.assertEqual(401, request(console, "GET", "/api/status", authorized=False)[0])
            self.assertEqual(421, request(console, "GET", "/api/status", headers={"Host": "other.test"})[0])
            self.assertEqual(403, request(console, "POST", "/api/check", headers={"Origin": "http://other.test"})[0])
            self.assertEqual(400, request(console, "POST", "/api/check", body=b"{}")[0])
            self.assertEqual(404, request(console, "GET", "/api/unknown")[0])

    def test_manual_check_rate_limit_and_persistence_after_reopening(self):
        with running_console(self.database) as console:
            self.assertEqual(200, request(console, "GET", "/health", authorized=False)[0])
            self.assertEqual(202, request(console, "POST", "/api/check")[0])
            self.assertEqual(429, request(console, "POST", "/api/check")[0])
            completed = self.wait_for_check(console, "manual")
            self.assertTrue(any(event["title"] == "Active AI check completed" for event in completed["events"]))
            self.assertEqual("demo", completed["response"]["mode"])
            self.assertFalse(completed["email"]["enabled"])
        with running_console(self.database) as restarted:
            code, snapshot, _ = request(restarted, "GET", "/api/status")
            self.assertEqual(200, code)
            self.assertEqual(completed["assessment"], snapshot["assessment"])
            self.assertEqual(completed["device_count"], snapshot["device_count"])

    def test_scheduler_fires_overdue_check_after_reopening_the_database(self):
        with running_console(self.database, workers=False) as console:
            self.assertEqual(403, request(console, "PUT", "/api/schedule", body=b'{"interval_minutes":5}',
                                          headers={"Origin": "http://other.test"})[0])
            self.assertEqual(400, request(console, "PUT", "/api/schedule", body=b'{"interval_minutes":4}')[0])
            code, saved, _ = request(console, "PUT", "/api/schedule", body=b'{"interval_minutes":5}')
            self.assertEqual(200, code)
            self.assertEqual(5, saved["interval_minutes"])
        # Make one saved occurrence overdue without leaving a test running for five minutes.
        due = time.time() - 1
        with store.connect(self.database) as db:
            store.property_set(db, "check_schedule", {**saved, "next_at": due})
        with running_console(self.database) as restarted:
            result = self.wait_for_check(restarted, "scheduled")
            self.assertEqual(due + 300, result["schedule"]["next_at"])
            self.assertEqual(1, sum(event["title"] == "Scheduled AI check completed" for event in result["events"]))
            code, disabled, _ = request(restarted, "PUT", "/api/schedule", body=b'{"interval_minutes":0}')
            self.assertEqual((200, {"interval_minutes": 0, "next_at": None}), (code, disabled))
