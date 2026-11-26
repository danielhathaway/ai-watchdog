import http.client
import json
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path

from watchdog import monitor, store, system_checks
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

    def test_antivirus_request_requires_authorization_and_rejects_duplicate_work(self):
        with running_console(self.database, workers=False) as console:
            path = "/api/antivirus/scan"
            self.assertEqual(503, request(console, "POST", path)[0])
            console.monitor.ready.set()
            self.assertEqual(409, request(console, "POST", path)[0])
            console.monitor.settings["antivirus_paths"] = ["/downloads"]
            console.monitor.antivirus = system_checks.AntivirusWorker(console.monitor)
            self.assertEqual(401, request(console, "POST", path, authorized=False)[0])
            self.assertEqual(403, request(console, "POST", path, headers={"Origin": "http://other.test"})[0])
            self.assertEqual(400, request(console, "POST", path, body=b'{"path":"/"}')[0])
            self.assertEqual(202, request(console, "POST", path)[0])
            self.assertEqual(429, request(console, "POST", path)[0])
            _, snapshot, _ = request(console, "GET", "/api/status")
            status = snapshot["system_checks"]["antivirus"]
            self.assertTrue(status["running"])
            self.assertEqual(["/downloads"], status["paths"])

    def test_alert_review_records_clean_evidence_without_changing_the_detection(self):
        paths = ["/downloads"]
        detection = system_checks.result("clamav", "ClamAV malware scan", "fail", "EICAR detected")
        clean = {**system_checks.result("clamav", "ClamAV malware scan", "pass", "One file scanned."),
                 "files_scanned": 1}
        now = time.time()
        with running_console(self.database, workers=False) as console:
            system_checks.save(self.database, "antivirus", now - 5, [detection], paths=paths)
            console.monitor.settings["antivirus_paths"] = paths
            _, status, _ = request(console, "GET", "/api/status")
            original, = status["events"]
            endpoint = f"/api/alerts/{original['id']}"
            ack = endpoint + "/acknowledge"
            resolve = endpoint + "/resolve"
            self.assertEqual(401, request(console, "POST", ack, authorized=False)[0])
            self.assertEqual(403, request(console, "POST", ack, headers={"Origin": "http://other.test"})[0])
            self.assertEqual(400, request(console, "POST", ack, body=b"{}")[0])
            self.assertEqual(404, request(console, "POST", "/api/alerts/999/acknowledge")[0])
            self.assertEqual(409, request(console, "POST", resolve)[0])
            code, acknowledged, _ = request(console, "POST", ack)
            self.assertEqual(200, code)
            self.assertIsNotNone(acknowledged["acknowledged_at"])
            self.assertEqual(acknowledged, request(console, "POST", ack)[1])

            for report, scope in ((clean, ["/other"]), ({**clean, "files_scanned": 0}, paths)):
                system_checks.save(self.database, "antivirus", now - 3, [report], paths=scope)
                self.assertEqual(409, request(console, "POST", resolve)[0])
            system_checks.save(self.database, "antivirus", now - 1, [clean], paths=paths)
            code, resolved, _ = request(console, "POST", resolve)
            self.assertEqual(200, code)
            self.assertEqual(now - 1, resolved["evidence_at"])
            self.assertEqual(clean["detail"], resolved["evidence_detail"])
            system_checks.save(self.database, "antivirus", now, [detection], paths=paths)
            self.assertEqual(resolved, request(console, "POST", resolve)[1])
            _, status, _ = request(console, "GET", "/api/status")
            retained, = [event for event in status["events"] if event["id"] == original["id"]]
            self.assertEqual({**original, "review": resolved}, retained)

            with store.connect(self.database) as db:
                older = store.event(db, now - 10, "high", "system-check", "ClamAV detected malware",
                                    "Older detection without a saved scope", "antivirus/clamav")
            system_checks.save(self.database, "antivirus", now + 1, [clean], paths=paths)
            code, review, _ = request(console, "POST", f"/api/alerts/{older}/acknowledge")
            self.assertEqual(200, code)
            self.assertFalse(review["scope_recorded"])
            self.assertEqual(409, request(console, "POST", f"/api/alerts/{older}/resolve")[0])

        with store.connect(self.database) as db:
            store.expire(db, now + 86401, 1)
            self.assertEqual(0, db.execute("SELECT count(*) FROM finding_reviews").fetchone()[0])

    def test_findings_pagination_and_filters_reach_events_beyond_activity(self):
        with running_console(self.database, workers=False) as console:
            now = time.time()
            with store.connect(self.database) as db:
                ids = [
                    store.event(db, now, "high", "system-check", "ClamAV detected malware", str(index), "antivirus/clamav")
                    for index in range(53)
                ]
                db.execute("INSERT INTO finding_reviews(event_id, acknowledged_at, resolved_at) VALUES (?, ?, ?)",
                           (ids[0], now, now))
                db.execute("INSERT INTO finding_reviews(event_id, acknowledged_at) VALUES (?, ?)", (ids[1], now))
                for _ in range(101):
                    store.event(db, now, "info", "test", "Other event")
            status, activity, _ = request(console, "GET", "/api/status")
            self.assertEqual(200, status)
            self.assertTrue(all(event["kind"] == "test" for event in activity["events"]))
            self.assertEqual(401, request(console, "GET", "/api/findings", authorized=False)[0])
            for query in ("?status=bad", "?before=0", "?status=open&status=all", "?unknown=1"):
                self.assertEqual(400, request(console, "GET", "/api/findings" + query)[0])

            found = []
            path = "/api/findings"
            for count in (25, 25, 2):
                status, page, _ = request(console, "GET", path)
                self.assertEqual(200, status)
                self.assertEqual(count, len(page["events"]))
                found.extend(item["id"] for item in page["events"])
                path = f"/api/findings?before={page['next_before']}"
            self.assertIsNone(page["next_before"])
            self.assertEqual(list(reversed(ids[1:])), found)
            for status, expected in (("acknowledged", [ids[1]]), ("resolved", [ids[0]])):
                _, page, _ = request(console, "GET", f"/api/findings?status={status}")
                self.assertEqual(expected, [item["id"] for item in page["events"]])
            _, page, _ = request(console, "GET", f"/api/findings?status=unreviewed&before={ids[2]}")
            self.assertEqual([], page["events"])

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
