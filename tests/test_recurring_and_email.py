import io
import json
import tempfile
import threading
import unittest
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from watchdog import monitor, notifications, schedule, store, system_checks
from watchdog.server import Console, Handler


class RecurringAndEmailTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.database = self.directory / "watchdog.sqlite3"
        store.initialize(self.database)
        self.email = notifications.configuration({
            "host": "smtp.example.com", "sender": "watchdog@example.com", "recipient": "me@example.com",
        }, self.directory)

    def test_rejects_invalid_intervals_and_preserves_due_time_on_identical_save(self):
        with store.connect(self.database) as db:
            for invalid in (True, -1, 4, 5.0, "60", 10081):
                with self.assertRaises(ValueError):
                    schedule.save(db, invalid, 100)
            self.assertEqual(schedule.save(db, 5, 100), schedule.save(db, 5, 200))
            self.assertEqual(400, schedule.read(db)["next_at"])
            self.assertIsNone(schedule.save(db, 0, 100)["next_at"])

    def test_scheduled_assessment_catches_up_once_without_changing_manual_checks(self):
        app = monitor.Monitor(
            {"ollama_model": ""}, self.database, self.directory, demo=True,
        )
        console = Console.__new__(Console)
        console.monitor = app
        console.assessment_lock = threading.Lock()
        with store.connect(self.database) as db:
            due = schedule.save(db, 5, 100)
        with patch("watchdog.server.time.time", return_value=1050):
            console.run_assessment()
            console.run_assessment(due)
        with store.connect(self.database) as db:
            self.assertEqual(1300, schedule.read(db)["next_at"])
            self.assertEqual("scheduled", store.property_get(db, "assessment")["trigger"])
            titles = {row[0] for row in db.execute("SELECT title FROM events WHERE kind='assessment'")}
            self.assertEqual({"Active AI check completed", "Scheduled AI check completed"}, titles)

    def test_edit_during_run_wins_over_previous_occurrence(self):
        with store.connect(self.database) as db:
            earlier = schedule.save(db, 5, 100)
            later = schedule.save(db, 15, 401)
            schedule.advance(db, earlier, 410)
            self.assertEqual(later, schedule.read(db))

    def test_schedule_endpoint_requires_exact_origin_and_authentication(self):
        handler = Handler.__new__(Handler)
        handler.server = SimpleNamespace(
            authority="127.0.0.1:8765", origin="http://127.0.0.1:8765", token="secret",
            monitor=SimpleNamespace(database=self.database),
        )
        handler.path = "/api/schedule"
        body = json.dumps({"interval_minutes": 60}).encode()
        for origin, token, code in (
            ("http://elsewhere.example", "Bearer secret", 403),
            (handler.server.origin, "", 401),
            (handler.server.origin, "Bearer secret", 200),
        ):
            handler.headers = Message()
            handler.headers["Host"] = handler.server.authority
            handler.headers["Origin"] = origin
            handler.headers["Authorization"] = token
            handler.headers["Content-Type"] = "application/json"
            handler.headers["Content-Length"] = str(len(body))
            handler.rfile = io.BytesIO(body)
            with patch.object(handler, "reply") as reply:
                handler.do_PUT()
                self.assertEqual(code, reply.call_args.args[0])
        with store.connect(self.database) as db:
            self.assertEqual(60, schedule.read(db)["interval_minutes"])

    def test_email_sends_only_new_matching_events_without_details(self):
        with store.connect(self.database) as db:
            store.event(db, 100, "critical", "watchdog", "Old event")
            notifications.prepare(db, self.email)
            store.event(db, 102, "medium", "anomaly", "Moderate event")
            store.event(db, 103, "high", "integrity", "Trusted file changed", "private detail", "/etc/file")
            store.event(db, 104, "critical", "watchdog", "Containment isolated")
        with patch.object(notifications.smtplib, "SMTP") as client:
            notifications.deliver(self.database, self.email, 105)
            smtp = client.return_value
            smtp.starttls.assert_called_once()
            smtp.send_message.assert_called_once()
            message = smtp.send_message.call_args.args[0]
            self.assertIn("Trusted file changed", message.get_content())
            self.assertIn("Containment isolated", message.get_content())
            for withheld in ("private detail", "/etc/file", "Moderate event", "Old event"):
                self.assertNotIn(withheld, message.get_content())
        with store.connect(self.database) as db:
            status = notifications.status(db)
            self.assertEqual(0, status["pending"])
            self.assertEqual(105, status["last_sent_at"])
            self.assertIsNone(status["coverage"]["last_accepted_at"])

    def test_pending_email_retries_and_is_cleared_when_recipient_changes(self):
        with store.connect(self.database) as db:
            notifications.prepare(db, {**self.email, "minimum_severity": "critical"})
            store.event(db, 100, "high", "integrity", "Skip high severity")
            store.event(db, 100, "critical", "watchdog", "Notify")
        with patch.object(notifications, "send", side_effect=ConnectionError) as send:
            notifications.deliver(self.database, self.email, 105)
            notifications.deliver(self.database, self.email, 110)
            send.assert_called_once()
        with store.connect(self.database) as db:
            status = notifications.status(db)
            self.assertEqual((1, 165), (status["pending"], status["retry_at"]))
            notifications.prepare(db, {**self.email, "recipient": "other@example.com"})
            self.assertEqual(0, notifications.status(db)["pending"])

    def test_coverage_email_waits_for_unresolved_incidents_and_cancels_on_recovery(self):
        path = "/private/scan/path"
        settings = {**self.email, "minimum_severity": "critical", "coverage_notify_minutes": 2}
        failed = {"path": path, "status": "warn", "access_errors": 1}
        clean = {"path": path, "status": "pass", "files_scanned": 1}
        with store.connect(self.database) as db:
            notifications.prepare(db, settings)
            for at in (10, 20, 30):
                system_checks.update_coverage_alerts(db, at, [failed])
        notifications.queue_coverage(self.database, self.email, [path], 500)
        notifications.queue_coverage(self.database, settings, [path], 149)
        with store.connect(self.database) as db:
            self.assertEqual(0, notifications.status(db)["pending"])
        for at in (150, 151):
            notifications.queue_coverage(self.database, settings, [path], at)
        with store.connect(self.database) as db:
            self.assertEqual(1, notifications.status(db)["pending"])
            system_checks.update_coverage_alerts(db, 152, [clean])
            self.assertEqual(0, notifications.status(db)["pending"])
            for at in (160, 170, 180):
                system_checks.update_coverage_alerts(db, at, [failed])
        notifications.queue_coverage(self.database, settings, [path], 300)
        with patch.object(notifications, "send", side_effect=ConnectionError):
            notifications.deliver(self.database, settings, 301)
        with store.connect(self.database) as db:
            coverage = notifications.status(db)["coverage"]
            self.assertEqual((1, 361, None), (coverage["pending"], coverage["retry_at"], coverage["last_accepted_at"]))
        with patch.object(notifications.smtplib, "SMTP") as client:
            notifications.deliver(self.database, settings, 361)
            message = client.return_value.send_message.call_args.args[0]
            self.assertIn("Antivirus coverage warning", message["Subject"])
            self.assertNotIn(path, message.get_content())
        notifications.queue_coverage(self.database, settings, [path], 1000)
        with store.connect(self.database) as db:
            status = notifications.status(db)["coverage"]
            self.assertEqual((0, None, 361), (status["pending"], status["retry_at"], status["last_accepted_at"]))

    def test_dashboard_distinguishes_expired_coverage_email_from_ordinary_alerts(self):
        settings = {**self.email, "coverage_notify_minutes": 1}
        with store.connect(self.database) as db:
            notifications.prepare(db, settings)
            queued = db.execute("INSERT INTO email_outbox(at,severity,title) VALUES (1,'medium','Coverage warning')")
            db.execute("INSERT INTO coverage_email VALUES (?, ?)", ("/coverage", queued.lastrowid))
            store.event(db, 10000, "high", "other", "Recent ordinary alert")
        with patch.object(notifications, "send"):
            notifications.deliver(self.database, settings, 86402)
        with store.connect(self.database) as db:
            status = notifications.status(db)
            self.assertEqual(86402, status["last_sent_at"])
            self.assertEqual({"pending": 0, "retry_at": None, "last_accepted_at": None, "last_expired_at": 86402},
                             status["coverage"])

    def test_smtp_password_is_read_only_from_private_regular_file(self):
        path = self.directory / "smtp-password"
        path.write_text("fake-password\n")
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            notifications.read_password(path)
        path.chmod(0o600)
        self.assertEqual("fake-password", notifications.read_password(path))
