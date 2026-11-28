import ipaddress
import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import collector, offhost, store
from watchdog.common import BOOT_ID, uptime, write_json

NOW = 1_800_000_000
EVENT = {"id": "c" * 32, "at": NOW, "severity": "critical", "kind": "integrity",
         "title": "Protected file changed", "detail": "Synthetic evidence", "subject": "/fixture"}


def packet(at, *, boot=BOOT_ID, events=()):
    return {"version": 1, "sent_at": int(at * offhost.TICKS), "boot_id": boot, "events": list(events)}


class OffHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / collector.STATE_NAME
        collector.initialize(self.database, {"a", "b"}, None, NOW)

    def test_never_seen_silence_restart_and_recovery(self):
        collector.receive(self.database, "a", packet(NOW + 20), NOW + 20)
        collector.check_silence(self.database, NOW + 30, 30)
        collector.initialize(self.database, {"a", "b"}, None, NOW + 31)
        collector.check_silence(self.database, NOW + 32, 30)
        state = collector.status(self.database, 10)
        self.assertEqual(["reporting", "silent"], [row["status"] for row in state["endpoints"]])
        self.assertEqual(["Endpoint heartbeat missing: b"], [row["title"] for row in state["alerts"]])
        collector.receive(self.database, "b", packet(NOW + 35), NOW + 35)
        state = collector.status(self.database, 10)
        self.assertEqual("reporting", state["endpoints"][1]["status"])
        self.assertEqual("Endpoint heartbeat recovered: b", state["alerts"][0]["title"])
        collector.initialize(self.database, {"b"}, None, NOW + 36)
        self.assertEqual(["b"], [row["name"] for row in collector.status(self.database, 10)["endpoints"]])

    def test_events_without_heartbeat_do_not_clear_silence_and_replays_do_not_advance_it(self):
        report = packet(NOW, events=[EVENT])
        self.assertTrue(collector.receive(self.database, "a", report, NOW))
        self.assertFalse(collector.receive(self.database, "a", report, NOW + 25))
        collector.check_silence(self.database, NOW + 30, 30)
        self.assertTrue(collector.receive(self.database, "a", packet(NOW + 40, boot=None, events=[EVENT]), NOW + 40))
        state = collector.status(self.database, 10)
        self.assertEqual(NOW + 40, state["endpoints"][0]["last_report"])
        self.assertEqual(NOW, state["endpoints"][0]["last_heartbeat"])
        self.assertEqual("silent", state["endpoints"][0]["status"])
        self.assertEqual(1, len(state["events"]))
        self.assertEqual(NOW, state["events"][0]["received_at"])

    def test_silence_uses_existing_email_outbox(self):
        email = {"recipient": "to@example.com", "sender": "from@example.com", "host": "localhost",
                 "port": 587, "minimum_severity": "high"}
        collector.initialize(self.database, {"a"}, email, NOW)
        collector.check_silence(self.database, NOW + 30, 30)
        collector.check_silence(self.database, NOW + 40, 30)
        self.assertEqual(1, collector.status(self.database, 10)["pending_alert_emails"])

    def test_payload_rejects_expired_malformed_or_low_severity_evidence(self):
        for report in (packet(NOW - 121), packet(NOW + 31), packet(NOW, boot=None),
                       packet(NOW, events=[EVENT, EVENT]), packet(NOW, events=[{**EVENT, "severity": "medium"}]),
                       packet(NOW, events=[{**EVENT, "title": "\ud800"}]), {**packet(NOW), "version": True}):
            with self.subTest(report=report):
                with self.assertRaises(ValueError):
                    offhost.validate_payload(json.dumps(report).encode(), NOW)
        self.assertEqual(packet(NOW, events=[EVENT]),
                         offhost.validate_payload(json.dumps(packet(NOW, events=[EVENT])).encode(), NOW))

    def test_local_event_id_reuse_gets_a_new_export_id(self):
        db = self.root / "monitor.sqlite3"
        store.initialize(db)
        with store.connect(db) as connection:
            first = store.event(connection, NOW, "high", "unit", "First")
        with store.connect(db) as connection:
            initial, = offhost.pending(connection, ["localhost", 8443, "a"])
        with store.connect(db) as connection:
            connection.execute("DELETE FROM events")
            second = store.event(connection, NOW, "high", "unit", "Second")
        with store.connect(db) as connection:
            replacement, = offhost.pending(connection, ["localhost", 8443, "a"])
        self.assertEqual(first, second)
        self.assertNotEqual(initial["id"], replacement["id"])

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for off-host TLS integration")
    def test_verified_tls_delivery_and_acknowledgment_retry(self):
        certificate = self.root / "collector.pem"
        key = self.root / "collector-key.pem"
        subprocess.run(
            ["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/CN=offhost-fixture", "-addext", "subjectAltName=IP:127.0.0.1",
             "-keyout", str(key), "-out", str(certificate)],
            capture_output=True, check=True, timeout=15,
        )
        try:
            probe = collector.Server(ipaddress.ip_address("127.0.0.1"), 0, self.database,
                                     {"a": "a" * 64, "b": "b" * 64}, ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), 300, 30)
        except PermissionError:
            self.skipTest("Local socket access is unavailable")
        self.addCleanup(probe.server_close)
        probe.tls.load_cert_chain(certificate, key)
        probe.next_check = time.monotonic() + 60
        thread = threading.Thread(target=probe.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(probe.shutdown)
        port = probe.server_port
        config = self.root / "sender.json"
        credential = self.root / "endpoint.key"
        write_json(config, {"endpoint": "a", "url": f"https://127.0.0.1:{port}",
                            "key_file": credential.name, "ca_file": certificate.name})
        credential.write_text("a" * 64)
        credential.chmod(0o600)
        database = self.root / "monitor.sqlite3"
        store.initialize(database)
        with store.connect(database) as db:
            store.event(db, time.time(), "high", "fixture", "One high alert")
            store.event(db, time.time(), "medium", "fixture", "Medium event stays local")
        write_json(self.root / "heartbeat.json", {"at": uptime(), "boot_id": BOOT_ID, "blocks": {}, "isolate": False})
        settings = {"heartbeat_timeout": 45}

        with self.assertRaises(ssl.SSLCertVerificationError):
            offhost.transmit("localhost", port, "a", "a" * 64, certificate, packet(time.time()))
        with self.assertRaisesRegex(ValueError, "did not accept"):
            offhost.transmit("127.0.0.1", port, "a", "b" * 64, certificate, packet(time.time()))
        self.assertIsNone(collector.status(self.database, 10)["endpoints"][0]["last_heartbeat"])

        send = offhost.transmit

        def lost_response(*args):
            send(*args)
            raise OSError("Response lost after commit")

        with patch.object(offhost, "transmit", side_effect=lost_response):
            with self.assertRaisesRegex(OSError, "Response lost"):
                offhost.send(self.root, self.root, settings, config)
        with store.connect(database) as db:
            self.assertEqual(0, db.execute("SELECT delivered FROM offhost_delivery").fetchone()[0])
        self.assertEqual({"heartbeat": True, "events": 1}, offhost.send(self.root, self.root, settings, config))
        state = collector.status(self.database, 10)
        self.assertEqual(["One high alert"], [row["title"] for row in state["events"]])
        self.assertEqual("reporting", state["endpoints"][0]["status"])
        self.assertEqual({"heartbeat": True, "events": 0}, offhost.send(self.root, self.root, settings, config))

        (self.root / "heartbeat.json").unlink()
        with store.connect(database) as db:
            store.event(db, time.time(), "critical", "fixture", "Event during loss of monitor heartbeat")
        previous = collector.status(self.database, 10)["endpoints"][0]["last_heartbeat"]
        self.assertEqual({"heartbeat": False, "events": 1}, offhost.send(self.root, self.root, settings, config))
        self.assertEqual(previous, collector.status(self.database, 10)["endpoints"][0]["last_heartbeat"])
