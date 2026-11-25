import shutil
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest
from contextlib import contextmanager
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import patch

from watchdog import notifications, store


class MailSink(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        self.wfile.write(b"220 localhost test sink\r\n")
        for line in self.rfile:
            command = line.split(maxsplit=1)[0].upper()
            if command == b"DATA":
                self.wfile.write(b"354 End message with a period\r\n")
                message = bytearray()
                for line in self.rfile:
                    if line == b".\r\n":
                        break
                    message.extend(line[1:] if line.startswith(b"..") else line)
                else:
                    return
                self.server.received.append(bytes(message))
                self.wfile.write(b"250 Accepted\r\n")
            elif command in {b"EHLO", b"HELO", b"MAIL", b"RCPT"}:
                self.wfile.write(b"250 localhost\r\n")
            else:
                self.wfile.write(b"500 Command not supported\r\n")


@contextmanager
def local_mail_sink(certificate, key):
    try:
        server = socketserver.TCPServer(("127.0.0.1", 0), MailSink)
    except PermissionError as error:
        raise unittest.SkipTest("Local socket access is unavailable") from error
    with server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        server.received = []
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=3)


class SMTPIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is needed to generate a temporary test certificate")
    def test_rejected_certificate_keeps_alert_queued_and_trusted_retry_delivers_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            certificate, key = directory / "cert.pem", directory / "key.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                "-keyout", str(key), "-out", str(certificate),
            ], check=True, capture_output=True, timeout=10)
            database = directory / "watchdog.sqlite3"
            store.initialize(database)
            untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            trusted = ssl.create_default_context(cafile=str(certificate))
            with local_mail_sink(certificate, key) as sink:
                settings = notifications.configuration({
                    "host": "127.0.0.1", "security": "tls", "port": sink.server_address[1],
                    "sender": "watchdog@example.test", "recipient": "recipient@example.test",
                }, directory)
                with store.connect(database) as db:
                    notifications.prepare(db, settings)
                    store.event(db, 100, "critical", "integrity", "File changed", "private detail", "/etc/private")
                with patch.object(notifications.ssl, "create_default_context", return_value=untrusted):
                    notifications.deliver(database, settings, 100)
                self.assertEqual([], sink.received)
                with store.connect(database) as db:
                    pending = notifications.status(db)
                self.assertEqual((1, 160), (pending["pending"], pending["retry_at"]))
                with patch.object(notifications.ssl, "create_default_context", return_value=trusted):
                    notifications.deliver(database, settings, 160)
                    notifications.deliver(database, settings, 230)
                self.assertEqual(1, len(sink.received))
                message = BytesParser(policy=policy.default).parsebytes(sink.received[0])
                self.assertEqual("recipient@example.test", message["To"])
                self.assertIn("File changed", message.get_content())
                self.assertNotIn("private", message.get_content())
                with store.connect(database) as db:
                    delivered = notifications.status(db)
                self.assertEqual((0, 160, None), (delivered["pending"], delivered["last_sent_at"], delivered["retry_at"]))
