"""Independent HTTPS receiver for endpoint evidence and silence alerts."""

import hmac
import ipaddress
import logging
import re
import socket
import socketserver
import sqlite3
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import notifications, offhost, store
from .backup_job import private_file

STATE_NAME = "telemetry.sqlite3"
CHECK_SECONDS = 5
MAX_ENDPOINTS = 256
SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    name TEXT PRIMARY KEY, enrolled_at REAL NOT NULL, last_report REAL,
    last_sent INTEGER, last_heartbeat REAL, boot_id TEXT, silent_at REAL
);
CREATE TABLE IF NOT EXISTS received_events (
    endpoint TEXT NOT NULL, event_id TEXT NOT NULL, at REAL NOT NULL, received_at REAL NOT NULL,
    severity TEXT NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, subject TEXT NOT NULL,
    PRIMARY KEY (endpoint, event_id)
);
CREATE INDEX IF NOT EXISTS received_event_time ON received_events(received_at);
"""


def configuration(path):
    data = offhost.read_settings(path, {"listen", "port", "certificate", "private_key", "endpoints"},
                                 {"silence_seconds", "retention_days", "email_alerts"})
    if not isinstance(data["listen"], str):
        raise ValueError("Collector listen address must be a numeric IP address")
    listen = ipaddress.ip_address(data["listen"])
    for field, default, low, high in (("port", None, 1024, 65535), ("silence_seconds", 180, 30, 86400),
                                      ("retention_days", 30, 1, 365)):
        value = data.get(field, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"Invalid collector {field}")
        data[field] = value
    endpoints = data["endpoints"]
    if not isinstance(endpoints, dict) or not 1 <= len(endpoints) <= MAX_ENDPOINTS:
        raise ValueError("Configure between 1 and 256 collector endpoints")
    keys = {}
    for endpoint, key_file in endpoints.items():
        if not offhost.ENDPOINT.fullmatch(endpoint):
            raise ValueError("Invalid off-host endpoint name")
        keys[endpoint] = offhost.read_key(offhost.filename(path.parent, key_file))
    if len(set(keys.values())) != len(keys):
        raise ValueError("Each enrolled endpoint requires a different credential")
    certificate = offhost.filename(path.parent, data["certificate"])
    private_key = offhost.filename(path.parent, data["private_key"])
    with private_file(private_key):
        pass
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(certificate, private_key, password=lambda: b"")
    email = notifications.configuration(data.get("email_alerts"), path.parent)
    if email:
        email["details_hint"] = "Run off-host status on the AI Watchdog collector for details."
    return listen, data["port"], keys, tls, data["silence_seconds"], data["retention_days"], email


def initialize(database, names, email, now):
    store.initialize(database)
    with store.connect(database) as db:
        db.executescript(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        db.executemany("INSERT OR IGNORE INTO endpoints(name,enrolled_at) VALUES (?,?)",
                       ((endpoint, now) for endpoint in names))
        db.executemany("DELETE FROM endpoints WHERE name=?",
                       ((row["name"],) for row in db.execute("SELECT name FROM endpoints").fetchall()
                        if row["name"] not in names))
        notifications.prepare(db, email)


def receive(database, endpoint, packet, now):
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        state = db.execute("SELECT last_sent,silent_at FROM endpoints WHERE name=?", (endpoint,)).fetchone()
        if state is None or (state["last_sent"] is not None and packet["sent_at"] <= state["last_sent"]):
            return False
        db.executemany(
            "INSERT OR IGNORE INTO received_events "
            "(endpoint,event_id,at,received_at,severity,kind,title,detail,subject) VALUES (?,?,?,?,?,?,?,?,?)",
            ((endpoint, row["id"], row["at"], now, row["severity"], row["kind"], row["title"], row["detail"], row["subject"])
             for row in packet["events"]),
        )
        db.execute("UPDATE endpoints SET last_sent=?,last_report=? WHERE name=?", (packet["sent_at"], now, endpoint))
        recovered = packet["boot_id"] is not None and state["silent_at"] is not None
        if packet["boot_id"] is not None:
            db.execute("UPDATE endpoints SET last_heartbeat=?,boot_id=?,silent_at=NULL WHERE name=?",
                       (now, packet["boot_id"], endpoint))
        if recovered:
            store.event(db, now, "info", "offhost", "Endpoint heartbeat recovered: " + endpoint, subject=endpoint)
    if recovered:
        logging.info("Endpoint heartbeat recovered: %s", endpoint)
    return True


def check_silence(database, now, threshold):
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        silent = [row["name"] for row in db.execute(
            "SELECT name FROM endpoints WHERE silent_at IS NULL AND coalesce(last_heartbeat,enrolled_at) <= ?",
            (now - threshold,),
        )]
        for name in silent:
            db.execute("UPDATE endpoints SET silent_at=? WHERE name=?", (now, name))
            store.event(db, now, "high", "offhost", "Endpoint heartbeat missing: " + name,
                        f"No fresh heartbeat received for at least {threshold} seconds.", name)
    for name in silent:
        logging.warning("Endpoint heartbeat missing: %s", name)


def status(database, limit):
    with store.connect(database) as db:
        db.execute("BEGIN")
        hosts = [dict(row) for row in db.execute(
            "SELECT name,enrolled_at,last_report,last_heartbeat,boot_id,silent_at FROM endpoints ORDER BY name"
        )]
        for host in hosts:
            host["status"] = ("silent" if host["silent_at"] is not None else
                              "waiting" if host["last_heartbeat"] is None else "reporting")
        return {
            "endpoints": hosts,
            "events": [dict(row) for row in db.execute(
                "SELECT * FROM received_events ORDER BY received_at DESC,rowid DESC LIMIT ?", (limit,),
            )],
            "alerts": [dict(row) for row in db.execute(
                "SELECT * FROM events WHERE kind='offhost' ORDER BY id DESC LIMIT ?", (limit,),
            )],
            "pending_alert_emails": db.execute("SELECT count(*) FROM email_outbox").fetchone()[0],
        }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Request data and credentials do not belong in the service journal.

    def reply(self, code):
        self.send_response_only(code)
        if code != 204:
            self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        endpoint = self.path.removeprefix(offhost.ROUTE)
        if not self.path.startswith(offhost.ROUTE) or not offhost.ENDPOINT.fullmatch(endpoint):
            self.reply(404)
            return
        key = self.server.keys.get(endpoint)
        authorization = self.headers.get_all("Authorization", [])
        authorized = (key is not None and len(authorization) == 1 and authorization[0].isascii()
                      and hmac.compare_digest(authorization[0], "Bearer " + key))
        length = self.headers.get_all("Content-Length", [])
        if (len(length) != 1 or not re.fullmatch(r"[0-9]{1,7}", length[0])
                or not 0 < int(length[0]) <= offhost.MAX_BODY or self.headers.get("Transfer-Encoding") is not None):
            self.reply(400)
            return
        if self.headers.get_content_type() != "application/json":
            self.reply(415)
            return
        deadline = time.monotonic() + offhost.REQUEST_TIMEOUT
        remaining = int(length[0])
        body = bytearray()
        while remaining:
            chunk = self.rfile.read1(remaining)
            if not chunk or time.monotonic() > deadline:
                self.reply(408)
                return
            if authorized:
                body.extend(chunk)
            remaining -= len(chunk)
        if not authorized:
            self.reply(403)
            return
        now = time.time()
        try:
            packet = offhost.validate_payload(body, now)
        except (ValueError, RecursionError):
            self.reply(400)
            return
        try:
            accepted = receive(self.server.database, endpoint, packet, now)
        except sqlite3.Error:
            logging.exception("Unable to store an off-host report")
            self.reply(503)
            return
        self.reply(204 if accepted else 409)


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, listen, port, database, keys, tls, threshold, retention_days):
        self.address_family = socket.AF_INET6 if listen.version == 6 else socket.AF_INET
        self.database, self.keys, self.tls = database, keys, tls
        self.threshold, self.retention_days = threshold, retention_days
        self.next_check = self.next_cleanup = 0
        self.slots = threading.BoundedSemaphore(16)
        super().__init__((str(listen), port), Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            request.settimeout(offhost.REQUEST_TIMEOUT)
            with self.tls.wrap_socket(request, server_side=True) as secured:
                self.finish_request(secured, address)
        except OSError:
            pass
        finally:
            request.close()
            self.slots.release()

    def service_actions(self):
        monotonic = time.monotonic()
        if monotonic < self.next_check:
            return
        self.next_check = monotonic + CHECK_SECONDS
        now = time.time()
        try:
            check_silence(self.database, now, self.threshold)
            if monotonic >= self.next_cleanup:
                with store.connect(self.database) as db:
                    cutoff = now - self.retention_days * 86400
                    db.execute("DELETE FROM received_events WHERE received_at < ?", (cutoff,))
                    store.expire(db, now, self.retention_days)
                self.next_cleanup = monotonic + 3600
        except sqlite3.Error:
            logging.exception("Off-host collector maintenance failed")


def email_worker(stop, database, settings):
    while not stop.wait(CHECK_SECONDS):
        try:
            notifications.deliver(database, settings, time.time())
        except sqlite3.Error:
            logging.exception("Collector email queue unavailable")


def serve(directory, config):
    listen, port, keys, tls, threshold, retention, email = configuration(config)
    with offhost.exclusive(directory, "collector.lock"):
        database = directory / STATE_NAME
        with Server(listen, port, database, keys, tls, threshold, retention) as server:
            initialize(database, keys, email, time.time())
            stop = threading.Event()
            if email:
                threading.Thread(target=email_worker, args=(stop, database, email), daemon=True).start()
            try:
                logging.info("Off-host collector ready for %d endpoints", len(keys))
                server.serve_forever()
            finally:
                stop.set()
