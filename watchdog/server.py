import hmac
import http.client
import json
import logging
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from . import analysis, notifications, schedule, store

STATIC = Path(__file__).with_name("static")
ASSETS = {
    "/": ("index.html", "text/html"), "/app.css": ("app.css", "text/css"),
    "/app.js": ("app.js", "text/javascript"),
}


class Console(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    slots = threading.BoundedSemaphore(24)

    def __init__(self, monitor, token):
        self.monitor = monitor
        self.token = token
        self.assessment_lock = threading.Lock()
        self.assessment_at = 0
        self.assessing = False
        super().__init__(("127.0.0.1", monitor.settings["port"]), Handler)
        self.authority = f"127.0.0.1:{self.server_port}"
        self.origin = "http://" + self.authority

    def get_request(self):
        socket, address = super().get_request()
        socket.settimeout(3)
        return socket, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def start_workers(self):
        email = None if self.monitor.demo else self.monitor.settings.get("email_alerts")
        with store.connect(self.monitor.database) as db:
            db.execute("BEGIN IMMEDIATE")
            notifications.prepare(db, email)
        self.monitor.start()
        threading.Thread(target=self.run_scheduler, name="check-scheduler", daemon=True).start()
        if email:
            threading.Thread(target=self.run_email_delivery, args=(email,), name="alert-email", daemon=True).start()

    def run_scheduler(self):
        while not self.monitor.stop.wait(2):
            if not self.monitor.ready.is_set():
                continue
            try:
                with store.connect(self.monitor.database) as db:
                    occurrence = schedule.read(db)
                if occurrence["next_at"] is not None and occurrence["next_at"] <= time.time():
                    self.assess(occurrence)
            except Exception:
                logging.exception("Checking the recurring assessment schedule failed")

    def run_email_delivery(self, email):
        while not self.monitor.stop.wait(10):
            try:
                notifications.deliver(self.monitor.database, email, time.time())
            except Exception:
                logging.error("Email alert worker failed")

    def assess(self, occurrence=None):
        with self.assessment_lock:
            if self.assessing or (self.assessment_at and time.monotonic() - self.assessment_at < 15):
                return False
            self.assessing = True
            self.assessment_at = time.monotonic()
        threading.Thread(target=self.run_assessment, args=(occurrence,), daemon=True, name="active-check").start()
        return True

    def run_assessment(self, occurrence=None):
        now = time.time()
        model = self.monitor.settings["ollama_model"]
        trigger = "scheduled" if occurrence else "manual"
        event_label = "Scheduled" if occurrence else "Active"
        try:
            with self.monitor.lock:
                result = self.monitor.scan(active=True)
            with store.connect(self.monitor.database) as db:
                result["recent_findings"] = {
                    row[0]: row[1] for row in db.execute(
                        "SELECT kind,count(*) FROM events WHERE at>=? GROUP BY kind", (now - 3600,)
                    )
                }
            result["model"] = "Statistical baseline"
            result["summary"] = (
                f'{len(result["deviations"])} baseline deviations and '
                f'{result["block_candidates"]} temporary block candidates in the latest check.'
            )
            if model and not self.monitor.demo:
                try:
                    result["summary"] = analysis.local_review(model, result)
                    result["model"] = "Local model + statistical baseline"
                except (OSError, ValueError, KeyError, TypeError, AttributeError, http.client.HTTPException):
                    result["model"] = "Statistical baseline · local model unavailable"
            result.update(at=time.time(), trigger=trigger)
            with store.connect(self.monitor.database) as db:
                db.execute("BEGIN IMMEDIATE")
                store.property_set(db, "assessment", result)
                store.event(db, result["at"], "info", "assessment", f"{event_label} AI check completed", result["summary"])
                schedule.advance(db, occurrence, result["at"])
        except Exception as error:
            logging.exception("Active check failed")
            with store.connect(self.monitor.database) as db:
                db.execute("BEGIN IMMEDIATE")
                failed_at = time.time()
                store.property_set(db, "assessment", {
                    "at": failed_at, "trigger": trigger, "error": type(error).__name__,
                    "summary": f"{event_label} check failed.",
                })
                store.event(db, failed_at, "medium", "assessment", f"{event_label} AI check failed", type(error).__name__)
                schedule.advance(db, occurrence, failed_at)
        finally:
            with self.assessment_lock:
                self.assessing = False


class Handler(BaseHTTPRequestHandler):
    server_version = "AIWatchdog"
    sys_version = ""

    def log_message(self, *_):
        pass

    def reply(self, status, data, mime="application/json"):
        raw = json.dumps(data).encode() if mime == "application/json" else data
        self.send_response(status)
        self.send_header("Content-Type", mime + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self, mutation=False):
        if self.headers.get_all("Host") != [self.server.authority]:
            self.reply(421, {"error": "Invalid host"})
            return False
        if mutation and self.headers.get_all("Origin") != [self.server.origin]:
            self.reply(403, {"error": "Invalid origin"})
            return False
        if self.path.startswith("/api/") and self.server.token:
            header = self.headers.get("Authorization", "").encode("utf-8")
            if not hmac.compare_digest(header, f"Bearer {self.server.token}".encode()):
                self.reply(401, {"error": "Access token required"})
                return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        if self.path in ASSETS:
            filename, mime = ASSETS[self.path]
            self.reply(200, (STATIC / filename).read_bytes(), mime)
        elif self.path == "/health":
            ready = self.server.monitor.ready.is_set()
            self.reply(200 if ready else 503, b"ok\n" if ready else b"starting\n", "text/plain")
        elif self.path == "/api/status":
            now = time.time()
            monitor = self.server.monitor
            with store.connect(monitor.database) as db:
                db.execute("BEGIN")
                data = store.snapshot(db, now)
                data["schedule"] = schedule.read(db)
                data["email"] = notifications.status(db)
            data.update({
                "now": now, "ready": monitor.ready.is_set(), "response": monitor.response(),
                "assessing": self.server.assessing, "interval": monitor.settings["interval"],
            })
            self.reply(200, data)
        else:
            self.reply(404, {"error": "Not found"})

    def do_POST(self):
        if not self.authorized(mutation=True):
            return
        if self.path != "/api/check":
            self.reply(404, {"error": "Not found"})
        elif self.headers.get("Content-Length", "0") != "0" or self.headers.get("Transfer-Encoding"):
            self.reply(400, {"error": "Unexpected body"})
        elif not self.server.monitor.ready.is_set():
            self.reply(503, {"error": "Monitoring is starting"})
        elif self.server.assess():
            self.reply(202, {"status": "running"})
        else:
            self.reply(429, {"error": "A check is running or was started recently"})

    def do_PUT(self):
        if not self.authorized(mutation=True):
            return
        if self.path != "/api/schedule":
            self.reply(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 128 or self.headers.get("Transfer-Encoding"):
                raise ValueError
            if self.headers.get_content_type() != "application/json":
                raise ValueError
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or set(payload) != {"interval_minutes"}:
                raise ValueError
        except (ValueError, OSError, RecursionError):
            self.reply(400, {"error": "Expected a schedule with an interval in minutes."})
            return
        try:
            with store.connect(self.server.monitor.database) as db:
                db.execute("BEGIN IMMEDIATE")
                saved = schedule.save(db, payload["interval_minutes"], time.time())
        except ValueError as error:
            self.reply(400, {"error": str(error)})
        else:
            self.reply(200, saved)
