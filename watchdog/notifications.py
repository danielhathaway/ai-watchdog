import os
import re
import smtplib
import ssl
import stat
from contextlib import suppress
from datetime import datetime, timezone
from email.message import EmailMessage

from . import store

ADDRESS = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]+")
HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
MESSAGE_LIMIT = 25
MIN_DELAY = 60
MAX_DELAY = 900
MESSAGE_TTL = 86400


def configuration(value, directory):
    if value is None:
        return None
    fields = {
        "host": "", "port": 587, "security": "starttls", "sender": "", "recipient": "",
        "minimum_severity": "high", "username": "", "password_file": "",
        "coverage_notify_minutes": 0,
    }
    if not isinstance(value, dict) or set(value) - set(fields):
        raise ValueError("Invalid email_alerts configuration")
    fields.update(value)
    for key in fields.keys() - {"port", "coverage_notify_minutes"}:
        if not isinstance(fields[key], str) or len(fields[key]) > 512 or (fields[key] and not fields[key].isprintable()):
            raise ValueError(f"Invalid email_alerts {key}")
    if not HOST.fullmatch(fields["host"]) or ".." in fields["host"]:
        raise ValueError("email_alerts requires an SMTP hostname or IPv4 address")
    if type(fields["port"]) is not int or not 1 <= fields["port"] <= 65535:
        raise ValueError("Invalid SMTP port")
    if type(fields["coverage_notify_minutes"]) is not int or not 0 <= fields["coverage_notify_minutes"] <= 10080:
        raise ValueError("coverage_notify_minutes must be between 0 and 10080")
    if fields["security"] not in ("starttls", "tls"):
        raise ValueError("SMTP requires starttls or tls")
    for key in ("sender", "recipient"):
        if not ADDRESS.fullmatch(fields[key]) or len(fields[key]) > 254 or ".." in fields[key]:
            raise ValueError(f"Invalid email_alerts {key} address")
    if fields["minimum_severity"] not in ("high", "critical"):
        raise ValueError("Invalid email_alerts minimum severity")
    if bool(fields["username"]) != bool(fields["password_file"]):
        raise ValueError("Set both SMTP username and password_file for authenticated SMTP")
    if fields["password_file"]:
        fields["password_file"] = directory / fields["password_file"]
    return fields


def read_password(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o037
                or info.st_uid not in (0, os.geteuid()) or not 0 < info.st_size <= 4096):
            raise ValueError("SMTP password file must be private and contain one password")
        password = file.read(4097).decode().rstrip("\r\n")
    if not password or len(password) > 4096 or "\r" in password or "\n" in password:
        raise ValueError("Invalid SMTP password file")
    return password


def send(settings, events):
    message = EmailMessage()
    message["From"] = settings["sender"]
    message["To"] = settings["recipient"]
    critical = any(event["severity"] == "critical" for event in events)
    level = ("Critical severity" if critical else "High severity" if any(event["severity"] == "high" for event in events)
             else "Antivirus coverage warning")
    message["Subject"] = f"AI Watchdog · {level} ({len(events)})"
    lines = [
        f'{datetime.fromtimestamp(event["at"], timezone.utc):%Y-%m-%d %H:%M UTC}'
        f'  {event["severity"].upper()}  {event["title"]}'
        for event in events
    ]
    message.set_content("\n".join(lines) + "\n\nOpen the local AI Watchdog dashboard for details.\n")

    password = read_password(settings["password_file"]) if settings["username"] else None
    context = ssl.create_default_context()
    host, port = settings["host"], settings["port"]
    if settings["security"] == "tls":
        smtp = smtplib.SMTP_SSL(host, port, timeout=10, context=context)
    else:
        smtp = smtplib.SMTP(host, port, timeout=10)
    try:
        if settings["security"] == "starttls":
            smtp.starttls(context=context)
        if settings["username"]:
            smtp.login(settings["username"], password)
        smtp.send_message(message, from_addr=settings["sender"], to_addrs=[settings["recipient"]])
    finally:
        # A connection closing after DATA acceptance does not warrant resending.
        with suppress(OSError):
            smtp.close()


def prepare(db, settings):
    destination = {key: settings[key] for key in ("recipient", "sender", "host", "port", "minimum_severity")} if settings else None
    if destination is not None and settings.get("coverage_notify_minutes"):
        destination["coverage_notify_minutes"] = settings["coverage_notify_minutes"]
    if store.property_get(db, "email_destination") != destination:
        db.execute("DELETE FROM email_outbox")
        store.property_set(db, "email_delivery", {})
        store.property_set(db, "coverage_email_delivery", {})
        store.property_set(db, "email_destination", destination)


def status(db):
    destination = store.property_get(db, "email_destination")
    delivery = store.property_get(db, "email_delivery", {})
    count = db.execute("SELECT count(*) FROM email_outbox").fetchone()[0]
    coverage = store.property_get(db, "coverage_email_delivery", {})
    coverage_pending = db.execute("SELECT count(*) FROM coverage_email").fetchone()[0]
    return {
        "enabled": destination is not None,
        "minimum_severity": destination["minimum_severity"] if destination else None,
        "coverage_notify_minutes": destination.get("coverage_notify_minutes", 0) if destination else 0,
        "pending": count,
        "last_sent_at": delivery.get("last_sent_at"),
        "retry_at": delivery.get("next_at") if delivery.get("failures") and count else None,
        "coverage": {
            "pending": coverage_pending,
            "retry_at": delivery.get("next_at") if delivery.get("failures") and coverage_pending else None,
            "last_accepted_at": coverage.get("last_accepted_at"),
            "last_expired_at": coverage.get("last_expired_at"),
        },
    }


def queue_coverage(database, settings, paths, now):
    delay = settings.get("coverage_notify_minutes", 0)
    if not delay:
        return
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        incidents = store.property_get(db, "antivirus_coverage_incidents", {})
        saved = store.property_get(db, "antivirus_coverage_notifications", {})
        pending = {}
        for queued in db.execute("SELECT path,outbox_id FROM coverage_email").fetchall():
            if queued["path"] not in (paths or []) or incidents.get(queued["path"], 0) < 3:
                db.execute("DELETE FROM email_outbox WHERE id=?", (queued["outbox_id"],))
        for path in paths or []:
            if incidents.get(path, 0) < 3:
                continue
            incident = saved.get(path)
            reported = db.execute(
                "SELECT max(at) FROM events WHERE kind='antivirus-coverage' AND subject=? AND severity='medium'",
                (path,),
            ).fetchone()[0]
            if incident is None or (reported is not None and reported > incident["degraded_at"]):
                incident = {"degraded_at": reported if reported is not None else now, "notified": False}
            pending[path] = incident
            if incident["notified"] or now - incident["degraded_at"] < delay * 60:
                continue
            inserted = db.execute(
                "INSERT INTO email_outbox(at,severity,title) VALUES (?, 'medium', ?)",
                (now, "Antivirus path coverage remains degraded"),
            )
            old = db.execute("SELECT outbox_id FROM coverage_email WHERE path=?", (path,)).fetchone()
            if old:
                db.execute("DELETE FROM email_outbox WHERE id=?", (old[0],))
            db.execute("INSERT INTO coverage_email VALUES (?, ?)", (path, inserted.lastrowid))
            pending[path] = {**incident, "notified": True}
        if pending != saved:
            store.property_set(db, "antivirus_coverage_notifications", pending)


def deliver(database, settings, now):
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        expired = db.execute(
            "SELECT 1 FROM coverage_email JOIN email_outbox ON outbox_id=id WHERE at < ? LIMIT 1",
            (now - MESSAGE_TTL,),
        ).fetchone()
        db.execute("DELETE FROM email_outbox WHERE at < ?", (now - MESSAGE_TTL,))
        if expired:
            coverage = store.property_get(db, "coverage_email_delivery", {})
            store.property_set(db, "coverage_email_delivery", {**coverage, "last_expired_at": now})
        delivery = store.property_get(db, "email_delivery", {})
        if now < delivery.get("next_at", 0):
            return
        events = db.execute(
            "SELECT email_outbox.*, coverage_email.outbox_id IS NOT NULL AS coverage FROM email_outbox "
            "LEFT JOIN coverage_email ON outbox_id=id ORDER BY id LIMIT ?", (MESSAGE_LIMIT,),
        ).fetchall()
    if not events:
        return
    try:
        send(settings, events)
    except (OSError, ValueError):
        # SMTP exceptions inherit OSError. Remote replies can echo credentials or addresses.
        failures = min(delivery.get("failures", 0) + 1, 5)
        delay = min(MAX_DELAY, MIN_DELAY * 2 ** (failures - 1))
        with store.connect(database) as db:
            store.property_set(db, "email_delivery", {**delivery, "failures": failures, "next_at": now + delay})
            store.event(db, now, "medium", "email", "Email delivery deferred",
                        "Check SMTP connectivity, TLS settings, and credentials.", cooldown=900)
    else:
        with store.connect(database) as db:
            db.execute("DELETE FROM email_outbox WHERE id <= ?", (events[-1]["id"],))
            store.property_set(db, "email_delivery", {"last_sent_at": now, "next_at": now + MIN_DELAY})
            if any(event["coverage"] for event in events):
                coverage = store.property_get(db, "coverage_email_delivery", {})
                store.property_set(db, "coverage_email_delivery", {**coverage, "last_accepted_at": now})
            store.event(db, now, "info", "email", "Alert email accepted by SMTP", f"{len(events)} alerts")
