"""Send high-severity endpoint evidence to a TLS-verified collector."""

import fcntl
import http.client
import json
import math
import os
import re
import ssl
import time
from contextlib import contextmanager
from urllib.parse import urlsplit

from . import responder, store
from .backup_job import private_file
from .common import BOOT_ID, uptime

VERSION = 1
ENDPOINT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
EVENT_ID = re.compile(r"[0-9a-f]{32}")
BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
SEVERITIES = {"high", "critical"}
EVENT_FIELDS = {"kind": 100, "title": 256, "detail": 4096, "subject": 512}
BATCH = 32
MAX_BODY = 1024 * 1024
REQUEST_TIMEOUT = 8
ROUTE = "/v1/endpoints/"
TICKS = 1_000_000_000


@contextmanager
def exclusive(directory, name):
    fd = os.open(directory / name, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("An off-host process already uses this state") from None
        yield


def read_settings(path, required, optional=()):
    with private_file(path) as stream:
        raw = stream.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("Off-host configuration exceeds the size limit")
    data = json.loads(raw)
    if not isinstance(data, dict) or not required <= data.keys() or data.keys() - required - set(optional):
        raise ValueError("Invalid off-host configuration fields")
    return data


def filename(directory, value):
    if not isinstance(value, str) or not value or len(value) > 1024 or "\x00" in value:
        raise ValueError("Invalid off-host configuration filename")
    return directory / value


def read_key(path):
    with private_file(path) as stream:
        data = stream.read(129).strip()
    if not re.fullmatch(rb"[a-fA-F0-9]{64}", data):
        raise ValueError("Off-host credentials must contain 32 random bytes encoded as 64 hexadecimal characters")
    return data.decode("ascii").lower()


def sender_settings(path):
    data = read_settings(path, {"endpoint", "url", "key_file"}, {"ca_file"})
    endpoint, url = data["endpoint"], data["url"]
    if not isinstance(endpoint, str) or not ENDPOINT.fullmatch(endpoint):
        raise ValueError("Invalid off-host endpoint name")
    if not isinstance(url, str) or not url or len(url) > 512 or not url.isprintable() or any(c.isspace() for c in url):
        raise ValueError("Invalid off-host collector URL")
    parsed = urlsplit(url)
    port = 443 if parsed.port is None else parsed.port
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or not 1 <= port <= 65535):
        raise ValueError("Use an HTTPS collector origin without credentials or a path")
    key = read_key(filename(path.parent, data["key_file"]))
    ca = filename(path.parent, data["ca_file"]) if "ca_file" in data else None
    return endpoint, parsed.hostname, port, key, ca


def valid_text(value, limit):
    if not isinstance(value, str) or len(value) > limit:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def validate_payload(raw, now):
    packet = json.loads(raw.decode("utf-8"))
    if (not isinstance(packet, dict) or packet.keys() != {"version", "sent_at", "boot_id", "events"}
            or type(packet["version"]) is not int or packet["version"] != VERSION):
        raise ValueError("Invalid off-host report")
    sent, boot, events = packet["sent_at"], packet["boot_id"], packet["events"]
    if (type(sent) is not int or not int((now - 120) * TICKS) <= sent <= int((now + 30) * TICKS)
            or (boot is not None and (not isinstance(boot, str) or not BOOT.fullmatch(boot)))
            or not isinstance(events, list) or len(events) > BATCH or (boot is None and not events)):
        raise ValueError("Invalid or expired off-host report")
    seen = set()
    for event in events:
        if not isinstance(event, dict) or event.keys() != {"id", "at", "severity", *EVENT_FIELDS}:
            raise ValueError("Invalid off-host event")
        identity, at = event["id"], event["at"]
        if (not isinstance(identity, str) or not EVENT_ID.fullmatch(identity) or identity in seen
                or type(at) not in (int, float) or not 0 <= at <= 253402300799 or not math.isfinite(at)
                or not isinstance(event["severity"], str) or event["severity"] not in SEVERITIES
                or any(not valid_text(event[key], limit) for key, limit in EVENT_FIELDS.items())):
            raise ValueError("Invalid off-host event")
        seen.add(identity)
    return packet


def pending(db, destination):
    db.execute("BEGIN IMMEDIATE")
    if store.property_get(db, "offhost_destination") != destination:
        db.execute("UPDATE offhost_delivery SET delivered=0")
        store.property_set(db, "offhost_destination", destination)
    db.execute(
        "INSERT INTO offhost_delivery(event_id) SELECT id FROM events "
        "WHERE severity IN ('high','critical') AND NOT EXISTS "
        "(SELECT 1 FROM offhost_delivery WHERE event_id=events.id) ORDER BY id LIMIT ?", (BATCH,),
    )
    return [dict(row) for row in db.execute(
        "SELECT d.export_id AS id,e.at,e.severity,e.kind,e.title,e.detail,e.subject "
        "FROM offhost_delivery d JOIN events e ON e.id=d.event_id "
        "WHERE d.delivered=0 ORDER BY d.event_id LIMIT ?", (BATCH,),
    )]


def transmit(host, port, endpoint, key, ca, packet):
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    body = json.dumps(packet, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    connection = http.client.HTTPSConnection(host, port, timeout=REQUEST_TIMEOUT, context=context)
    try:
        connection.request("POST", ROUTE + endpoint, body,
                           {"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        if connection.getresponse().status != 204:
            raise ValueError("Off-host collector did not accept the report")
    except http.client.HTTPException:
        raise ValueError("Invalid response from off-host collector") from None
    finally:
        connection.close()


def send(directory, runtime, settings, config):
    endpoint, host, port, key, ca = sender_settings(config)
    database = directory / "monitor.sqlite3"
    if not database.is_file():
        raise ValueError("Endpoint monitor database is missing")
    with exclusive(directory, "offhost-send.lock"):
        store.initialize(database)
        with store.connect(database) as db:
            events = pending(db, [host, port, endpoint])
        try:
            responder.heartbeat(os.geteuid(), uptime(), settings, runtime=runtime)
            boot = BOOT_ID
        except (OSError, ValueError, RecursionError):
            boot = None
        if boot is None and not events:
            return {"heartbeat": False, "events": 0}
        for event in events:
            for field, limit in EVENT_FIELDS.items():
                event[field] = event[field][:limit].encode("utf-8", "replace").decode("utf-8")
        packet = {"version": VERSION, "sent_at": time.time_ns(), "boot_id": boot, "events": events}
        transmit(host, port, endpoint, key, ca, packet)
        with store.connect(database) as db:
            db.executemany("UPDATE offhost_delivery SET delivered=1 WHERE export_id=?",
                           ((event["id"],) for event in events))
        return {"heartbeat": boot is not None, "events": len(events)}
