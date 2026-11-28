import json
import sqlite3
from contextlib import closing, contextmanager

from .common import BOOT_ID

SSH_ACTIVITY_STATE = "ssh_activity"
SSH_ACTIVITY_SENSOR = "SSH activity correlation"

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY, at REAL NOT NULL, rx REAL, tx REAL, connections INTEGER,
    failures INTEGER, risk INTEGER NOT NULL, training INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sample_time ON samples(at);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, at REAL NOT NULL, severity TEXT NOT NULL,
    kind TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, subject TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_topic ON events(kind, subject, at);
CREATE INDEX IF NOT EXISTS event_time ON events(at);
CREATE INDEX IF NOT EXISTS offhost_events ON events(id) WHERE severity IN ('high','critical');
CREATE TABLE IF NOT EXISTS offhost_delivery (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    export_id TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))),
    delivered INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS offhost_export_id ON offhost_delivery(export_id);
CREATE INDEX IF NOT EXISTS offhost_pending ON offhost_delivery(event_id) WHERE delivered=0;
CREATE TABLE IF NOT EXISTS finding_reviews (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    paths TEXT, acknowledged_at REAL, resolved_at REAL, evidence_at REAL, evidence_detail TEXT
);
CREATE TABLE IF NOT EXISTS traffic_attribution (
    event_id INTEGER PRIMARY KEY, at REAL NOT NULL, snapshot TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS traffic_attribution_time ON traffic_attribution(at);
CREATE TABLE IF NOT EXISTS interface_spikes (
    id INTEGER PRIMARY KEY, at REAL NOT NULL, snapshot TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS interface_spike_time ON interface_spikes(at);
CREATE TABLE IF NOT EXISTS listener_inventory (
    at REAL PRIMARY KEY, listeners TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS antivirus_path_history (
    id INTEGER PRIMARY KEY, at REAL NOT NULL, path TEXT NOT NULL, result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS antivirus_history_time ON antivirus_path_history(at);
CREATE INDEX IF NOT EXISTS antivirus_history_path ON antivirus_path_history(path, id);
CREATE TABLE IF NOT EXISTS devices (
    identity TEXT PRIMARY KEY, mac TEXT, address TEXT NOT NULL, interface TEXT NOT NULL,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL, observations INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS properties (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS failures (cursor TEXT PRIMARY KEY, address TEXT NOT NULL, at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS failure_time ON failures(at);
CREATE TABLE IF NOT EXISTS email_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS email_outbox_time ON email_outbox(at);
CREATE TABLE IF NOT EXISTS coverage_email (
    path TEXT PRIMARY KEY, outbox_id INTEGER NOT NULL REFERENCES email_outbox(id) ON DELETE CASCADE
);
"""


@contextmanager
def connect(path):
    with closing(sqlite3.connect(path, timeout=3)) as database:
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA foreign_keys=ON")
        with database:
            yield database


def initialize(path):
    with connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript(SCHEMA)


def property_get(db, key, default=None):
    row = db.execute("SELECT value FROM properties WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


def property_set(db, key, value):
    db.execute("INSERT OR REPLACE INTO properties VALUES (?, ?)", (key, json.dumps(value)))


def sensor_status(db):
    sensors = property_get(db, "sensors", {})
    row = db.execute("SELECT json_extract(value, '$.boot_id'), json_extract(value, '$.status') "
                     "FROM properties WHERE key=?", (SSH_ACTIVITY_STATE,)).fetchone()
    if row and row[0] == BOOT_ID:
        sensors[SSH_ACTIVITY_SENSOR] = row[1]
    return sensors


def event(db, at, severity, kind, title, detail="", subject="", cooldown=0):
    if cooldown and db.execute(
        "SELECT 1 FROM events WHERE kind=? AND subject=? AND at>=? LIMIT 1",
        (kind, subject, at - cooldown),
    ).fetchone():
        return
    inserted = db.execute(
        "INSERT INTO events(at,severity,kind,title,detail,subject) VALUES (?,?,?,?,?,?)",
        (at, severity, kind, title, detail, subject),
    )


    if severity in ("critical", "high"):
        destination = property_get(db, "email_destination")
        if destination and (severity == "critical" or destination["minimum_severity"] == "high"):
            db.execute("INSERT INTO email_outbox(at,severity,title) VALUES (?,?,?)", (at, severity, title))

    return inserted.lastrowid


def expire(db, now, days):
    cutoff = now - days * 86400
    db.execute("DELETE FROM samples WHERE at < ?", (cutoff,))
    db.execute("DELETE FROM events WHERE at < ?", (cutoff,))
    db.execute("DELETE FROM traffic_attribution WHERE at < ?", (cutoff,))
    db.execute("DELETE FROM interface_spikes WHERE at < ?", (cutoff,))
    db.execute("DELETE FROM listener_inventory WHERE at < ?", (cutoff,))
    db.execute("DELETE FROM antivirus_path_history WHERE at < ?", (cutoff,))
    db.execute("DELETE FROM devices WHERE last_seen < ?", (cutoff,))


def record_antivirus_paths(db, at, coverage):
    db.executemany("INSERT INTO antivirus_path_history(at,path,result) VALUES (?,?,?)",
                   ((at, row["path"], json.dumps(row)) for row in coverage))


def antivirus_history(db, path, before):
    size = 25
    rows = db.execute(
        "SELECT id,at,result FROM antivirus_path_history "
        "WHERE (? IS NULL OR path=?) AND (? IS NULL OR id<?) ORDER BY id DESC LIMIT ?",
        (path, path, before, before, size + 1),
    ).fetchall()
    paths = [row[0] for row in db.execute(
        "SELECT path FROM antivirus_path_history GROUP BY path ORDER BY max(id) DESC LIMIT 128"
    )]
    return {
        "results": [{"id": row["id"], "at": row["at"], **json.loads(row["result"])} for row in rows[:size]],
        "paths": paths,
        "next_before": rows[size - 1]["id"] if len(rows) > size else None,
    }


def snapshot(db, now):
    def rows(sql, parameters=()):
        return [dict(row) for row in db.execute(sql, parameters)]

    baseline = property_get(db, "traffic_baseline", {})
    current_interfaces = property_get(db, "interface_traffic")
    spikes = [
        {"id": row["id"], "at": row["at"], **json.loads(row["snapshot"])}
        for row in db.execute("SELECT id,at,snapshot FROM interface_spikes ORDER BY id DESC LIMIT 20")
    ]
    samples = rows(
        """SELECT at,rx,tx,connections,failures,risk FROM (
           SELECT id,at,rx,tx,connections,failures,risk FROM samples
           WHERE at >= ? ORDER BY id DESC LIMIT 720) ORDER BY id""",
        (now - 3600,),
    )
    for sample in samples:
        if current_interfaces and (not baseline or sample["at"] < baseline["since"]):
            # Preserve the other metrics while keeping old aggregate traffic off the new chart.
            sample["rx"] = sample["tx"] = None
    events = rows(
        "SELECT events.*, traffic_attribution.snapshot AS attribution FROM events "
        "LEFT JOIN traffic_attribution ON event_id = events.id ORDER BY events.id DESC LIMIT 100"
    )
    for item in events:
        if item["attribution"] is not None:
            item["attribution"] = json.loads(item["attribution"])
    return {
        "samples": samples,
        "interface_traffic": current_interfaces,
        "interface_spikes": spikes,
        "events": events,
        "process_traffic": property_get(db, "process_traffic", {"state": "unavailable"}),
        "devices": rows("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 250"),
        "device_count": db.execute("SELECT count(*) FROM devices").fetchone()[0],
        "alert_count": db.execute(
            "SELECT count(*) FROM events WHERE severity IN ('high','critical') AND at>=?",
            (now - 86400,),
        ).fetchone()[0],
        "sensors": sensor_status(db),
        "assessment": property_get(db, "assessment"),
    }
