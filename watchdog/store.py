import json
import sqlite3
from contextlib import closing, contextmanager

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
CREATE TABLE IF NOT EXISTS devices (
    identity TEXT PRIMARY KEY, mac TEXT, address TEXT NOT NULL, interface TEXT NOT NULL,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL, observations INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS properties (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS failures (cursor TEXT PRIMARY KEY, address TEXT NOT NULL, at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS failure_time ON failures(at);
"""


@contextmanager
def connect(path):
    with closing(sqlite3.connect(path, timeout=3)) as database:
        database.row_factory = sqlite3.Row
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


def event(db, at, severity, kind, title, detail="", subject="", cooldown=0):
    if cooldown and db.execute(
        "SELECT 1 FROM events WHERE kind=? AND subject=? AND at>=? LIMIT 1",
        (kind, subject, at - cooldown),
    ).fetchone():
        return
    db.execute(
        "INSERT INTO events(at,severity,kind,title,detail,subject) VALUES (?,?,?,?,?,?)",
        (at, severity, kind, title, detail, subject),
    )


def expire(db, now, days):
    cutoff = now - days * 86400
    db.execute("DELETE FROM samples WHERE at < ?", (cutoff,))
    db.execute("DELETE FROM events WHERE at < ?", (cutoff,))
    db.execute("DELETE FROM devices WHERE last_seen < ?", (cutoff,))


def snapshot(db, now):
    def rows(sql, parameters=()):
        return [dict(row) for row in db.execute(sql, parameters)]

    samples = rows(
        """SELECT at,rx,tx,connections,failures,risk FROM (
           SELECT id,at,rx,tx,connections,failures,risk FROM samples
           WHERE at >= ? ORDER BY id DESC LIMIT 720) ORDER BY id""",
        (now - 3600,),
    )
    return {
        "samples": samples,
        "events": rows("SELECT * FROM events ORDER BY id DESC LIMIT 100"),
        "devices": rows("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 250"),
        "device_count": db.execute("SELECT count(*) FROM devices").fetchone()[0],
        "alert_count": db.execute(
            "SELECT count(*) FROM events WHERE severity IN ('high','critical') AND at>=?",
            (now - 86400,),
        ).fetchone()[0],
        "sensors": property_get(db, "sensors", {}),
        "assessment": property_get(db, "assessment"),
    }
