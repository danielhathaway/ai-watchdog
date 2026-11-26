"""Operator review of antivirus findings and their follow-up scan evidence."""
import json

from . import store


class ReviewConflict(Exception):
    pass


def is_malware(event):
    return (event["kind"], event["subject"], event["severity"], event["title"]) == (
        "system-check", "antivirus/clamav", "high", "ClamAV detected malware",
    )


def record_scope(db, event_id, paths):
    db.execute("INSERT INTO finding_reviews(event_id, paths) VALUES (?, ?)", (event_id, json.dumps(paths)))


def clean_evidence(event, review, report):
    if not review or review["paths"] is None or not report:
        return None
    if report.get("paths") != json.loads(review["paths"]) or report.get("at", 0) <= event["at"]:
        return None
    for row in report["checks"]:
        if row["id"] == "clamav" and row["status"] == "pass" and (row.get("files_scanned") or 0) > 0:
            return row["detail"]
    return None


def annotate(db, events, report):
    findings = [event for event in events if is_malware(event)]
    if not findings:
        return
    placeholders = ",".join("?" for event in findings)
    records = {row["event_id"]: row for row in db.execute(
        f"SELECT * FROM finding_reviews WHERE event_id IN ({placeholders})", [event["id"] for event in findings],
    )}
    for event in findings:
        row = records.get(event["id"])
        event["review"] = {
            **{key: row[key] if row else None for key in ("acknowledged_at", "resolved_at", "evidence_at", "evidence_detail")},
            "scope_recorded": bool(row and row["paths"] is not None),
            "can_resolve": bool(row and row["acknowledged_at"] and not row["resolved_at"]
                                and clean_evidence(event, row, report)),
        }


def update(db, event_id, at, action, report):
    event = db.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not event or not is_malware(event):
        return None
    row = db.execute("SELECT * FROM finding_reviews WHERE event_id = ?", (event_id,)).fetchone()
    if action == "acknowledge":
        db.execute(
            "INSERT INTO finding_reviews(event_id, acknowledged_at) VALUES (?, ?) "
            "ON CONFLICT(event_id) DO UPDATE SET acknowledged_at=coalesce(acknowledged_at,excluded.acknowledged_at)",
            (event_id, at),
        )
    elif not row or not row["resolved_at"]:
        detail = clean_evidence(event, row, report)
        if not row or not row["acknowledged_at"] or not detail:
            raise ReviewConflict("Acknowledge the finding and complete a clean rescan of the same paths first.")
        db.execute(
            "UPDATE finding_reviews SET resolved_at=?, evidence_at=?, evidence_detail=? WHERE event_id=?",
            (at, report["at"], detail, event_id),
        )
    event = dict(event)
    annotate(db, [event], report)
    return event["review"]
