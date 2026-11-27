"""Host-local results from the scheduled backup services."""

import json
import math
import os
from pathlib import Path
import stat

from . import backups, store
from .common import write_json

CONFIG = Path("/etc/ai-watchdog")
STATE = Path("/var/lib/ai-watchdog-backup-health")
JOBS = {"upload": "backup-upload.json", "drill": "backup-drill.json"}
VERIFIER_CONFIG = {"report": "backup-verifier-report.json", "import": "backup-verifier-import.json"}


def timestamp(value):
    return type(value) in (int, float) and 0 < value < math.inf


def read_record(job):
    try:
        with backups.open_regular(STATE / f"{job}.json") as stream:
            info = os.fstat(stream.fileno())
            if info.st_uid != 0 or info.st_mode & 0o022:
                return {}
            data = json.loads(stream.read(4097))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError, RecursionError):
        pass
    return {}


def receipt_times(result):
    return {key: result[key] for key in ("success_at", "failure_at") if timestamp(result.get(key))}


def receipt(job):
    return receipt_times(read_record(job))


def check_directory():
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Unsafe scheduled backup result directory")


def record(job, now, environment):
    if os.geteuid() != 0 or job not in JOBS:
        raise ValueError("Scheduled backup results must come from a system service")
    check_directory()
    success = (environment.get("SERVICE_RESULT"), environment.get("EXIT_CODE"),
               environment.get("EXIT_STATUS")) == ("success", "exited", "0")
    result = receipt(job)
    result["success_at" if success else "failure_at"] = now
    write_json(STATE / f"{job}.json", result, mode=0o644)


def refresh(database, now, upload_hours, drill_hours, verifier_minutes):
    observations = {}
    configs = {**JOBS, "verifier": VERIFIER_CONFIG["import"]}
    for job, config in configs.items():
        try:
            info = (CONFIG / config).stat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            if job == "verifier":
                report = read_record(job)
                times = {key: at for key, at in receipt_times(report).items() if at <= now}
                if timestamp(report.get("sent_at")) and isinstance(report.get("verifier"), str):
                    times.update(reported_at=report["sent_at"], verifier=report["verifier"])
            else:
                times = {key: at for key, at in receipt(job).items() if at <= now}
            observations[job] = (min(now, info.st_mtime), times)

    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        previous = store.property_get(db, "backup_health", {})
        updated = {}
        for job, (configured_at, times) in observations.items():
            prior = previous.get(job, {})
            since = min(prior.get("since", configured_at), configured_at, now)
            success = times.get("success_at", 0)
            failure = times.get("failure_at", 0)
            state = "failed" if failure > success else "healthy" if success else "waiting"
            row = {"since": since, **times, "status": state}
            if job == "upload":
                deadline = max(since, success) + upload_hours * 3600
                row["deadline"] = deadline
                if now >= deadline:
                    row["status"] = "overdue"
                    if prior.get("status") != "overdue":
                        store.event(db, now, "medium", "backup", "Scheduled backup upload missed",
                                    "No verified encrypted upload completed within the configured interval.", "upload")
                elif prior.get("status") == "overdue" and success > prior.get("success_at", 0):
                    store.event(db, now, "info", "backup", "Scheduled backup uploads recovered",
                                "A verified encrypted upload completed.", "upload")
            else:
                if job == "verifier":
                    review_reporting(db, now, row, prior, verifier_minutes)
                if job == "verifier" and prior.get("verifier") and row.get("verifier") != prior["verifier"]:
                    prior = {}
                review_drill(db, now, job, row, prior, success, failure, drill_hours)
            updated[job] = row
        if updated != previous:
            store.property_set(db, "backup_health", updated)


def review_reporting(db, now, row, prior, minutes):
    reported = row.get("reported_at", 0)
    deadline = (reported or row["since"]) + minutes * 60
    row["report_deadline"] = deadline
    was_overdue = prior.get("report_status") == "overdue"
    overdue = now >= deadline or (was_overdue and reported <= prior.get("reported_at", 0))
    row["report_status"] = "overdue" if overdue else "current" if reported else "waiting"
    if overdue and not was_overdue:
        store.event(db, now, "medium", "backup", "Verifier reports overdue",
                    "The primary dashboard has no recent authenticated report. Check the verifier and import service journals.",
                    "verifier-reporting")
    elif was_overdue and not overdue:
        store.event(db, now, "info", "backup", "Verifier reporting resumed",
                    "The primary dashboard received a fresh authenticated report.", "verifier-reporting")


def review_drill(db, now, job, row, prior, success, failure, hours):
    name = "Verifier restore drill" if job == "verifier" else "Scheduled restore drill"
    new_failure = failure > prior.get("failure_at", 0)
    open_failure = prior.get("failure_at", 0) > prior.get("success_at", 0)
    new_success = success > prior.get("success_at", 0)
    if new_failure and not open_failure:
        detail = "The scheduled job did not complete its authenticated restore check. See the verifier's service journal."
        store.event(db, now, "medium", "backup", name + " failed", detail, job)
    if (new_failure or open_failure) and success > failure and new_success:
        store.event(db, now, "info", "backup", name + " recovered",
                    "The isolated restore passed its authenticated dashboard check.", job)
    deadline = (success or row["since"]) + hours * 3600
    row["deadline"] = deadline
    if now >= deadline:
        row["status"] = "overdue"
        if prior.get("status") != "overdue":
            store.event(db, now, "medium", "backup", name + " overdue",
                        "No successful restore drill was recorded within the configured interval.", job)
    elif prior.get("status") == "overdue" and new_success:
        store.event(db, now, "info", "backup", name + " is current again",
                    "A successful restore drill closed the overdue alert.", job)
