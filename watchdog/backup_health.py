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


def receipt(job):
    try:
        with backups.open_regular(STATE / f"{job}.json") as stream:
            info = os.fstat(stream.fileno())
            if info.st_uid != 0 or info.st_mode & 0o022:
                return {}
            data = json.loads(stream.read(1025))
        if isinstance(data, dict):
            return {key: data[key] for key in ("success_at", "failure_at") if key in data
                    and type(data[key]) in (int, float) and 0 < data[key] < math.inf}
    except (OSError, ValueError, RecursionError):
        pass
    return {}


def record(job, now, environment):
    if os.geteuid() != 0 or job not in JOBS:
        raise ValueError("Scheduled backup results must come from a system service")
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Unsafe scheduled backup result directory")
    success = (environment.get("SERVICE_RESULT"), environment.get("EXIT_CODE"),
               environment.get("EXIT_STATUS")) == ("success", "exited", "0")
    result = receipt(job)
    result["success_at" if success else "failure_at"] = now
    write_json(STATE / f"{job}.json", result, mode=0o644)


def refresh(database, now, max_hours):
    observations = {}
    for job, config in JOBS.items():
        try:
            info = (CONFIG / config).stat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            observations[job] = (min(now, info.st_mtime), {key: at for key, at in receipt(job).items() if at <= now})

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
                deadline = max(since, success) + max_hours * 3600
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
                new_failure = failure > prior.get("failure_at", 0)
                open_failure = prior.get("status") == "failed"
                if new_failure and not open_failure:
                    store.event(db, now, "medium", "backup", "Scheduled restore drill failed",
                                "The scheduled job did not complete its authenticated restore check. See its service journal.", "drill")
                if (new_failure or open_failure) and success > failure and success > prior.get("success_at", 0):
                    store.event(db, now, "info", "backup", "Scheduled restore drill recovered",
                                "The isolated restore passed its authenticated dashboard check.", "drill")
            updated[job] = row
        if updated != previous:
            store.property_set(db, "backup_health", updated)
