"""Inventory and integrity verification for private Watchdog backup directories."""

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from contextlib import closing

from .common import write_json

MANIFEST = "manifest.json"
REQUIRED = {"config.json", "monitor.sqlite3", "token"}
OPTIONAL = {"baseline.json", "watchdog-integrity.json", "watchdog-advisories.json", "vulnerability-rules.json"}
STATE_NAMES = REQUIRED | OPTIONAL
FILE_NAME = re.compile(
    r"state/(?:[a-z0-9-]+\.json|monitor\.sqlite3|token)"
    r"|watchdog/(?:[a-zA-Z0-9_]+\.py|static/(?:index\.html|app\.css|app\.js))"
)


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError(f"Expected a private backup directory owned by this account: {path}")


def open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
        stream.close()
        raise ValueError(f"Expected a regular backup file: {path.name}")
    return stream


def checksum(path):
    digest = hashlib.sha256()
    count = 0
    with open_regular(path) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            count += len(chunk)
    return {"bytes": count, "sha256": digest.hexdigest()}


def seal(directory, desktop):
    files = {str(file.relative_to(directory)): checksum(file) for file in sorted(directory.rglob("*"))
             if file != directory / MANIFEST and file.is_file()}
    if not {f"state/{name}" for name in REQUIRED} <= files.keys():
        raise ValueError("Backup is missing required state files")
    write_json(directory / MANIFEST, {"version": 1, "mode": "desktop" if desktop else "system",
                                     "at": time.time(), "files": files})


def read_manifest(directory):
    private_directory(directory)
    with open_regular(directory / MANIFEST) as stream:
        data = json.loads(stream.read(262145))
    if (not isinstance(data, dict) or data.get("version") != 1 or data.get("mode") not in ("desktop", "system")
            or not isinstance(data.get("at"), (int, float)) or not isinstance(data.get("files"), dict)):
        raise ValueError("Unsupported or malformed Watchdog backup manifest")
    files = data["files"]
    if not {f"state/{name}" for name in REQUIRED} <= files.keys():
        raise ValueError("Backup manifest is missing required state files")
    for name, entry in files.items():
        if (not FILE_NAME.fullmatch(name) or not isinstance(entry, dict) or set(entry) != {"bytes", "sha256"}
                or type(entry["bytes"]) is not int or entry["bytes"] < 0
                or not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            raise ValueError("Backup manifest contains an invalid file entry")
    return data


def verify_files(directory, files):
    for name, expected in files.items():
        relative = Path(name)
        for parent in relative.parents:
            if parent != Path(".") and not stat.S_ISDIR((directory / parent).lstat().st_mode):
                raise ValueError(f"Unsafe backup directory for {name}")
        if checksum(directory / relative) != expected:
            raise ValueError(f"Backup checksum mismatch: {name}")


def verify_database(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise ValueError("Backup database did not pass its integrity check")
        required = {"events", "properties", "samples"}
        tables = {name for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not required <= tables:
            raise ValueError("Backup database is missing required Watchdog tables")


def verify(directory):
    manifest = read_manifest(directory)
    verify_files(directory, manifest["files"])
    verify_database(directory / "state/monitor.sqlite3")
    return manifest


def inventory(directory):
    if not directory.exists():
        return []
    private_directory(directory)
    results = []
    for backup in sorted(directory.glob("backup-*"), key=lambda path: path.lstat().st_mtime, reverse=True):
        result = {"path": str(backup)}
        try:
            manifest = read_manifest(backup)
            result.update(at=manifest["at"], mode=manifest["mode"], status="manifest-present",
                          bytes=sum(file["bytes"] for file in manifest["files"].values()))
        except FileNotFoundError:
            result["status"] = "unverified"
        except (OSError, ValueError):
            result["status"] = "invalid"
        results.append(result)
    return results
