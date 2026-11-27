"""Exchange authenticated drill results over a dedicated status prefix."""

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile

from . import backup_health, backup_job
from .common import write_json

LIMIT = 4096
OBJECT = "watchdog-verifier-v1.json"
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}")


def settings(path):
    with backup_job.private_file(path) as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Verifier configuration is too large")
    options = json.loads(raw)
    if not isinstance(options, dict) or set(options) != {"verifier", "remote", "rclone_config", "key_file"}:
        raise ValueError("Verifier configuration requires verifier, remote, rclone_config and key_file")
    if not isinstance(options["verifier"], str) or not ID.fullmatch(options["verifier"]):
        raise ValueError("Invalid verifier name")
    backup_job.validate_remote(options["remote"])
    for field in ("rclone_config", "key_file"):
        if not isinstance(options[field], str) or not options[field]:
            raise ValueError(f"Expected a filename for {field}")
        options[field] = path.parent / options[field]
    with backup_job.private_file(options["rclone_config"]):
        pass
    with backup_job.private_file(options["key_file"]) as stream:
        key = stream.read(129).strip()
    if not re.fullmatch(rb"[0-9a-fA-F]{64}", key):
        raise ValueError("Verifier key must be 32 random bytes encoded as 64 hexadecimal characters")
    return options, bytes.fromhex(key.decode("ascii"))


def signature(payload, key):
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def validate(raw, verifier, key, now):
    if len(raw) > LIMIT:
        raise ValueError("Verifier report exceeds the size limit")
    try:
        envelope = json.loads(raw)
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "mac"}:
            raise ValueError
        payload, mac = envelope["payload"], envelope["mac"]
        required = {"version", "verifier", "sent_at"}
        if (not isinstance(payload, dict) or not required <= payload.keys()
                or payload.keys() - required - {"success_at", "failure_at"}
                or type(payload["version"]) is not int or payload["version"] != 1
                or payload["verifier"] != verifier or not isinstance(mac, str)
                or not re.fullmatch(r"[0-9a-f]{64}", mac)):
            raise ValueError
        sent = payload["sent_at"]
        if not backup_health.timestamp(sent) or sent > now + 120:
            raise ValueError
        for field in ("success_at", "failure_at"):
            if field in payload and (not backup_health.timestamp(payload[field]) or payload[field] > sent):
                raise ValueError
        if not hmac.compare_digest(mac, signature(payload, key)):
            raise ValueError
    except (TypeError, ValueError, RecursionError):
        raise ValueError("Verifier report is invalid or its signature did not match") from None
    return payload


def import_report(payload):
    backup_health.check_directory()
    lock = os.open(backup_health.STATE / "verifier.lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, "wb") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        previous = backup_health.read_record("verifier")
        previous_at = previous.get("sent_at")
        if (previous.get("verifier") == payload["verifier"] and backup_health.timestamp(previous_at)
                and payload["sent_at"] <= previous_at):
            return
        write_json(backup_health.STATE / "verifier.json", payload, mode=0o644)


def sync(operation, now):
    if os.geteuid() != 0:
        raise ValueError("Verifier reporting requires the system backup service account")
    options, key = settings(backup_health.CONFIG / backup_health.VERIFIER_CONFIG[operation])
    remote = backup_job.Remote(options)
    destination = f"{remote.folder}/{OBJECT}"
    if operation == "report":
        if not (backup_health.CONFIG / backup_health.JOBS["drill"]).is_file():
            raise ValueError("Configure a local scheduled drill before publishing verifier reports")
        local = {name: at for name, at in backup_health.receipt("drill").items() if at <= now}
        payload = {"version": 1, "verifier": options["verifier"], "sent_at": now, **local}
        with tempfile.TemporaryDirectory(prefix="watchdog-verifier-") as directory:
            report = Path(directory) / OBJECT
            write_json(report, {"payload": payload, "mac": signature(payload, key)})
            remote.run("copyto", str(report), destination, "--ignore-times")
    else:
        raw = remote.run("cat", destination, "--count", str(LIMIT + 1), capture=True)
        import_report(validate(raw, options["verifier"], key, now))
