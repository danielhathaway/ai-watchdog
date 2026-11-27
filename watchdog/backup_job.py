"""Scheduled encrypted backup rotation and isolated restore drills."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from . import backup_crypto, backups
from .common import configuration

RCLONE = "/usr/bin/rclone"
OBJECT = re.compile(r"watchdog-[0-9]{8}T[0-9]{12}Z-[a-f0-9]{16}-([a-f0-9]{64})\.age")
REMOTE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+")


@contextmanager
def private_file(path):
    with backups.open_regular(path) as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError(f"Expected a private file owned by this account: {path.name}")
        yield stream


def settings(path, operation):
    with private_file(path) as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("Backup job configuration is too large")
    options = json.loads(raw)
    required = {"remote", "rclone_config"}
    required.update({"recipient", "keep"} if operation == "publish" else {"identity"})
    if not isinstance(options, dict) or set(options) != required:
        raise ValueError(f"Backup {operation} configuration requires {', '.join(sorted(required))}")
    remote = options["remote"]
    if (not isinstance(remote, str) or not REMOTE.fullmatch(remote) or len(remote) > 300
            or {".", ".."} & set(remote.split(":", 1)[1].split("/"))):
        raise ValueError("Use a named rclone remote and a dedicated subdirectory, such as offsite:backups/endpoint")
    for key in required & {"rclone_config", "identity"}:
        if not isinstance(options[key], str) or not options[key]:
            raise ValueError(f"Expected a filename for {key}")
        options[key] = path.parent / options[key]
        with private_file(options[key]):
            pass
    if operation == "publish":
        recipient = options["recipient"]
        if not isinstance(recipient, str) or not backup_crypto.RECIPIENT.fullmatch(recipient):
            raise ValueError("Supply a native age X25519 recipient")
        keep = options["keep"]
        if type(keep) is not int or (keep != 0 and not 2 <= keep <= 365):
            raise ValueError("Backup retention must keep between 2 and 365 archives, or use 0 for provider retention")
    return options


class Remote:
    def __init__(self, options):
        self.folder = options["remote"]
        self.config = options["rclone_config"]

    def run(self, *arguments, capture=False):
        operation = arguments[0]
        try:
            result = subprocess.run(
                [RCLONE, "--config", str(self.config), "--retries", "2", "--contimeout", "15s",
                 "--timeout", "2m", *arguments], check=False, timeout=1200,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            raise ValueError(f"Off-host backup storage timed out during {operation}") from None
        if result.returncode:
            raise ValueError(f"Off-host backup storage failed during {operation} (rclone exit {result.returncode})")
        return result.stdout

    def names(self):
        entries = json.loads(self.run("lsjson", self.folder, "--files-only", "--max-depth", "1", capture=True))
        return sorted({item["Name"] for item in entries if OBJECT.fullmatch(item["Name"])}, reverse=True)

    def download(self, name, destination):
        self.run("copyto", f"{self.folder}/{name}", str(destination))
        if backups.checksum(destination)["sha256"] != OBJECT.fullmatch(name)[1]:
            raise ValueError("The off-host archive did not match its SHA-256 digest")

    def publish(self, ciphertext, workspace, keep):
        digest = backups.checksum(ciphertext)["sha256"]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        name = f"watchdog-{timestamp}-{secrets.token_hex(8)}-{digest}.age"
        self.run("copyto", str(ciphertext), f"{self.folder}/{name}", "--immutable")
        self.download(name, workspace / "readback.age")
        names = self.names()
        if name not in names:
            raise ValueError("The verified upload was missing from the retention inventory")
        if keep:
            older = [item for item in names if item != name]
            for old in older[keep - 1:]:
                self.run("deletefile", f"{self.folder}/{old}")
        return name


def publish(installation, options):
    installation.preflight()
    with installation.maintenance_lock("off-host.lock"), tempfile.TemporaryDirectory(prefix="watchdog-upload-") as directory:
        workspace = Path(directory)
        source = installation.create_backup(workspace)
        ciphertext = workspace / "sealed.age"
        backup_crypto.export_backup(source, ciphertext, options["recipient"])
        return Remote(options).publish(ciphertext, workspace, options["keep"])


def drill_dashboard(state):
    from .monitor import Monitor
    from .server import Console

    config = state / "config.json"
    options = configuration(config)
    options.update(port=0, enforce=False, integrity_paths=[], antivirus_paths=[], email_alerts=None, ollama_model="")
    token = (state / "token").read_text().strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,256}", token):
        raise ValueError("The restored dashboard token is invalid")
    monitor = Monitor(options, state / "monitor.sqlite3", state, baseline=state / "baseline.json",
                      response_runtime=state / "response", config=config, observe_directory=state)
    monitor.scan()
    monitor.ready.set()
    with Console(monitor, token) as console:
        worker = threading.Thread(target=console.handle_request, daemon=True)
        worker.start()
        client = http.client.HTTPConnection("127.0.0.1", console.server_port, timeout=10)
        try:
            client.request("GET", "/api/status", headers={"Authorization": f"Bearer {token}"})
            response = client.getresponse()
            if response.status != 200 or not json.load(response).get("ready"):
                raise ValueError("The isolated restored dashboard did not pass its authenticated health check")
        finally:
            client.close()
            worker.join(timeout=4)


def drill(options, desktop, archive=None):
    remote = Remote(options)
    names = remote.names()
    if not names:
        raise ValueError("No managed encrypted archives are available for the restore drill")
    if archive is not None and archive not in names:
        raise ValueError("The selected archive is not in the managed off-host inventory")
    name = archive or names[0]
    with tempfile.TemporaryDirectory(prefix="watchdog-drill-") as directory:
        ciphertext = Path(directory) / "restore.age"
        remote.download(name, ciphertext)
        with backup_crypto.open_encrypted(ciphertext, options["identity"]) as source:
            if backups.read_manifest(source)["mode"] != ("desktop" if desktop else "system"):
                raise ValueError("The backup and drill installation modes differ")
            drill_dashboard(source / "state")
    return name
