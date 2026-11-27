"""Replace deployed application code and recover automatically if it fails to start."""

import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
from contextlib import closing, contextmanager
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

from . import backups
from .common import CONFIG, RESPONSE_STATE, configuration

SYSTEM_ROOT = Path("/opt/ai-watchdog")
SYSTEM_STATE = Path("/var/lib/ai-watchdog")
SYSTEM_BACKUPS = Path("/var/lib/ai-watchdog-rollbacks")
ASSETS = ("index.html", "app.css", "app.js")
STATE_FILES = ("token", "baseline.json", "watchdog-integrity.json", "watchdog-advisories.json",
               "vulnerability-rules.json")


class RollbackError(Exception):
    pass


def trusted_directory(path):
    for directory in (path, *path.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RollbackError(f"Use a root-controlled directory for system rollback: {directory}")


def copy_regular(source, target, *, root_owned=False):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as reader:
        info = os.fstat(reader.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise RollbackError(f"Expected a regular file: {source}")
        if root_owned and (info.st_uid != 0 or info.st_mode & 0o022):
            raise RollbackError(f"Expected a root-controlled file: {source}")
        with target.open("xb") as writer:
            os.fchmod(writer.fileno(), 0o600)
            shutil.copyfileobj(reader, writer)
        return info


def copy_package(source, target, *, root_owned=False):
    for directory in (source, source / "static"):
        if not stat.S_ISDIR(directory.lstat().st_mode):
            raise RollbackError(f"Expected a package directory: {directory}")
        if root_owned:
            trusted_directory(directory)
    for required in ("__init__.py", "__main__.py", "common.py", "monitor.py", "server.py"):
        if not (source / required).is_file():
            raise RollbackError(f"Rollback source is missing {required}")
    target.mkdir(mode=0o755)
    (target / "static").mkdir(mode=0o755)
    for file in sorted(source.glob("*.py")) + [source / "static" / asset for asset in ASSETS]:
        destination = target / file.relative_to(source)
        copy_regular(file, destination, root_owned=root_owned)
        destination.chmod(0o644)
    # The service user needs to traverse the installed package even under umask 077.
    target.chmod(0o755)
    (target / "static").chmod(0o755)


def backup_database(database, destination):
    with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
        snapshot = Path(directory) / database.name
        metadata = copy_regular(database, snapshot)
        try:
            copy_regular(database.with_suffix(".sqlite3-wal"), snapshot.with_suffix(".sqlite3-wal"))
        except FileNotFoundError:
            pass
        with closing(sqlite3.connect(snapshot)) as source, closing(sqlite3.connect(destination)) as backup:
            source.backup(backup)
            if backup.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise RollbackError("The state database did not pass its backup integrity check")
    destination.chmod(0o600)
    return metadata


def restore_database(backup, database, metadata):
    with tempfile.TemporaryDirectory(dir=database.parent) as directory:
        replacement = Path(directory) / database.name
        copy_regular(backup, replacement)
        os.chown(replacement, metadata.st_uid, metadata.st_gid)
        replacement.chmod(stat.S_IMODE(metadata.st_mode))
        for suffix in ("-wal", "-shm", "-journal"):
            database.with_name(database.name + suffix).unlink(missing_ok=True)
        os.replace(replacement, database)


class Deployment:
    def __init__(self, desktop):
        self.desktop = desktop
        self.root = Path(__file__).resolve().parent.parent if desktop else SYSTEM_ROOT
        self.state = self.root / ".watchdog" if desktop else SYSTEM_STATE
        self.config = self.state / "config.json" if desktop else CONFIG
        self.backups = self.state / "rollbacks" if desktop else SYSTEM_BACKUPS
        suffix = ("ai-watchdog-observe", "ai-watchdog-observe-supervisor") if desktop else (
            "ai-watchdog", "ai-watchdog-response",
        )
        self.monitor, self.supervisor = (name + ".service" for name in suffix)
        self.control = ("/usr/bin/systemctl", "--user") if desktop else ("/usr/bin/systemctl",)

    def systemctl(self, *args, check=True):
        return subprocess.run((*self.control, *args), check=check, capture_output=True, text=True, timeout=60)

    def active(self, unit):
        return self.systemctl("is-active", "--quiet", unit, check=False).returncode == 0

    def stop(self):
        self.systemctl("stop", self.supervisor, self.monitor)

    def start_healthy(self, port, token, supervise):
        self.systemctl("start", self.monitor)
        self.wait_health(port, token)
        if supervise:
            self.systemctl("start", self.supervisor)
            self.wait_health(port, token, supervise=True)

    def wait_health(self, port, token, supervise=False):
        request = Request(f"http://127.0.0.1:{port}/api/status", headers={"Authorization": "Bearer " + token})
        opener = build_opener(ProxyHandler({}))
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.active(self.monitor) and (not supervise or self.active(self.supervisor)):
                try:
                    with opener.open(request, timeout=3) as response:
                        status = json.load(response)
                    if status.get("ready") and (not supervise or status["response"].get("watchdog_alive")):
                        return
                except (OSError, URLError, ValueError, KeyError):
                    pass
            time.sleep(1)
        raise RollbackError("Watchdog did not pass the authenticated dashboard health check")

    def preflight(self, source=None):
        if self.desktop == (os.geteuid() == 0):
            raise RollbackError("Run desktop rollback as the monitor user and system rollback as root")
        if self.desktop:
            state = self.state.lstat()
            if not stat.S_ISDIR(state.st_mode) or state.st_uid != os.geteuid() or state.st_mode & 0o077:
                raise RollbackError("The desktop monitor state directory must be private and owned by this account")
        else:
            trusted_directory(self.root)
            if source is not None:
                trusted_directory(source)
            trusted_directory(self.config.parent)
            if (RESPONSE_STATE / "isolation.json").exists():
                raise RollbackError("The isolation latch is present; review containment before stopping the supervisor")
        if source is not None and (self.root == source or source.is_relative_to(self.root / "watchdog")):
            raise RollbackError("Use a separate checkout of the trusted rollback version")
        for unit in (self.monitor, self.supervisor):
            directory = self.systemctl("show", "--value", "--property=WorkingDirectory", unit).stdout.strip()
            if directory != str(self.root):
                raise RollbackError(f"{unit} does not use the expected installation directory {self.root}")
        self.backups.mkdir(mode=0o700, exist_ok=True)
        info = self.backups.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RollbackError("The rollback backup directory must be private and owned by this account")
        return configuration(self.config)["port"]

    def backup_state(self, backup):
        state = backup / "state"
        state.mkdir(mode=0o700)
        copy_regular(self.config, state / "config.json")
        config_files = ("baseline.json", "watchdog-integrity.json") if not self.desktop else ()
        for directory, names in ((self.state, STATE_FILES), (self.config.parent, config_files)):
            for name in names:
                if (directory / name).exists() and not (state / name).exists():
                    copy_regular(directory / name, state / name)
        if not self.desktop:
            for name in ("isolation.json", "watchdog-boot.json"):
                try:
                    copy_regular(RESPONSE_STATE / name, state / ("response-" + name))
                except FileNotFoundError:
                    pass
        return backup_database(self.state / "monitor.sqlite3", state / "monitor.sqlite3")

    def rollback(self, source):
        source = source.resolve(strict=True)
        port = self.preflight(source)
        with self.maintenance_lock():
            return self.replace(source, port)

    @contextmanager
    def maintenance_lock(self):
        fd = os.open(self.backups / "lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RollbackError("Another backup, restore, or rollback is already running") from error
            yield

    def capture(self, backup):
        metadata = self.backup_state(backup)
        token = (backup / "state/token").read_text().strip()
        if len(token) < 40:
            raise RollbackError("The backed-up dashboard token is missing or invalid")
        backups.seal(backup, self.desktop)
        return metadata, token

    def create_backup(self):
        port = self.preflight()
        with self.maintenance_lock():
            was_active, supervise = self.active(self.monitor), self.active(self.supervisor)
            backup = Path(tempfile.mkdtemp(dir=self.backups, prefix="backup-"))
            copy_package(self.root / "watchdog", backup / "watchdog", root_owned=not self.desktop)
            token = None
            try:
                self.stop()
                _, token = self.capture(backup)
            finally:
                self.restart_original(port, token, was_active, supervise)
            return backup

    def restart_original(self, port, token, was_active, supervise):
        if was_active and token:
            self.start_healthy(port, token, supervise)
        else:
            if was_active:
                self.systemctl("start", self.monitor)
            if supervise:
                self.systemctl("start", self.supervisor)

    def apply_state(self, state, metadata):
        restore_database(state / "monitor.sqlite3", self.state / "monitor.sqlite3", metadata)
        for name in sorted(backups.STATE_NAMES - {"monitor.sqlite3"}):
            destination = self.config if name == "config.json" else self.state / name
            if not self.desktop and name in {"baseline.json", "watchdog-integrity.json"}:
                destination = self.config.parent / name
            source = state / name
            if not source.is_file():
                destination.unlink(missing_ok=True)
                continue
            owner = (0, 0) if not self.desktop and destination.parent == self.config.parent else (
                metadata.st_uid, metadata.st_gid,
            )
            mode = 0o644 if owner[0] == 0 and name in {"baseline.json", "watchdog-integrity.json"} else 0o600
            if destination == self.config:
                mode = stat.S_IMODE(self.config.lstat().st_mode)
            with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
                replacement = Path(directory) / name
                copy_regular(source, replacement)
                os.chown(replacement, *owner)
                replacement.chmod(mode)
                os.replace(replacement, destination)

    def restore(self, source):
        source = source.resolve(strict=True)
        manifest = backups.verify(source)
        if manifest["mode"] != ("desktop" if self.desktop else "system"):
            raise RollbackError("Backup and destination installation modes differ")
        original_port = self.preflight()
        with self.maintenance_lock(), tempfile.TemporaryDirectory(dir=self.backups) as directory:
            stage = Path(directory)
            (stage / "state").mkdir(mode=0o700)
            files = {f"state/{name}": manifest["files"][f"state/{name}"] for name in backups.STATE_NAMES
                     if f"state/{name}" in manifest["files"]}
            for name in files:
                copy_regular(source / name, stage / name)
            backups.verify_files(stage, files)
            state = stage / "state"
            port = configuration(state / "config.json")["port"]
            token = (state / "token").read_text().strip()
            if len(token) < 40:
                raise RollbackError("The dashboard token in the backup is invalid")
            was_active, supervise = self.active(self.monitor), self.active(self.supervisor)
            fallback = Path(tempfile.mkdtemp(dir=self.backups, prefix="backup-"))
            copy_package(self.root / "watchdog", fallback / "watchdog", root_owned=not self.desktop)
            print(f"Pre-restore backup: {fallback}", flush=True)
            original_token = None
            changed = False
            try:
                self.stop()
                if not self.desktop and (RESPONSE_STATE / "isolation.json").exists():
                    raise RollbackError("The isolation latch appeared while stopping Watchdog")
                metadata, original_token = self.capture(fallback)
                changed = True
                self.apply_state(state, metadata)
                self.start_healthy(port, token, supervise)
            except (Exception, KeyboardInterrupt) as error:
                try:
                    if changed:
                        self.stop()
                        self.apply_state(fallback / "state", metadata)
                    self.restart_original(original_port, original_token, was_active, supervise)
                except (Exception, KeyboardInterrupt) as recovery:
                    raise RollbackError(f"Restore failed ({error}); automatic recovery failed ({recovery}). "
                                        f"Use the backup at {fallback}.") from recovery
                raise RollbackError(f"Restore failed ({error}); the original installation was restored. "
                                    f"Backup: {fallback}") from error
            return fallback

    def replace(self, source, port):
        app = self.root / "watchdog"
        database = self.state / "monitor.sqlite3"
        was_active = self.active(self.monitor)
        supervise = self.active(self.supervisor)
        with tempfile.TemporaryDirectory(dir=self.root, prefix=".rollback-") as directory:
            work = Path(directory)
            candidate, previous = work / "candidate", work / "previous"
            copy_package(source / "watchdog", candidate, root_owned=not self.desktop)
            backup = Path(tempfile.mkdtemp(dir=self.backups, prefix="backup-"))
            copy_package(app, backup / "watchdog", root_owned=not self.desktop)
            print(f"Rollback backup: {backup}", flush=True)
            started = False
            token = None
            try:
                self.stop()
                if not self.desktop and (RESPONSE_STATE / "isolation.json").exists():
                    raise RollbackError("The isolation latch appeared while stopping Watchdog")
                metadata, token = self.capture(backup)
                os.replace(app, previous)
                os.replace(candidate, app)
                started = True
                self.start_healthy(port, token, supervise)
            except (Exception, KeyboardInterrupt) as error:
                try:
                    if previous.exists():
                        self.stop()
                        if app.exists():
                            os.replace(app, candidate)
                        os.replace(previous, app)
                    if started:
                        restore_database(backup / "state" / "monitor.sqlite3", database, metadata)
                    self.restart_original(port, token, was_active, supervise)
                except (Exception, KeyboardInterrupt) as recovery:
                    raise RollbackError(f"Rollback failed ({error}); automatic recovery failed ({recovery}). "
                                        f"Use the backup at {backup}.") from recovery
                raise RollbackError(f"Rollback failed ({error}); the original installation was restored. "
                                    f"Backup: {backup}") from error
        return backup
