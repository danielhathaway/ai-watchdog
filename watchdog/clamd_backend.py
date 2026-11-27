"""Opt-in ClamD under the monitor account, with Watchdog-owned scan policy."""
import array
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import threading
import time

CLAMD = "/usr/sbin/clamd"
LIMIT = "Heuristics.Limits.Exceeded"


class ClamDError(Exception):
    def __init__(self, message, partial=None):
        super().__init__(message)
        self.partial = partial


class ClamD:
    def __init__(self):
        self.lock = threading.Lock()
        self.work = None
        self.process = None
        self.closed = False

    def _stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process = None
        if self.work is not None:
            self.work.cleanup()
            self.work = None

    def close(self):
        with self.lock:
            self.closed = True
            self._stop()

    def query(self, command, deadline, fd=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ClamDError("ClamD reached the shared scan deadline.")
        with self.lock:
            if self.work is None:
                raise ClamDError("The private ClamD instance is unavailable.")
            endpoint = Path(self.work.name) / "clamd.sock"
        try:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(remaining)
                connection.connect(str(endpoint))
                connection.sendall(b"z" + command + b"\0")
                if fd is not None:
                    connection.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
                with connection.makefile("rb") as stream:
                    data = stream.read(4097)
        except OSError as error:
            raise ClamDError("No usable response from the private ClamD socket.") from error
        if not data.endswith(b"\0") or data.count(b"\0") != 1 or len(data) > 4096:
            raise ClamDError("ClamD returned a malformed response.")
        return data[:-1].decode("utf-8", errors="replace")

    def prepare(self, readiness, deadline):
        if readiness["state"] != "ready":
            raise ClamDError("Current official signatures could not be verified for ClamD.")
        with self.lock:
            if self.closed:
                raise ClamDError("Watchdog is shutting down.")
            if self.process is None or self.process.poll() is not None:
                self._stop()
                self.work = tempfile.TemporaryDirectory(prefix="watchdog-clamd-")
                directory = Path(self.work.name)
                config = directory / "clamd.conf"
                config.write_text(
                    "Foreground yes\nDatabaseDirectory /var/lib/clamav\n"
                    f"LocalSocket {directory / 'clamd.sock'}\nLocalSocketMode 0600\n"
                    "OfficialDatabaseOnly yes\nAlertExceedsMax yes\nSelfCheck 60\nMaxThreads 1\n"
                )
                try:
                    self.process = subprocess.Popen(
                        [CLAMD, "--config-file", str(config)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, env={**os.environ, "LC_ALL": "C", "TZ": "UTC"},
                    )
                except OSError as error:
                    self._stop()
                    raise ClamDError("The private ClamD process could not start.") from error
            process = self.process
        ready_by = min(deadline, time.monotonic() + 60)
        while time.monotonic() < ready_by:
            if process.poll() is not None:
                raise ClamDError("ClamD exited during startup.")
            try:
                version = self.query(b"VERSION", min(ready_by, time.monotonic() + 2))
            except ClamDError:
                time.sleep(.25)
                continue
            expected = f'{readiness["engine"]}/{readiness["signature_version"]}/'
            if not version.startswith(expected):
                raise ClamDError("ClamD has not loaded the current official signature version.")
            return
        raise ClamDError("ClamD did not become ready before its startup deadline.")

    def scan_path(self, path, deadline):
        row = {"path": path, "status": "skipped", "files_scanned": 0, "scan_errors": 0,
               "access_errors": 0, "limit_hits": 0, "detections": 0, "backend": "clamd"}
        findings = []
        failure = None

        def io_error(error):
            row["scan_errors"] += 1
            if isinstance(error, PermissionError):
                row["access_errors"] += 1

        def scan_file(name, display, device, directory=None):
            if time.monotonic() >= deadline:
                raise ClamDError("ClamD reached the shared scan deadline.")
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_dev != device or not info.st_size:
                    return
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except OSError as error:
                io_error(error)
                return
            with os.fdopen(fd, "rb") as opened:
                current = os.fstat(opened.fileno())
                if not stat.S_ISREG(current.st_mode) or current.st_dev != device or not current.st_size:
                    return
                reply = self.query(b"FILDES", deadline, opened.fileno())
            verdict = reply.partition(": ")[2]
            if verdict == "OK":
                row["files_scanned"] += 1
            elif verdict.startswith((LIMIT + ".", LIMIT + " FOUND")) and verdict.endswith(" FOUND"):
                row["limit_hits"] += 1
            elif re.fullmatch(r"[\w.-]+ FOUND", verdict, re.ASCII):
                row["files_scanned"] += 1
                row["detections"] += 1
                if len(findings) < 5:
                    findings.append(f"{display}: {verdict}"[:512])
            else:
                # Standalone ClamAV supplies the authoritative legacy coverage on ambiguous daemon replies.
                raise ClamDError("ClamD could not classify a file; the path requires a standalone scan.")

        try:
            info = os.lstat(path)
        except OSError as error:
            io_error(error)
        else:
            if stat.S_ISDIR(info.st_mode):
                try:
                    for root, dirs, files, fd in os.fwalk(path, onerror=io_error, follow_symlinks=False):
                        if time.monotonic() >= deadline:
                            raise ClamDError("ClamD reached the shared scan deadline.")
                        if os.fstat(fd).st_dev != info.st_dev:
                            dirs.clear()
                            continue
                        for name in files:
                            scan_file(name, os.path.join(root, name), info.st_dev, fd)
                except (OSError, RecursionError):
                    failure = ClamDError("ClamD could not walk this path safely.")
                except ClamDError as error:
                    failure = error
            elif stat.S_ISREG(info.st_mode):
                scan_file(path, path, info.st_dev)

        if row["detections"]:
            row["status"] = "fail"
            row["detail"] = f"ClamAV reported {row['detections']} infected files. " + " · ".join(findings)
        elif row["scan_errors"] or row["limit_hits"]:
            row["status"] = "warn"
            row["detail"] = "ClamD reported access errors or file or archive limit hits."
        elif row["files_scanned"]:
            row["status"] = "pass"
            row["detail"] = f"No malware reported across {row['files_scanned']} scanned files."
        else:
            row["detail"] = "ClamAV did not scan any files in this path."
        if failure is not None:
            if findings:
                failure.partial = row
            raise failure
        return row
