"""Collect bounded executable-mapping metadata from local systemd services."""
import os
import time
from pathlib import Path

from .common import BOOT_ID, write_json

SNAPSHOT = Path("/run/ai-watchdog-runtime-processes/processes.json")
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_PROCESSES = 8192
MAX_MAPPINGS = 16_000
MAX_MAP_BYTES = 1024 * 1024
MAX_PATH_BYTES = 512
SNAPSHOT_MAX_AGE = 120
SYSTEM_DIRS = {"bin", "sbin", "lib", "lib32", "lib64", "libexec"}


def package_path(path):
    if (len(path) > MAX_PATH_BYTES or not path.startswith("/") or not path.isascii() or not path.isprintable()
            or "\\" in path or '"' in path):
        return None
    parts = path.removeprefix("/usr/").lstrip("/").split("/")
    if len(parts) < 2 or parts[0] not in SYSTEM_DIRS or any(part in {"", ".", ".."} for part in parts):
        return None
    return "/" + "/".join(parts)


def service(path):
    for line in path.read_text().splitlines():
        _, controllers, group = line.split(":", 2)
        if controllers not in {"", "name=systemd"} or not group.startswith("/") or len(group) > MAX_PATH_BYTES:
            continue
        parts = group.split("/")
        for index in range(len(parts) - 1, 0, -1):
            if parts[index].endswith(".scope"):
                return None
            if parts[index].endswith(".service"):
                return "/".join(parts[:index + 1])
    return None


def started(path):
    # The comm field can contain spaces or parentheses. Start time is field 22.
    return path.read_bytes().rsplit(b")", 1)[1].split()[19]


def mappings(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_MAP_BYTES + 1)
    if len(data) > MAX_MAP_BYTES:
        raise ValueError("Process map exceeds the size limit")
    files = set()
    for line in data.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or b"x" not in fields[1] or fields[4] == b"0":
            continue
        path = os.fsdecode(fields[5])
        deleted = path.endswith(" (deleted)")
        path = path.removesuffix(" (deleted)")
        if deleted:
            path = path.removesuffix(".dpkg-tmp")
        if name := package_path(path):
            major, minor = fields[3].split(b":")
            files.add((name, os.makedev(int(major, 16), int(minor, 16)), int(fields[4]), deleted))
    return files


def collect(proc=Path("/proc")):
    at = time.time()
    root = Path("/").stat()
    units = {}
    total = 0
    unreadable = 0
    limited = False
    with os.scandir(proc) as entries:
        for index, entry in enumerate(item for item in entries if item.name.isdecimal()):
            if index >= MAX_PROCESSES or total >= MAX_MAPPINGS:
                limited = True
                break
            if int(entry.name) == os.getpid():
                continue
            process = Path(entry.path)
            try:
                unit = service(process / "cgroup")
            except (FileNotFoundError, ProcessLookupError):
                continue
            except (OSError, ValueError):
                unreadable += 1
                continue
            if not unit:
                continue
            row = units.setdefault(unit, {"files": set(), "partial": False})
            try:
                generation = started(process / "stat")
                process_root = (process / "root").stat()
                if (root.st_dev, root.st_ino) != (process_root.st_dev, process_root.st_ino):
                    row["partial"] = True
                    continue
                files = mappings(process / "maps")
                if generation != started(process / "stat") or unit != service(process / "cgroup"):
                    row["partial"] = True
                    continue
            except (FileNotFoundError, ProcessLookupError):
                continue
            except (OSError, IndexError, ValueError):
                row["partial"] = True
                continue
            new_files = files - row["files"]
            if len(new_files) > MAX_MAPPINGS - total:
                limited = True
                break
            row["files"].update(new_files)
            total += len(new_files)
    return {"at": at, "boot_id": BOOT_ID, "limited": limited, "unreadable": unreadable,
            "units": {unit: {**row, "files": sorted(row["files"])} for unit, row in units.items()}}


if __name__ == "__main__":
    write_json(SNAPSHOT, collect(), mode=0o640)
