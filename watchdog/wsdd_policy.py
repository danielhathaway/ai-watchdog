"""Inspect the optional Wi-Fi-only wsdd installation without altering it."""
import hashlib
import json
import re
import stat
import subprocess
from pathlib import Path

STATE = Path("/var/lib/ai-watchdog-wsdd/policy.json")
LAUNCHER = Path("/usr/bin/wsdd")
VENDOR = Path("/usr/bin/wsdd.distrib")
PROFILE = Path("/etc/apparmor.d/usr.bin.wsdd")
LABEL = "/usr/bin/wsdd (enforce)"
BEGIN = "  # BEGIN AI Watchdog wsdd Wi-Fi policy"
END = "  # END AI Watchdog wsdd Wi-Fi policy"
RULE = "  /usr/bin/wsdd.distrib r,"
BLOCK = f"{BEGIN}\n{RULE}\n{END}\n"
INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}", re.ASCII)
DIGEST = re.compile(r"[0-9a-f]{64}")


def trusted_file(path, executable=False):
    info = path.lstat()
    return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            and (not executable or bool(info.st_mode & 0o111)))


def manifest(path=None):
    path = path or STATE
    if not trusted_file(path) or path.stat().st_size > 4096:
        raise ValueError("Unsafe wsdd policy state file")
    data = json.loads(path.read_text())
    if (not isinstance(data, dict) or set(data) != {"interface", "launcher_sha256"}
            or not isinstance(data["interface"], str) or not INTERFACE.fullmatch(data["interface"])
            or not isinstance(data["launcher_sha256"], str) or not DIGEST.fullmatch(data["launcher_sha256"])):
        raise ValueError("Invalid wsdd policy state")
    return data


def diversion():
    command = "/usr/bin/dpkg-divert"
    return tuple(subprocess.check_output([command, option, str(LAUNCHER)], text=True, timeout=5).strip()
                 for option in ("--listpackage", "--truename"))


def launcher_matches(data):
    return trusted_file(LAUNCHER, executable=True) and (
        hashlib.sha256(LAUNCHER.read_bytes()).hexdigest() == data["launcher_sha256"]
    )


def check_files(data):
    issues = []
    if diversion() != ("LOCAL", str(VENDOR)):
        issues.append("The expected local package diversion is missing or changed")
    for probe, message in (
        (lambda: launcher_matches(data), "The Wi-Fi launcher is missing or changed"),
        (lambda: trusted_file(VENDOR, executable=True), "The diverted executable is missing or unsafe"),
        (lambda: trusted_file(PROFILE) and PROFILE.read_text().count(BLOCK) == 1,
         "The managed AppArmor read rule is missing or changed"),
    ):
        try:
            if not probe():
                issues.append(message)
        except FileNotFoundError:
            issues.append(message)
    return issues
