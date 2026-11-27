"""Observe session-linked privileged changes using local journal and file evidence."""
import ipaddress
import json
import logging
import os
import re
import shlex
import sqlite3
import stat
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import sensors, store
from .common import BOOT_ID, execute

WINDOW = 600
CHANGE_WINDOW = 90
SIGNAL_RETENTION = WINDOW + CHANGE_WINDOW
MAX_BATCH = 400
MAX_SIGNALS = 1600
STATE = store.SSH_ACTIVITY_STATE
SENSOR = store.SSH_ACTIVITY_SENSOR
SYSTEM_UNITS = Path("/etc/systemd/system")
SSH = ("/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/lib/openssh/sshd-auth")
SUDO = ("/usr/bin/sudo", "/usr/bin/sudo.ws", "/usr/bin/sudo-rs", "/usr/lib/cargo/bin/sudo")
SYSTEMD = ("/usr/lib/systemd/systemd", "/lib/systemd/systemd")
UNIT_STARTED = "39f53479d3a045ac8e11786248231fbf"
ACCOUNT = r"[A-Za-z0-9_.@-]{1,64}"
UNIT = re.compile(r"[A-Za-z0-9_.@:-]{1,180}\.(?:service|socket|timer|path)")
ACCEPTED = re.compile(rf"^Accepted [\w/@.+-]+ for ({ACCOUNT}) from ([\da-fA-F:.]+) port \d+ ssh2(?:[: ]|$)")
SSH_SESSION = re.compile(rf"^pam_unix\(sshd:session\): session opened for user ({ACCOUNT})(?:\(uid=\d+\))? by ")
ROOT_SESSION = re.compile(r"^pam_unix\((?:sudo|sudo-i):session\): session opened for user root(?:\(uid=0\))? by ")
APPROVAL = re.compile(rf"^\s*({ACCOUNT})\s*:\s*TTY=[^;]+\s*;(?:[^;]+;)*?\s*USER=root\s*;\s*COMMAND=(.+)$")
FIELDS = ("MESSAGE,_BOOT_ID,_PID,_UID,_EXE,_AUDIT_SESSION,_AUDIT_LOGINUID,_SYSTEMD_SESSION,"
          "_SOURCE_REALTIME_TIMESTAMP,MESSAGE_ID,UNIT")
MATCHES = tuple(arg for exe in (*SSH, *SUDO) for arg in (f"_EXE={exe}", "+")) + (
    "_PID=1", f"MESSAGE_ID={UNIT_STARTED}",
)
PERSISTENCE = re.compile(
    r"/etc/(?:cron\.d/[A-Za-z0-9_-]+|sudoers\.d/[A-Za-z0-9_-]+|ssh/sshd_config\.d/[A-Za-z0-9_-]+\.conf)"
)
FIXED_PATHS = {"/etc/crontab", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/ld.so.preload", "/etc/rc.local"}


def unit_name(value):
    return isinstance(value, str) and not value.startswith(("-", ".")) and UNIT.fullmatch(value)


def persistence_path(value):
    if not isinstance(value, str) or len(value) > 256:
        return False
    if value in FIXED_PATHS or PERSISTENCE.fullmatch(value):
        return True
    prefix = str(SYSTEM_UNITS) + "/"
    if value.startswith(prefix):
        parts = value[len(prefix):].split("/")
        return (len(parts) == 1 and unit_name(parts[0])) or (
            len(parts) == 2 and parts[0].endswith(".d") and unit_name(parts[0][:-2])
            and re.fullmatch(r"[A-Za-z0-9_-]{1,100}\.conf", parts[1])
        )
    return False


def approved_target(command):
    try:
        binary, *args = shlex.split(command)
    except ValueError:
        return None
    if binary in ("/usr/bin/systemctl", "/bin/systemctl"):
        now = "--now" in args
        if now:
            args.remove("--now")
        if len(args) == 2:
            action, target = args
            if not now and action in {"start", "restart"}:
                return ("service", target) if unit_name(target) and target.endswith(".service") else None
            if action in {"enable", "reenable"} and unit_name(target):
                return "enablement", target
            if not now and action == "link" and target.startswith("/") and unit_name(PurePosixPath(target).name):
                return "enablement", PurePosixPath(target).name
        return None
    if binary in {"sudoedit", "/usr/bin/sudoedit", "/usr/bin/tee", "/bin/tee"}:
        if binary.endswith("/tee") and args[:1] == ["-a"]:
            args = args[1:]
        if len(args) == 1 and persistence_path(args[0]):
            return "file", args[0]
    if binary in {"/usr/bin/cp", "/bin/cp", "/usr/bin/install", "/bin/install"}:
        if binary.endswith("/install") and len(args) == 4 and args[0] == "-m" and re.fullmatch(r"[0-7]{3,4}", args[1]):
            args = args[2:]
        if len(args) == 2 and not args[0].startswith("-") and persistence_path(args[1]):
            return "file", args[1]
    return None


def identifier(value, pattern):
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else None


def session(entry):
    audit = identifier(entry.get("_AUDIT_SESSION"), r"\d{1,10}")
    uid = identifier(entry.get("_AUDIT_LOGINUID"), r"\d{1,10}")
    return {name: value for name, value in (
        ("audit", audit), ("uid", uid), ("systemd", identifier(entry.get("_SYSTEMD_SESSION"), r"[A-Za-z0-9_-]{1,32}")),
    ) if value and value != "4294967295"}


def same_session(left, right):
    shared = left.keys() & right.keys()
    return bool(shared & {"audit", "systemd"}) and all(left[key] == right[key] for key in shared)


def signal(entry, now):
    if entry.get("_BOOT_ID") != BOOT_ID.replace("-", ""):
        return None
    stamp = identifier(entry.get("__REALTIME_TIMESTAMP"), r"\d{1,20}")
    cursor = identifier(entry.get("__CURSOR"), r"[ -~]{1,512}")
    pid = identifier(entry.get("_PID"), r"[1-9]\d{0,9}")
    if not (stamp and cursor and pid):
        return None
    at = int(stamp) / 1_000_000
    source = identifier(entry.get("_SOURCE_REALTIME_TIMESTAMP"), r"\d{1,20}")
    if source and 0 <= at - int(source) / 1_000_000 <= 5:
        at = int(source) / 1_000_000
    if not 0 <= now - at <= SIGNAL_RETENTION:
        return None
    message = entry.get("MESSAGE")
    base = {"id": cursor, "at": at, "pid": pid}
    exe = entry.get("_EXE")
    if (exe in SYSTEMD and pid == "1" and entry.get("_UID") == "0"
            and entry.get("MESSAGE_ID") == UNIT_STARTED and unit_name(entry.get("UNIT"))):
        return {**base, "kind": "started", "target": entry["UNIT"]}
    if not isinstance(message, str) or len(message) > 2048:
        return None
    base["session"] = session(entry)
    if exe in SSH and entry.get("_UID") == "0":
        if match := ACCEPTED.match(message):
            if match[1] == "root" or base["session"].get("uid") == "0":
                return None
            try:
                address = str(ipaddress.ip_address(match[2]))
            except ValueError:
                return None
            return {**base, "kind": "login", "account": match[1], "address": address}
        if match := SSH_SESSION.match(message):
            return {**base, "kind": "ssh-open", "account": match[1]}
    if exe in SUDO:
        if ROOT_SESSION.match(message):
            return {**base, "kind": "root-open"}
        if (match := APPROVAL.fullmatch(message)) and (action := approved_target(match[2])):
            return {**base, "kind": "approved", "account": match[1], "action": action[0], "target": action[1]}
    return None


def journal(cursor, now):
    options = [sensors.JOURNAL, "--system", "-b", "-q", "--no-pager", "-o", "json",
               f"--output-fields={FIELDS}", "--until", f"@{now:.6f}", "-n", str(MAX_BATCH + 1)]
    try:
        position = ["--after-cursor", cursor] if cursor else ["--since", f"@{max(0, int(now) - 60)}"]
        output = execute(*options, *position, *MATCHES)
    except subprocess.CalledProcessError:
        if not cursor:
            raise
        _, next_cursor, _ = journal(None, now)
        return [], next_cursor, True
    entries = [json.loads(line) for line in output.splitlines()]
    last = entries[-1]["__CURSOR"] if entries else cursor
    if len(entries) > MAX_BATCH:
        return [], last, True
    return [item for entry in entries if (item := signal(entry, now))], last, False


def valid_sessions(login, opens):
    if {"audit", "systemd"} & login["session"].keys():
        yield login["session"]
    for event in opens:
        if (event["account"] == login["account"] and 0 <= event["at"] - login["at"] <= 15
                and {"audit", "systemd"} & event["session"].keys()
                and all(value == event["session"].get(key, value) for key, value in login["session"].items())):
            yield login["session"] | event["session"]


def changes(path, since, until, symlink=False):
    try:
        info = path.lstat()
        at = info.st_ctime_ns / 1_000_000_000
        if not since <= at <= until:
            return None
        if symlink:
            if stat.S_ISLNK(info.st_mode) and PurePosixPath(os.readlink(path)).name == path.name:
                return at, str(path)
        elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return at, str(path)
    except (FileNotFoundError, NotADirectoryError):
        pass
    return None


def enablement_directories():
    try:
        with os.scandir(SYSTEM_UNITS) as entries:
            directories = [SYSTEM_UNITS]
            for index, entry in enumerate(entries):
                if index >= 1024:
                    raise ValueError("System unit directory exceeds the scan limit")
                if entry.name.endswith((".wants", ".requires")) and entry.is_dir(follow_symlinks=False):
                    directories.append(SYSTEM_UNITS / entry.name)
            return directories
    except FileNotFoundError:
        return []


def matches(signals, allowed, now, errors):
    by_kind = defaultdict(list)
    ssh_open = defaultdict(list)
    root_open = defaultdict(list)
    starts = defaultdict(list)
    for event in signals:
        kind = event["kind"]
        if kind == "ssh-open":
            ssh_open[event["pid"]].append(event)
        elif kind == "root-open":
            root_open[event["pid"]].append(event)
        elif kind == "started":
            starts[event["target"]].append(event["at"])
        else:
            by_kind[kind].append(event)
    logins = defaultdict(list)
    for login in sorted(by_kind["login"], key=lambda event: event["at"], reverse=True):
        for binding in valid_sessions(login, ssh_open[login["pid"]]):
            logins[login["account"]].append((login, binding))
    directories = None
    for approval in by_kind["approved"]:
        target, action = approval["target"], approval["action"]
        start = approval["at"]
        if target in allowed or not 0 <= now - start <= CHANGE_WINDOW:
            continue
        opening = next((event for event in root_open[approval["pid"]]
                        if abs(event["at"] - start) <= 5 and same_session(event["session"], approval["session"])), None)
        if not opening:
            continue
        login = next((event for event, binding in logins[approval["account"]]
                      if 0 <= min(start, opening["at"]) - event["at"] <= WINDOW
                      and same_session(binding, approval["session"] | opening["session"])), None)
        if not login:
            continue
        since, until = max(start, opening["at"]), min(now, start + CHANGE_WINDOW)
        try:
            if action == "service":
                evidence = next(((at, target) for at in starts[target] if since <= at <= until), None)
            elif action == "file":
                evidence = changes(Path(target), since, until)
            else:
                if directories is None:
                    directories = enablement_directories()
                evidence = next((observed for directory in directories
                                 if (observed := changes(directory / target, since, until, symlink=True))), None)
        except (OSError, ValueError):
            errors.add(target)
            continue
        if evidence:
            yield login, approval, opening, evidence


def utc(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def check(database, now, allowed=()):
    with store.connect(database) as db:
        previous = store.property_get(db, STATE, {})
    if previous.get("boot_id") != BOOT_ID:
        previous = {}
    cursor = previous.get("cursor")
    status, detail = "ready", ""
    alerts = []
    signals = {}
    try:
        recent, cursor, gap = journal(cursor, now)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        status, detail = "degraded", type(error).__name__
    else:
        if gap:
            status, detail = "degraded", "Journal cursor lost or per-scan limit reached."
        else:
            signals = {item["id"]: item for item in (*previous.get("signals", []), *recent)
                       if 0 <= now - item["at"] <= SIGNAL_RETENTION}
            if len(signals) > MAX_SIGNALS:
                signals.clear()
                status, detail = "degraded", "Correlation window exceeded the event limit."
    if status == "ready":
        errors = set()
        alerts = list(matches(signals.values(), set(allowed), now, errors))
        if errors:
            status, detail = "degraded", f"Could not verify {len(errors)} persistence targets."
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        if status == "degraded":
            store.event(db, now, "medium", "sensor", "SSH activity correlation coverage degraded",
                        detail, SENSOR, cooldown=600)
        for login, approval, opening, (changed_at, target) in alerts:
            actor = f'{login["account"]} from {login["address"]}'
            severity = "medium" if approval["action"] == "service" else "high"
            confirmation = "Systemd recorded a start for" if approval["action"] == "service" else "File metadata changed at"
            store.event(db, now, severity, "ssh-activity", "SSH login followed by privileged change",
                        f'SSH accepted {actor} at {utc(login["at"])}. Root sudo session opened at {utc(opening["at"])}. '
                        f'{confirmation} {target} at {utc(changed_at)}.',
                        f'{actor} → {approval["target"]}', cooldown=WINDOW)
        state = {"boot_id": BOOT_ID, "cursor": cursor, "status": status, "signals": list(signals.values())}
        if state != previous:
            store.property_set(db, STATE, state)


def run(monitor):
    while not monitor.stop.wait(1):
        if not monitor.ready.is_set():
            continue
        try:
            check(monitor.database, time.time(), monitor.settings["ssh_activity_allowed_targets"])
        except (OSError, sqlite3.Error):
            logging.exception("SSH activity correlation failed")
        if monitor.stop.wait(monitor.settings["interval"] - 1):
            break
