"""Deterministic health, file integrity and host configuration checks."""
import ipaddress
import json
import logging
import os
import re
import stat
import subprocess
import time
from pathlib import Path

from . import store
from .common import BOOT_ID, execute, uptime, write_json
from .process_traffic import SS
from .responder import heartbeat
from .sensors import IP, fingerprint

APP = Path(__file__).resolve().parent
SSHD = Path("/usr/sbin/sshd")
UDP_INSTALL = Path("/opt/ai-watchdog-udp")
SYSTEM_UNITS = Path("/etc/systemd/system")
GROUPS = {"health": ("health_check_minutes", 5), "hardening": ("hardening_check_minutes", 60)}
PROBE_ERRORS = (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError)
KERNEL_SETTINGS = {
    "kernel.randomize_va_space": 2,
    "kernel.yama.ptrace_scope": 1,
    "fs.protected_hardlinks": 1,
    "fs.protected_symlinks": 1,
}


def result(key, name, status, detail):
    return {"id": key, "name": name, "status": status, "detail": detail}


def targets(config, directory):
    paths = set(APP.rglob("*.py")) | set((APP / "static").glob("*"))
    paths.add(config.absolute())
    units = []
    if directory is None:
        units.extend(SYSTEM_UNITS / f"ai-watchdog{suffix}.service" for suffix in ("", "-response"))
    else:
        config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        for suffix in ("", "-supervisor"):
            name = f"ai-watchdog-observe{suffix}.service"
            paths.add(directory / name)
            units.append(config_home / "systemd" / "user" / name)
    if UDP_INSTALL.is_dir():
        paths.update((UDP_INSTALL / "collector.py", UDP_INSTALL / "udp.bt"))
        units.append(SYSTEM_UNITS / "ai-watchdog-udp@.service")
    for unit in units:
        paths.add(unit)
        paths.update(unit.with_name(unit.name + ".d").glob("*.conf"))
    return sorted(paths)


def record_baseline(path, config, directory):
    files = {str(item): fingerprint(item) for item in targets(config, directory)}
    write_json(path, {"files": files}, mode=0o644 if directory is None else 0o600)
    return len(files)


def integrity(path, config, directory):
    name = "Watchdog file integrity"
    try:
        info = path.lstat()
        owner = 0 if directory is None else os.getuid()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError("Unsafe baseline permissions")
        if not 0 < info.st_size <= 1024 * 1024:
            raise ValueError("Invalid baseline size")
        expected = json.loads(path.read_text())["files"]
        if not isinstance(expected, dict) or not expected:
            raise ValueError("Invalid baseline")
    except FileNotFoundError:
        return result("files", name, "unknown", "No trusted Watchdog file baseline has been recorded.")
    except PROBE_ERRORS:
        return result("files", name, "fail", "The Watchdog file baseline is unreadable or invalid.")

    current = {str(item) for item in targets(config, directory)}
    changed = sorted(current - expected.keys())
    unreadable = []
    for filename, saved in expected.items():
        try:
            if fingerprint(filename) != saved:
                changed.append(filename)
        except (OSError, ValueError):
            unreadable.append(filename)
    if changed:
        return result("files", name, "fail", f"{len(changed)} added or changed files: " + ", ".join(changed[:8]))
    if unreadable:
        return result("files", name, "unknown", f"{len(unreadable)} files could not be verified: "
                      + ", ".join(unreadable[:8]))
    return result("files", name, "pass", f"{len(expected)} files match the trusted baseline.")


def health(monitor):
    try:
        heartbeat(os.getuid(), uptime(), monitor.settings, runtime=monitor.runtime)
        fresh = True
    except PROBE_ERRORS:
        fresh = False
    response = monitor.response()
    alive = response["watchdog_alive"]
    observing = response["status"] == "observing"
    with store.connect(monitor.database) as db:
        sensors = store.property_get(db, "sensors", {})
    unavailable = [name for name, state in sensors.items() if state != "ready"]
    insecure = []
    missing = []
    for item in (monitor.database.parent, monitor.database, monitor.database.parent / "token"):
        try:
            info = item.lstat()
            expected_type = stat.S_ISDIR if item == monitor.database.parent else stat.S_ISREG
            if info.st_mode & 0o077 or info.st_uid != os.getuid() or not expected_type(info.st_mode):
                insecure.append(item.name)
        except OSError:
            missing.append(item.name)
    return [
        result("heartbeat", "Monitor heartbeat", "pass" if fresh else "fail",
               "A current heartbeat was published." if fresh else "The monitor heartbeat is missing or stale."),
        result("supervisor", "Independent supervisor", "pass" if alive and observing else "fail",
               f"Supervisor status is {response['status']}." if alive else "Supervisor status is missing or stale."),
        result("sensors", "Sensor status", "warn" if unavailable else "pass" if sensors else "unknown",
               ", ".join(unavailable) or ("Reported sensors are ready." if sensors else "No sensor readings yet.")),
        result("state", "Private monitor state", "fail" if insecure else "unknown" if missing else "pass",
               "Unexpected ownership, permissions, or file type: " + ", ".join(insecure) if insecure else
               "State could not be checked: " + ", ".join(missing) if missing else
               "The state directory, database, and access token are private."),
        integrity(monitor.baseline.with_name("watchdog-integrity.json"), monitor.config, monitor.observe_directory),
    ]


LISTENER_INVENTORY_VERSION = 2
SS_PROCESS = re.compile(r'\("([^"]+)",pid=(\d+),fd=(\d+)\)')
SS_CGROUP = re.compile(r"\bcgroup:(/\S*)")
SS_INODE = re.compile(r"\bino:(\d+)")
PYTHON_PROCESS = re.compile(r"python(?:\d+(?:\.\d+)?)?")


def process_app(name, pid, fd, inode):
    # An interpreter's process name alone does not identify its app.
    if not inode or not PYTHON_PROCESS.fullmatch(name):
        return name
    path = Path("/proc") / str(pid)
    try:
        if (path / "fd" / str(fd)).readlink() != Path(f"socket:[{inode}]"):
            return name
        with (path / "cmdline").open("rb") as stream:
            argv = stream.read(4096).split(b"\0")
        if len(argv) >= 3 and argv[1].startswith(b"/"):
            script = Path(os.fsdecode(argv[1])).name
            if re.fullmatch(r"[A-Za-z0-9_.+-]{1,100}", script):
                return script
    except OSError:
        pass
    return name


def interface_lookup():
    addresses = {}
    indices = {}
    try:
        interfaces = json.loads(execute(IP, "-j", "address", "show"))
        for device in interfaces:
            name = device["ifname"]
            indices[str(device["ifindex"])] = name
            for row in device.get("addr_info", []):
                address = ipaddress.ip_address(row["local"])
                addresses.setdefault(address, set()).add(name)
    except PROBE_ERRORS:
        return {}, {}
    return addresses, indices


def listener_interface(ip, scope, addresses, indices):
    if scope:
        return indices.get(scope) if scope.isdecimal() else scope
    if ip is None or ip.is_unspecified or ip.is_multicast:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    names = addresses.get(ip, set())
    return next(iter(names)) if len(names) == 1 else None


def matches_rule(rule, protocol, interface, service, apps):
    return (
        interface == rule["interface"] and service == rule["service"]
        and rule.get("protocol", protocol) == protocol
        and ("app" not in rule or apps == {rule["app"]})
    )


def listeners(output, allowed=(), rules=(), interfaces=None):
    entries = {}
    apps = {}
    addresses, indices = interfaces or ({}, {})
    for line in output.splitlines():
        fields = line.split(maxsplit=6)
        if not fields:
            continue
        protocol = fields[0]
        if len(fields) < 6 or protocol not in {"tcp", "udp"}:
            raise ValueError("Unrecognized listener record")
        host, port = fields[4].rsplit(":", 1)
        address, sep, zone = host.partition("%")
        address = address.strip("[]")
        ip = ipaddress.ip_address(address) if address != "*" else None
        if ip and (ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip).is_loopback:
            continue
        scope = zone.rstrip("]")
        interface = listener_interface(ip, scope, addresses, indices)
        address += sep + scope
        port = int(port)
        entry = entries.setdefault((protocol, port, address), {
            "protocol": protocol, "port": port, "address": address, "socket_count": 0,
            "processes": {}, "services": set(), "interface": interface, "allowed": True,
        })
        entry["socket_count"] += 1
        metadata = fields[6] if len(fields) == 7 else ""
        service = None
        if cgroup := SS_CGROUP.search(metadata):
            for unit in reversed(cgroup[1].split("/")):
                if unit.startswith(("user@", "session-")):
                    continue
                if unit.endswith((".service", ".scope")):
                    service = unit
                    entry["services"].add(unit)
                    break
        inode = SS_INODE.search(metadata)
        socket_apps = set()
        for name, pid, fd in SS_PROCESS.findall(metadata):
            pid = int(pid)
            if pid not in apps:
                apps[pid] = process_app(name, pid, fd, inode[1] if inode else None)
            entry["processes"][pid] = {"pid": pid, "name": name, "app": apps[pid]}
            socket_apps.add(apps[pid])
        if f"{protocol}/{port}" not in allowed and not any(
            matches_rule(rule, protocol, interface, service, socket_apps) for rule in rules
        ):
            entry["allowed"] = False
    for entry in entries.values():
        entry["processes"] = [entry["processes"][pid] for pid in sorted(entry["processes"])]
        entry["services"] = sorted(entry["services"])
    return [entries[key] for key in sorted(entries)]


def port_check(allowed, rules=()):
    name = "Non-loopback listening ports"
    try:
        output = execute(SS, "-H", "-lntu", "-p", "-e")
        entries = listeners(output, set(allowed), rules, interface_lookup())
    except PROBE_ERRORS:
        return {**result("ports", name, "unknown", "Listening sockets could not be inventoried."),
                "inventory_version": LISTENER_INVENTORY_VERSION}

    unexpected = []
    for entry in entries:
        if not entry["allowed"]:
            label = f'{entry["protocol"]}/{entry["port"]}'
            owners = sorted({process["app"] for process in entry["processes"]} | set(entry["services"]))
            unexpected.append(f'{label} ({entry["address"]}) — ' + (", ".join(owners) or "owner unavailable"))
    if unexpected:
        detail = f"{len(unexpected)} listeners outside the allowlist: " + "; ".join(unexpected[:30])
        check = result("ports", name, "warn", detail)
    else:
        check = result("ports", name, "pass", f"{len(entries)} non-loopback listeners, all on allowed ports.")
    return {**check, "inventory_version": LISTENER_INVENTORY_VERSION, "listeners": entries}


def ssh_check():
    name = "OpenSSH server configuration"
    if not SSHD.is_file():
        return result("ssh", name, "skipped", "The OpenSSH server binary was not found.")
    output = None
    for flag in ("-G", "-T"):
        try:
            output = execute(str(SSHD), flag)
            break
        except PROBE_ERRORS:
            continue
    if output is None:
        return result("ssh", name, "unknown", "The effective SSH configuration could not be read.")
    values = dict(line.split(None, 1) for line in output.splitlines() if len(line.split(None, 1)) == 2)
    expected = {"permitrootlogin": "no", "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
                "permitemptypasswords": "no"}
    warnings = [f"{key}={values[key]}" for key, value in expected.items() if key in values and values[key] != value]
    missing = sorted(expected.keys() - values.keys())
    detail = ("Review " + ", ".join(warnings) + ". " if warnings else "")
    detail += ("Missing: " + ", ".join(missing) + ". " if missing else "")
    return result("ssh", name, "warn" if warnings else "unknown" if missing else "pass",
                  detail + "Checked the default configuration; per-connection Match rules may differ.")


def kernel_check(key, minimum):
    label = f"Kernel setting {key}"
    try:
        value = int((Path("/proc/sys") / key.replace(".", "/")).read_text().strip())
    except (OSError, ValueError):
        return result(key, label, "unknown", "The running kernel setting could not be read.")
    return result(key, label, "pass" if value >= minimum else "warn", f"Current value {value}; expected at least {minimum}.")


def firewall_check():
    name = "nftables inbound policy"
    try:
        rules = json.loads(execute("/usr/sbin/nft", "-j", "list", "ruleset"))["nftables"]
        families = {entry["chain"]["family"] for entry in rules if "chain" in entry
                    and entry["chain"].get("hook") == "input" and entry["chain"].get("policy") == "drop"}
    except PROBE_ERRORS:
        return result("firewall", name, "unknown", "The nftables policy is unreadable with the monitor's permissions.")
    if "inet" in families or {"ip", "ip6"} <= families:
        return result("firewall", name, "pass", "Found default-drop input chains covering IPv4 and IPv6.")
    return result("firewall", name, "warn", "No default-drop input policy covers both IP families. Review firewall rules.")


def hardening(settings):
    return [port_check(settings["allowed_listeners"], settings["allowed_listener_rules"]), ssh_check(), firewall_check(),
            *(kernel_check(key, minimum) for key, minimum in KERNEL_SETTINGS.items())]


def read(db, settings):
    saved = store.property_get(db, "system_checks", {})
    return {group: {**saved.get(group, {}), "interval_minutes": settings.get(key, default)}
            for group, (key, default) in GROUPS.items()}


def save(database, group, now, rows):
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        saved = store.property_get(db, "system_checks", {})
        before = {row["id"]: row for row in saved.get(group, {}).get("checks", [])}
        for row in rows:
            previous = before.get(row["id"], {})
            if (row["status"], row["detail"]) == (previous.get("status"), previous.get("detail")):
                continue
            if row["status"] in {"fail", "warn"}:
                severity = "high" if row["status"] == "fail" else "medium"
            elif row["status"] == "pass" and previous.get("status") in {"fail", "warn"}:
                severity = "info"
            else:
                continue
            store.event(db, now, severity, "system-check", f'{row["name"]}: {row["status"]}',
                        row["detail"], f'{group}/{row["id"]}')
        if group == "hardening":
            for row in rows:
                if row["id"] == "ports" and "listeners" in row:
                    db.execute("INSERT INTO listener_inventory(at, listeners) VALUES (?, ?)",
                               (now, json.dumps(row["listeners"])))
        saved[group] = {"at": now, "boot_id": BOOT_ID, "checks": rows}
        store.property_set(db, "system_checks", saved)


def run(monitor):
    while not monitor.stop.wait(5):
        if not monitor.ready.is_set():
            continue
        try:
            with store.connect(monitor.database) as db:
                saved = read(db, monitor.settings)
            for group, collect in (("health", lambda: health(monitor)), ("hardening", lambda: hardening(monitor.settings))):
                previous = saved[group]
                elapsed = time.time() - previous.get("at", 0)
                outdated = group == "hardening" and any(
                    row["id"] == "ports" and row.get("inventory_version") != LISTENER_INVENTORY_VERSION
                    for row in previous.get("checks", [])
                )
                if not outdated and previous.get("boot_id") == BOOT_ID and 0 <= elapsed < previous["interval_minutes"] * 60:
                    continue
                try:
                    rows = collect()
                except Exception:
                    logging.exception("Scheduled %s checks failed", group)
                    continue
                save(monitor.database, group, time.time(), rows)
        except Exception:
            logging.exception("Scheduled system checks failed")
            monitor.stop.wait(55)
