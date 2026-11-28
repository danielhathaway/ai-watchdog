"""Deterministic health, file integrity and host configuration checks."""
import ipaddress
import json
import logging
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import backup_health, certificates, clamd_backend, multicast, reviews, store, vulnerabilities, wsdd_policy
from .common import BOOT_ID, execute, uptime, write_json
from .process_traffic import SS
from .responder import heartbeat
from .sensors import IP, fingerprint

APP = Path(__file__).resolve().parent
SSHD = Path("/usr/sbin/sshd")
CLAMSCAN = "/usr/bin/clamscan"
ANTIVIRUS_TIMEOUT = 900
ANTIVIRUS_SIGNATURE_MAX_DAYS = 7
ANTIVIRUS_RETRY_SECONDS = 300
UDP_INSTALL = Path("/opt/ai-watchdog-udp")
MULTICAST_INSTALL = Path("/opt/ai-watchdog-multicast")
WSDD_DPKG_HOOK = Path("/etc/dpkg/dpkg.cfg.d/90-ai-watchdog-wsdd")
SYSTEM_UNITS = Path("/etc/systemd/system")
GROUPS = {
    "health": ("health_check_minutes", 5),
    "hardening": ("hardening_check_minutes", 60),
    "antivirus": ("antivirus_check_minutes", 1440),
}
PROBE_ERRORS = (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError)
KERNEL_SETTINGS = {
    "kernel.randomize_va_space": 2,
    "kernel.yama.ptrace_scope": 1,
    "fs.protected_hardlinks": 1,
    "fs.protected_symlinks": 1,
}


def result(key, name, status, detail):
    return {"id": key, "name": name, "status": status, "detail": detail}


def wsdd_hook_files():
    return {WSDD_DPKG_HOOK, *(wsdd_policy.STATE.parent / name for name in ("manage.py", "wsdd_policy.py"))}


def targets(config, directory):
    paths = set(APP.rglob("*.py")) | set((APP / "static").glob("*"))
    paths.add(config.absolute())
    units = []
    if directory is None:
        units.extend(SYSTEM_UNITS / f"ai-watchdog{suffix}.service" for suffix in ("", "-response"))
        scheduled = ("vulnerability-refresh.service", "vulnerability-refresh.timer",
                     "userspace.service", "userspace.timer", "runtime-processes.service",
                     "offhost-sender.service", "offhost-sender.timer", "collector.service")
        units.extend(unit for name in scheduled if (unit := SYSTEM_UNITS / f"ai-watchdog-{name}").exists())
    else:
        config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        for suffix in ("", "-supervisor"):
            name = f"ai-watchdog-observe{suffix}.service"
            paths.add(directory / name)
            units.append(config_home / "systemd" / "user" / name)
        for suffix in ("vulnerability-refresh.service", "vulnerability-refresh.timer", "userspace.service",
                       "userspace.timer", "offhost-sender.service", "offhost-sender.timer"):
            name = f"ai-watchdog-observe-{suffix}"
            if (directory / name).exists():
                paths.add(directory / name)
                units.append(config_home / "systemd" / "user" / name)
    if UDP_INSTALL.is_dir():
        paths.update((UDP_INSTALL / "collector.py", UDP_INSTALL / "udp.bt"))
        units.append(SYSTEM_UNITS / "ai-watchdog-udp@.service")
    if MULTICAST_INSTALL.is_dir():
        paths.update(MULTICAST_INSTALL / name for name in ("multicast_collector.py", "multicast.bt"))
        units.extend(SYSTEM_UNITS / f"ai-watchdog-multicast@.{suffix}" for suffix in ("service", "timer"))
    hook_files = wsdd_hook_files()
    if any(os.path.lexists(item) for item in hook_files | {wsdd_policy.STATE}):
        paths.update(hook_files)
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
    hook_files = {str(item) for item in wsdd_hook_files()}
    changed = sorted(current - expected.keys())
    unreadable = []
    for filename, saved in expected.items():
        try:
            if (filename in hook_files and not wsdd_policy.trusted_file(Path(filename))) or fingerprint(filename) != saved:
                changed.append(filename)
        except FileNotFoundError:
            changed.append(filename)
        except (OSError, ValueError):
            unreadable.append(filename)
    if changed:
        return result("files", name, "fail", f"{len(changed)} added or changed files: " + ", ".join(changed[:8]))
    if unreadable:
        return result("files", name, "unknown", f"{len(unreadable)} files could not be verified: "
                      + ", ".join(unreadable[:8]))
    detail = f"{len(expected)} files match the trusted baseline."
    if hook_files <= expected.keys():
        detail += " The wsdd dpkg hook and both helper files match."
    return result("files", name, "pass", detail)


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
        sensors = store.sensor_status(db)
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
    checks = [
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
    try:
        data = wsdd_policy.manifest()
        issues = wsdd_policy.check_files(data)
        checks.append(result("wsdd-policy", "Wi-Fi discovery policy", "fail" if issues else "pass",
                             ". ".join(issues) if issues else
                             f"Launcher, diversion, and on-disk AppArmor rule match for {data['interface']}."))
    except FileNotFoundError:
        pass
    except PROBE_ERRORS:
        checks.append(result("wsdd-policy", "Wi-Fi discovery policy", "unknown",
                             "The installed policy could not be checked. Run the installer check as root."))
    return checks


LISTENER_INVENTORY_VERSION = 4
MAX_MULTICAST_PROBES = 256
SS_PROCESS = re.compile(r'\("([^"]+)",pid=(\d+),fd=(\d+)\)')
SS_CGROUP = re.compile(r"\bcgroup:(/\S*)")
SS_INODE = re.compile(r"\bino:(\d+)")
SS_COOKIE = re.compile(r"\bsk:([0-9a-fA-F]+)(?=\s|$)")
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


def multicast_details(inode, scope, options, addresses, indices):
    device = options.get("device") if options is not None else None
    receive_interface = (device or scope) if not (device and scope and device != scope) else None
    send = {}
    if options and (address := options.get("ipv4")):
        send["ipv4"] = {"address": address, "interface": listener_interface(
            ipaddress.ip_address(address), "", addresses, indices
        )}
    if options and (index := options.get("ipv4_index")):
        send["ipv4"] = {"index": index, "interface": indices.get(str(index))}
    if options and (index := options.get("ipv6")):
        send["ipv6"] = {"index": index, "interface": indices.get(str(index))}
    memberships = [
        {"family": family, "index": index, "interface": indices.get(str(index))}
        for family, index in sorted({tuple(pair) for pair in (options or {}).get("memberships", [])})
    ]
    return {"inode": inode, "receive_interface": receive_interface, "multicast_send": send,
            "multicast_memberships": memberships,
            "socket_options_source": (options or {}).get("source"), "socket_options_available": options is not None}


def listeners(output, allowed=(), rules=(), interfaces=None, helper=None):
    entries = {}
    apps = {}
    probes = 0
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
            "processes": {}, "services": set(), "interface": interface, "allowed": True, "sockets": [],
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
        match = SS_INODE.search(metadata)
        inode = int(match[1]) if match else None
        socket_apps = set()
        cookie = SS_COOKIE.search(metadata)
        options = (multicast.helper_options(helper, inode, cookie[1])
                   if protocol == "udp" and helper and cookie else None)
        for name, pid, fd in SS_PROCESS.findall(metadata):
            pid = int(pid)
            if pid not in apps:
                apps[pid] = process_app(name, pid, fd, inode)
            entry["processes"][pid] = {"pid": pid, "name": name, "app": apps[pid]}
            socket_apps.add(apps[pid])
            if protocol == "udp" and inode and options is None and probes < MAX_MULTICAST_PROBES:
                probes += 1
                options = multicast.socket_options(pid, int(fd), inode)
        receive_interface = listener_interface(None, scope, addresses, indices)
        if protocol == "udp":
            details = multicast_details(inode, receive_interface, options, addresses, indices)
            receive_interface = details["receive_interface"]
            entry["sockets"].append(details)
        if f"{protocol}/{port}" not in allowed and not any(
            matches_rule(rule, protocol, receive_interface, service, socket_apps) for rule in rules
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
        entries = listeners(output, set(allowed), rules, interface_lookup(), multicast.helper_snapshot())
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


def certificate_check(settings):
    audit = certificates.audit(settings.get("trusted_ca_sha256", ()), settings.get("blocked_ca_sha256", ()))
    detail = f'{audit["anchors"]} unique certificates across the system PEM bundle and hashed directory.'
    if audit["findings"]:
        detail += f' {len(audit["findings"])} certificates need review.'
        detail += " " + ", ".join(
            f'{row["sha256"][:16]} ({", ".join(row["issues"])})' for row in audit["findings"][:3]
        ) + "."
    if audit["package_errors"]:
        detail += f' {len(audit["package_errors"])} CA package files differ from readable package metadata.'
    if audit["coverage_errors"] or not audit["distribution_available"]:
        detail += " Trust-store coverage is incomplete."
    return {**result("certificates", "System certificate authorities", audit["status"], detail),
            "certificate_findings": audit["findings"][:25], "certificate_finding_count": len(audit["findings"])}


def hardening(settings):
    return [port_check(settings["allowed_listeners"], settings["allowed_listener_rules"]), ssh_check(), firewall_check(),
            *(kernel_check(key, minimum) for key, minimum in KERNEL_SETTINGS.items()), certificate_check(settings)]


def antivirus_readiness(now):
    try:
        output = subprocess.run(
            [CLAMSCAN, "--version"], capture_output=True, text=True, errors="replace", check=True,
            timeout=3, env={**os.environ, "LC_ALL": "C", "TZ": "UTC"},
        ).stdout.strip()
    except FileNotFoundError:
        return {"state": "missing-scanner"}
    except (OSError, subprocess.SubprocessError):
        return {"state": "unavailable"}
    engine, build, date = (output.split("/", 2) + ["", ""])[:3]
    if not engine.startswith("ClamAV "):
        return {"state": "unavailable"}
    if not build and not date:
        return {"state": "missing-signatures", "engine": engine}
    try:
        published = datetime.strptime(date, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return {"state": "unavailable", "engine": engine}
    state = "stale-signatures" if now - published > ANTIVIRUS_SIGNATURE_MAX_DAYS * 86400 else "ready"
    return {"state": state, "engine": engine, "signatures_at": published, "signature_version": build}


def antivirus_path(path, timeout):
    report = {"path": path, "status": "warn", "files_scanned": None, "scan_errors": 0,
              "access_errors": 0, "limit_hits": 0, "detections": 0}
    if timeout <= 0:
        return {**report, "detail": "Scan time limit reached before this path was scanned."}
    try:
        with tempfile.TemporaryFile() as output:
            scan = subprocess.run(
                [CLAMSCAN, "--suppress-ok-results", "--recursive", "--cross-fs=no", "--follow-dir-symlinks=0",
                 "--follow-file-symlinks=0", "--official-db-only=yes", "--alert-exceeds-max=yes",
                 f"--fail-if-cvd-older-than={ANTIVIRUS_SIGNATURE_MAX_DAYS}", "--", path],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=timeout,
                env={**os.environ, "LC_ALL": "C"},
            )
            size = output.seek(0, os.SEEK_END)
            output.seek(max(0, size - 4096))
            summary = output.read().decode("utf-8", errors="replace").rpartition("----------- SCAN SUMMARY -----------")[2]
            output.seek(0)
            findings = []
            detection_lines = 0
            diagnostic = ""
            for raw in output:
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                if line.endswith(" FOUND"):
                    signature = line.rpartition(": ")[2]
                    if signature.startswith(("Heuristics.Limits.Exceeded.", "Heuristics.Limits.Exceeded FOUND")):
                        report["limit_hits"] += 1
                    else:
                        detection_lines += 1
                        if len(findings) < 5:
                            findings.append(line[:512])
                elif line.endswith(("Access denied", "Permission denied", "Can't open directory.")):
                    report["access_errors"] += 1
                    if not diagnostic:
                        diagnostic = line[:300]
                elif not diagnostic and ("ERROR:" in line or line.startswith("WARNING:")):
                    diagnostic = line[:300]
    except FileNotFoundError:
        return {**report, "detail": "ClamAV was not found at /usr/bin/clamscan."}
    except subprocess.TimeoutExpired:
        return {**report, "detail": f"The scan exceeded {ANTIVIRUS_TIMEOUT // 60} minutes."}
    except OSError:
        return {**report, "detail": "Watchdog could not run ClamAV or collect its report."}

    fields = dict(re.findall(r"^(Scanned files|Infected files|Total errors): (\d+)$", summary, re.MULTILINE))
    scanned = int(fields["Scanned files"]) if "Scanned files" in fields else None
    errors = int(fields.get("Total errors", 0))
    limits = report["limit_hits"]
    reported = int(fields.get("Infected files", 0))
    # ClamAV versions differ in whether limit alerts count as infected files or scan errors.
    detections = 0
    if reported or scan.returncode == 1:
        detections = max(min(detection_lines, reported or 1), reported - limits,
                         int(scan.returncode == 1 and not limits))
    report.update(files_scanned=scanned, scan_errors=errors, detections=detections)
    if detections:
        detail = f"ClamAV reported {detections} infected files."
        if findings:
            detail += " " + " · ".join(findings)
        return {**report, "status": "fail", "detail": detail}
    if limits:
        detail = f"ClamAV reported {limits} file or archive limit hits."
        return {**report, "detail": detail}
    if scan.returncode != 0 or errors or report["access_errors"]:
        detail = f"ClamAV could not complete the scan (exit {scan.returncode})."
        return {**report, "detail": (detail + " " + diagnostic).rstrip()}
    if scanned is None:
        return {**report, "detail": "ClamAV did not provide a scan summary."}
    if not scanned:
        return {**report, "status": "skipped", "detail": "ClamAV did not scan any files in this path."}
    return {**report, "status": "pass", "detail": f"No malware reported across {scanned} scanned files."}


def antivirus(paths, *, daemon=None):
    deadline = time.monotonic() + ANTIVIRUS_TIMEOUT
    coverage = []
    fallback = None
    if daemon is not None:
        try:
            daemon.prepare(antivirus_readiness(time.time()), deadline)
        except (clamd_backend.ClamDError, OSError) as error:
            fallback = str(error)
    for path in paths:
        started = time.monotonic()
        remaining = timeout = deadline - started
        partial = None
        if daemon is not None and fallback is None:
            try:
                row = daemon.scan_path(path, deadline)
            except (clamd_backend.ClamDError, OSError) as error:
                fallback = str(error)
                partial = error.partial if isinstance(error, clamd_backend.ClamDError) else None
                timeout = deadline - time.monotonic()
        if daemon is None or fallback is not None:
            row = {**antivirus_path(path, timeout), "backend": "clamscan"}
            if partial is not None and row["status"] != "fail":
                row = {**partial, "detail": partial["detail"] + " The scan was interrupted after this detection."}
            if fallback:
                row["fallback"] = fallback
        coverage.append({**row, "duration_seconds": round(time.monotonic() - started, 3) if remaining > 0 else None})
    detections = [row for row in coverage if row["status"] == "fail"]
    incomplete = [row for row in coverage if row["status"] == "warn"]
    scanned = [row["files_scanned"] for row in coverage if row["files_scanned"] is not None]
    totals = {key: sum(row[key] for row in coverage) for key in ("scan_errors", "limit_hits", "access_errors")}
    if detections:
        status = "fail"
        detail = " · ".join(row["detail"] for row in detections[:5])
        if incomplete or any(totals.values()):
            detail += " Some files could not be scanned."
    elif incomplete:
        status = "warn"
        detail = incomplete[0]["detail"] if len(coverage) == 1 else f"ClamAV could not complete {len(incomplete)} scan paths."
    elif sum(scanned):
        status = "pass"
        detail = f"No malware reported across {sum(scanned)} scanned files."
    else:
        status = "skipped"
        detail = "ClamAV did not scan any files in the configured paths."
    return {**result("clamav", "ClamAV malware scan", status, detail), **totals,
            "files_scanned": sum(scanned) if scanned else None, "coverage": coverage}


def read(db, settings):
    saved = store.property_get(db, "system_checks", {})
    reports = {group: {**saved.get(group, {}), "interval_minutes": settings.get(key, default)}
               for group, (key, default) in GROUPS.items()}
    paths = settings.get("antivirus_paths")
    if not paths:
        del reports["antivirus"]
    elif reports["antivirus"].get("paths") != paths:
        reports["antivirus"] = {"interval_minutes": reports["antivirus"]["interval_minutes"]}
    return reports


def update_coverage_alerts(db, now, coverage):
    previous = store.property_get(db, "antivirus_coverage_incidents", {})
    current = {}
    for row in coverage:
        path = row["path"]
        count = previous.get(path, 0)
        if row.get("access_errors") or row.get("limit_hits") or row.get("scan_errors"):
            if count == 2:
                store.event(db, now, "medium", "antivirus-coverage", "Antivirus path coverage degraded",
                            "ClamAV reported access, scan, or file limits on three successive attempts.", path)
            current[path] = min(count + 1, 3)
        elif row["status"] in {"pass", "fail"} and (row.get("files_scanned") or 0) > 0:
            if count == 3:
                store.event(db, now, "info", "antivirus-coverage", "Antivirus path coverage recovered",
                            "ClamAV scanned files in this path without reporting access errors or limits.", path)
        elif count:
            # Unavailable scans and empty paths provide no evidence that coverage recovered.
            current[path] = count
    for path in previous.keys() - current.keys():
        db.execute("DELETE FROM email_outbox WHERE id IN (SELECT outbox_id FROM coverage_email WHERE path=?)", (path,))
    if current != previous:
        store.property_set(db, "antivirus_coverage_incidents", current)


def save(database, group, now, rows, *, paths=None):
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        saved = store.property_get(db, "system_checks", {})
        before = {row["id"]: row for row in saved.get(group, {}).get("checks", [])}
        for row in rows:
            if group == "antivirus":
                coverage = row.get("coverage", [])
                store.record_antivirus_paths(db, now, coverage)
                if coverage:
                    update_coverage_alerts(db, now, coverage)
            previous = before.get(row["id"], {})
            detection = group == "antivirus" and row["status"] == "fail"
            scope_changed = detection and paths != saved.get(group, {}).get("paths")
            if not scope_changed and (row["status"], row["detail"]) == (previous.get("status"), previous.get("detail")):
                continue
            if row["status"] in {"fail", "warn"}:
                severity = "high" if row["status"] == "fail" else "medium"
            elif row["status"] == "pass" and previous.get("status") in {"fail", "warn"}:
                severity = "info"
            else:
                continue
            title = "ClamAV detected malware" if detection else f'{row["name"]}: {row["status"]}'
            event_id = store.event(db, now, severity, "system-check", title, row["detail"], f'{group}/{row["id"]}')
            if detection and paths:
                reviews.record_scope(db, event_id, paths)
        if group == "hardening":
            for row in rows:
                if row["id"] == "ports" and "listeners" in row:
                    db.execute("INSERT INTO listener_inventory(at, listeners) VALUES (?, ?)",
                               (now, json.dumps(row["listeners"])))
        saved[group] = {"at": now, "boot_id": BOOT_ID, "checks": rows}
        if paths is not None:
            saved[group]["paths"] = paths
        store.property_set(db, "system_checks", saved)


def antivirus_next_at(report, now):
    at = report.get("at", 0)
    if report.get("boot_id") != BOOT_ID or not 0 < at <= now:
        return now
    interval = report["interval_minutes"] * 60
    if any(row["status"] == "warn" or row.get("scan_errors") or row.get("limit_hits") or
           any(path["status"] == "warn" for path in row.get("coverage", [])) for row in report["checks"]):
        interval = min(interval, ANTIVIRUS_RETRY_SECONDS)
    return at + interval


class AntivirusWorker:
    def __init__(self, monitor):
        self.monitor = monitor
        self.paths = monitor.settings["antivirus_paths"]
        self.lock = threading.Lock()
        self.requested = threading.Event()
        self.running = False
        self.readiness = {"state": "checking"}
        self.daemon = clamd_backend.ClamD() if monitor.settings.get("antivirus_clamd") else None

    def shutdown(self):
        if self.daemon is not None:
            self.daemon.close()

    def request(self):
        with self.lock:
            if self.running or self.requested.is_set():
                return False
            self.requested.set()
            return True

    def status(self, report, now):
        with self.lock:
            return {**report, "paths": self.paths, "readiness": self.readiness,
                    "running": self.running or self.requested.is_set(), "next_at": antivirus_next_at(report, now)}

    def scan_if_due(self):
        with store.connect(self.monitor.database) as db:
            report = read(db, self.monitor.settings)["antivirus"]
        now = time.time()
        with self.lock:
            if self.running or (not self.requested.is_set() and now < antivirus_next_at(report, now)):
                return
            self.running = True
            self.requested.clear()
        try:
            row = antivirus(self.paths, daemon=self.daemon) if self.daemon is not None else antivirus(self.paths)
            save(self.monitor.database, "antivirus", time.time(), [row], paths=self.paths)
        finally:
            with self.lock:
                self.running = False

    def run(self):
        next_probe = 0
        while not self.monitor.stop.is_set():
            if not self.monitor.ready.is_set():
                self.monitor.stop.wait(1)
                continue
            try:
                if time.monotonic() >= next_probe:
                    readiness = antivirus_readiness(time.time())
                    with self.lock:
                        self.readiness = readiness
                    next_probe = time.monotonic() + 60
                self.scan_if_due()
            except Exception:
                logging.exception("Antivirus check failed")
                self.monitor.stop.wait(5)
            self.requested.wait(5)


def run(monitor):
    collectors = (("health", lambda: health(monitor)), ("hardening", lambda: hardening(monitor.settings)))
    next_backup_check = 0
    next_feed_check = 0
    while not monitor.stop.wait(5):
        if not monitor.ready.is_set():
            continue
        try:
            if monitor.observe_directory is None and time.monotonic() >= next_backup_check:
                next_backup_check = time.monotonic() + 15
                try:
                    backup_health.refresh(monitor.database, time.time(), monitor.settings["backup_upload_max_hours"],
                                          monitor.settings["backup_drill_max_hours"],
                                          monitor.settings["backup_verifier_max_minutes"])
                except (OSError, ValueError):
                    logging.exception("Scheduled backup health check failed")
            if time.monotonic() >= next_feed_check:
                next_feed_check = time.monotonic() + 60
                try:
                    ecosystem = vulnerabilities.ubuntu_ecosystem(vulnerabilities.os_release())
                    has_manifest = (monitor.database.parent / "watchdog-advisories.json").is_file()
                    expected = ([ecosystem] if ecosystem else []) + (["kev"] if ecosystem or has_manifest else [])
                    vulnerabilities.check_feed_health(monitor.database, expected, time.time())
                except (OSError, ValueError):
                    logging.exception("Scheduled vulnerability feed health check failed")
            with store.connect(monitor.database) as db:
                saved = read(db, monitor.settings)
            for group, collect in collectors:
                previous = saved[group]
                elapsed = time.time() - previous.get("at", 0)
                outdated = group == "hardening" and any(
                    row["id"] == "ports" and row.get("inventory_version") != LISTENER_INVENTORY_VERSION
                    for row in previous.get("checks", [])
                )
                if group == "hardening" and not any(row["id"] == "certificates" for row in previous.get("checks", [])):
                    outdated = True
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
