import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

CONFIG = Path("/etc/ai-watchdog/config.json")
BASELINE = Path("/etc/ai-watchdog/baseline.json")
MONITOR_RUNTIME = Path("/run/ai-watchdog")
RESPONSE_RUNTIME = Path("/run/ai-watchdog-response")
RESPONSE_STATE = Path("/var/lib/ai-watchdog-response")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
DEFAULTS = {
    "port": 8765,
    "interval": 10,
    "heartbeat_timeout": 45,
    "startup_grace": 90,
    "enforce": False,
    "protected_networks": [],
    "blocked_macs": [],
    "integrity_paths": ["/etc/passwd", "/etc/group", "/etc/ld.so.preload"],
    "isolate_on_integrity": [],
    "ollama_model": "",
    "retention_days": 30,
    "email_alerts": None,
    "health_check_minutes": 5,
    "backup_upload_max_hours": 26,
    "hardening_check_minutes": 60,
    "antivirus_paths": [],
    "antivirus_check_minutes": 1440,
    "antivirus_clamd": False,
    "allowed_listeners": [],
    "allowed_listener_rules": [],
}


def uptime():
    return time.monotonic()


def configuration(path=CONFIG):
    settings = DEFAULTS.copy()
    if path.exists():
        user_config = json.loads(path.read_text())
        if not isinstance(user_config, dict) or set(user_config) - set(settings):
            raise ValueError("Unknown configuration keys")
        settings.update(user_config)
    for key, low, high in (
        ("port", 1024, 65535), ("interval", 5, 30), ("heartbeat_timeout", 30, 300),
        ("startup_grace", 10, 600), ("retention_days", 1, 365),
        ("health_check_minutes", 1, 10080), ("hardening_check_minutes", 1, 10080),
        ("backup_upload_max_hours", 2, 720),
        ("antivirus_check_minutes", 5, 10080),
    ):
        if type(settings[key]) is not int or not low <= settings[key] <= high:
            raise ValueError(f"Invalid {key}")
    if settings["heartbeat_timeout"] < 3 * settings["interval"]:
        raise ValueError("heartbeat_timeout must cover at least three scans")
    if type(settings["enforce"]) is not bool:
        raise ValueError("enforce must be a boolean")
    if type(settings["antivirus_clamd"]) is not bool:
        raise ValueError("antivirus_clamd must be a boolean")
    listeners = settings["allowed_listeners"]
    if not isinstance(listeners, list) or len(listeners) > 256 or any(
        not isinstance(item, str) or not re.fullmatch(r"(?:tcp|udp)/[1-9][0-9]{0,4}", item)
        or int(item.split("/", 1)[1]) > 65535 for item in listeners
    ):
        raise ValueError("allowed_listeners must contain entries such as tcp/22 or udp/5353")
    settings["allowed_listeners"] = sorted(set(listeners))
    rules = settings["allowed_listener_rules"]
    if not isinstance(rules, list) or len(rules) > 256:
        raise ValueError("allowed_listener_rules must be a list of service and interface rules")
    for rule in rules:
        if (not isinstance(rule, dict) or not {"service", "interface"} <= rule.keys()
                or rule.keys() - {"service", "interface", "app", "protocol"}
                or any(not isinstance(value, str) for value in rule.values())
                or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,200}\.(?:service|scope)", rule["service"])
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", rule["interface"])
                or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,100}", rule.get("app", "any"))
                or rule.get("protocol", "udp") not in {"tcp", "udp"}):
            raise ValueError("Invalid allowed_listener_rules entry")
    for key in ("integrity_paths", "isolate_on_integrity", "protected_networks", "blocked_macs"):
        items = settings[key]
        if not isinstance(items, list) or len(items) > 64 or not all(
            isinstance(item, str) and 0 < len(item) <= 256 for item in items
        ):
            raise ValueError(f"Invalid {key}")
    if any(not Path(path).is_absolute() for path in settings["integrity_paths"]):
        raise ValueError("Integrity paths must be absolute")
    paths = settings["antivirus_paths"]
    if not isinstance(paths, list) or len(paths) > 64 or any(
        not isinstance(path, str) or not 0 < len(path) <= 4096 or not Path(path).is_absolute()
        or "\x00" in path
        for path in paths
    ):
        raise ValueError("antivirus_paths must be a list of absolute file or directory paths")
    settings["antivirus_paths"] = sorted(set(paths))
    if set(settings["isolate_on_integrity"]) - set(settings["integrity_paths"]):
        raise ValueError("Isolation paths must be included in integrity_paths")
    settings["protected_networks"] = [
        ipaddress.ip_network(network) for network in settings["protected_networks"]
    ]
    if any(not re.fullmatch(r"(?:[a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}", mac)
           for mac in settings["blocked_macs"]):
        raise ValueError("Invalid blocked_macs")
    settings["blocked_macs"] = sorted({mac.lower() for mac in settings["blocked_macs"]})
    model = settings["ollama_model"]
    if not isinstance(model, str) or (model and not re.fullmatch(r"[\w./:-]{1,100}", model, re.ASCII)):
        raise ValueError("Invalid ollama_model")
    from .notifications import configuration as email_configuration

    settings["email_alerts"] = email_configuration(settings["email_alerts"], path.parent.absolute())
    return settings


def write_json(path, value, mode=0o600):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
        try:
            os.fchmod(output.fileno(), mode)
            output.write(json.dumps(value, allow_nan=False).encode())
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def execute(*arguments, input_text=None, timeout=3):
    return subprocess.run(arguments, input=input_text, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, text=True, check=True).stdout


def blockable(value, protected):
    try:
        address = ipaddress.ip_address(value)
        if address.version == 6 and (address.scope_id or address.ipv4_mapped):
            return None
    except (TypeError, ValueError):
        return None
    if (
        not address.is_global or address.is_multicast or address.is_reserved
        or any(address in network for network in protected)
    ):
        return None
    return str(address)
