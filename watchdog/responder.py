import fcntl
import http.client
import json
import logging
import os
import pwd
import socket
import stat
import subprocess
import time
from contextlib import contextmanager

from .common import (
    BOOT_ID, MONITOR_RUNTIME, RESPONSE_RUNTIME, RESPONSE_STATE, blockable, execute, uptime, write_json,
)
from .sensors import IP

NFT = "/usr/sbin/nft"
TABLE = "ai_watchdog"
ERRORS = (OSError, ValueError, subprocess.SubprocessError)


def ruleset(blocks, isolated, macs=()):
    text = [f"destroy table inet {TABLE}"]
    if not blocks and not isolated and not macs:
        return text[0] + "\n"
    text.append(f"table inet {TABLE} {{")
    if isolated:
        blocks = {}
    for family, address_type, set_name in (("ip", "ipv4_addr", "blocked4"), ("ip6", "ipv6_addr", "blocked6")):
        entries = [f"{address} timeout {seconds}s" for address, seconds in blocks.items()
                   if (":" in address) == (family == "ip6")]
        if entries:
            text.append(f"set {set_name} {{ type {address_type}; flags timeout; "
                        + "elements = { " + ", ".join(entries) + " }; }")
    for hook, directions in (("input", ("saddr",)), ("output", ("daddr",)), ("forward", ("saddr", "daddr"))):
        text.append(f"chain {hook} {{ type filter hook {hook} priority -10; policy accept;")
        if isolated:
            if hook == "forward":
                text.append("counter drop")
            else:
                interface = "iifname" if hook == "input" else "oifname"
                text.append(f'{interface} != "lo" counter drop')
        else:
            if hook in {"input", "forward"}:
                for mac in macs:
                    text.append(f"ether saddr {mac} counter drop")
            for family, set_name in (("ip", "blocked4"), ("ip6", "blocked6")):
                if any((":" in address) == (family == "ip6") for address in blocks):
                    for direction in directions:
                        text.append(f"{family} {direction} @{set_name} counter drop")
        text.append("}")
    text.append("}")
    return "\n".join(text) + "\n"


def apply_firewall(blocks, isolated, macs=()):
    execute(NFT, "-f", "-", input_text=ruleset(blocks, isolated, macs))


def notify(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(message.encode(), address)


def heartbeat(uid, now, settings, runtime=None):
    fd = os.open((runtime or MONITOR_RUNTIME) / "heartbeat.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or not 0 < info.st_size <= 8192:
            raise ValueError("Invalid heartbeat file")
        payload = json.loads(stream.read(8193))
    if not isinstance(payload, dict):
        raise ValueError("Invalid heartbeat")
    at = payload.get("at")
    if (
        payload.get("boot_id") != BOOT_ID or type(at) not in (int, float)
        or not now - settings["heartbeat_timeout"] < at <= now
        or type(payload.get("isolate")) is not bool
        or not isinstance(payload.get("blocks"), dict) or len(payload["blocks"]) > 64
    ):
        raise ValueError("Invalid or expired heartbeat")
    return payload


def dashboard_alive(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        return response.status == 200 and response.read(16) == b"ok\n"
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def links():
    return json.loads(execute(IP, "-j", "link", "show"))


def protected_addresses():
    own = json.loads(execute(IP, "-j", "address", "show"))
    defaults = []
    for family in ("-4", "-6"):
        defaults.extend(json.loads(execute(IP, family, "-j", "route", "show", "table", "all", "default")))
    addresses = {entry["local"] for interface in own for entry in interface.get("addr_info", [])}
    for route in defaults:
        addresses.update(item["gateway"] for item in route.get("nexthops", []) if "gateway" in item)
        if "gateway" in route:
            addresses.add(route["gateway"])
    return addresses


@contextmanager
def exclusive():
    with (RESPONSE_STATE / "lock").open("a") as file:
        fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def load_latch():
    try:
        return json.loads((RESPONSE_STATE / "isolation.json").read_text())
    except FileNotFoundError:
        return None
    except (ValueError, RecursionError):
        return {"reason": "Containment state is unreadable", "boot_id": BOOT_ID, "links": {}}


def persist_latch(state):
    write_json(RESPONSE_STATE / "isolation.json", state)
    # Keep the latch across an unexpected reboot after containment.
    fd = os.open(RESPONSE_STATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def isolate_links(state):
    errors = []
    if state["boot_id"] != BOOT_ID:
        state.update(boot_id=BOOT_ID, links={})
    for link in links():
        if link["ifname"] == "lo" or "UP" not in link.get("flags", []):
            continue
        key = str(link["ifindex"])
        try:
            if state["links"].get(key) != link["ifname"]:
                state["links"][key] = link["ifname"]
                persist_latch(state)
            execute(IP, "link", "set", "dev", link["ifname"], "down")
        except ERRORS as error:
            errors.append(f'{link["ifname"]}: {type(error).__name__}')
    return errors


def recover():
    with exclusive():
        state = load_latch()
        if state and state["boot_id"] == BOOT_ID:
            for link in links():
                if state["links"].get(str(link["ifindex"])) == link["ifname"] and "UP" not in link.get("flags", []):
                    execute(IP, "link", "set", "dev", link["ifname"], "up")
        apply_firewall({}, False)
        (RESPONSE_STATE / "isolation.json").unlink(missing_ok=True)
        (RESPONSE_STATE / "watchdog-boot.json").unlink(missing_ok=True)
        (RESPONSE_RUNTIME / "status.json").unlink(missing_ok=True)


def supervise(settings):
    with exclusive():
        loop(settings)


def loop(settings, user_directory=None):
    user_observe = user_directory is not None
    enforce = settings["enforce"] and not user_observe
    response_state = user_directory / "response" if user_observe else RESPONSE_STATE
    response_runtime = response_state if user_observe else RESPONSE_RUNTIME
    uid = os.getuid() if user_observe else pwd.getpwnam("ai-watchdog").pw_uid
    started = uptime()
    last_responsive = None
    previous_status = None
    # Anchor the first startup grace to this boot, including across responder restarts.
    marker = response_state / "watchdog-boot.json"
    try:
        previous = json.loads(marker.read_text())
        if previous["boot_id"] == BOOT_ID:
            started = previous["started"]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    write_json(marker, {"boot_id": BOOT_ID, "started": started})
    grace = settings["startup_grace"]
    state = None if user_observe else load_latch()
    firewall_state = None
    failed_blocks = 0
    persisted = state is not None
    macs = tuple(settings["blocked_macs"]) if enforce else ()
    notify("READY=1")
    while True:
        now = uptime()
        reason = ""
        blocks = {}
        failures = []
        try:
            request = heartbeat(uid, now, settings, runtime=user_directory)
        except (OSError, ValueError, RecursionError):
            request = None
        responsive = request is not None and dashboard_alive(settings["port"])
        if responsive:
            last_responsive = now
        elif request is None and last_responsive is not None:
            # A stale monitor heartbeat has already missed the full timeout.
            reason = "Monitoring heartbeat expired"
        elif (last_responsive is None and now - started >= grace) or (
            last_responsive is not None and now - last_responsive >= settings["heartbeat_timeout"]
        ):
            reason = "Monitoring service stopped responding"
        if request and request["isolate"]:
            reason = reason or "Repeated change to an isolation-critical file"

        if reason and enforce and state is None:
            state = {"reason": reason, "boot_id": BOOT_ID, "links": {}}
        if state:
            reason = state["reason"]
            if not persisted:
                try:
                    persist_latch(state)
                    persisted = True
                except OSError as error:
                    failures.append("Isolation latch: " + type(error).__name__)

        if enforce and request and not state:
            eligible = {
                canonical: max(1, int(expiry - now)) for address, expiry in request["blocks"].items()
                if type(expiry) in (int, float) and now < expiry <= now + 905
                and (canonical := blockable(address, settings["protected_networks"]))
            }
            if eligible:
                try:
                    protected = protected_addresses()
                    blocks = {address: eligible[address] for address in sorted(set(eligible) - protected)}
                except ERRORS as error:
                    failures.append("Protected address inventory: " + type(error).__name__)

        if enforce or state:
            desired = (tuple(blocks), bool(state), macs)
            try:
                # Reassert nonempty rules after firewall reloads without altering any unrelated table.
                if desired != firewall_state or any(desired):
                    apply_firewall(blocks, bool(state), macs)
                    firewall_state = desired
                failed_blocks = 0
            except ERRORS as error:
                firewall_state = None
                failures.append("Firewall: " + type(error).__name__)
                failed_blocks = failed_blocks + 1 if blocks and not state else 0
                if failed_blocks >= 3:
                    reason = "Repeated firewall failure while mitigating SSH abuse"
                    state = {"reason": reason, "boot_id": BOOT_ID, "links": {}}
                    try:
                        persist_latch(state)
                        persisted = True
                    except OSError as persistence_error:
                        failures.append("Isolation latch: " + type(persistence_error).__name__)
        if state:
            try:
                failures.extend(isolate_links(state))
            except ERRORS as error:
                failures.append("Link isolation: " + type(error).__name__)

        status = "failed" if failures else (
            "isolated" if state else "would-isolate" if reason else "observing" if responsive else "starting"
        )
        signature = (status, reason, tuple(failures), firewall_state)
        if signature != previous_status:
            logging.log(logging.CRITICAL if failures or reason else logging.INFO,
                        "Containment %s. %s %s", status, reason, " ".join(failures))
            previous_status = signature
        write_json(response_runtime / "status.json", {
            "boot_id": BOOT_ID, "at": uptime(), "mode": "enforce" if enforce else "observe",
            "status": status, "isolated": bool(state) and not failures,
            "blocked": [*blocks, *macs] if firewall_state == (tuple(blocks), False, macs) else [],
            "reason": " ".join([part for part in [reason, *failures] if part]),
        }, mode=0o644)
        notify("WATCHDOG=1")
        time.sleep(5)
