"""Correlate running service mappings with fixed Ubuntu package versions."""
import json
import re
import time
from collections import defaultdict
from pathlib import Path

from . import runtime_processes, store
from .common import BOOT_ID

DPKG_STATUS = Path("/var/lib/dpkg/status")
DPKG_INFO = Path("/var/lib/dpkg/info")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?")
LIBRARY = re.compile(r"(.+\.so\.\d+)\.\d[0-9a-zA-Z.+~-]*")
MAX_PACKAGE_LIST_BYTES = 4 * 1024 * 1024
MAX_HISTORY_PATHS = runtime_processes.MAX_MAPPINGS
MAX_RELATIONS = 4096
MAX_REQUIRED = 32
MAX_AGE = 30 * 60
PROPERTY = "vulnerability_userspace"
SUMMARY_PROPERTY = "vulnerability_userspace_summary"


def package_stamp():
    info = DPKG_STATUS.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def file_owners(components, observed, directory):
    owners = defaultdict(dict)
    partial = set()
    for component in sorted(components):
        if not PACKAGE.fullmatch(component):
            partial.add(component)
            continue
        try:
            with (directory / (component + ".list")).open("rb") as stream:
                contents = stream.read(MAX_PACKAGE_LIST_BYTES + 1)
            if len(contents) > MAX_PACKAGE_LIST_BYTES:
                raise ValueError("Package file list exceeds the size limit")
            for path in contents.decode(errors="surrogateescape").splitlines():
                name = runtime_processes.package_path(path)
                if name not in observed:
                    continue
                try:
                    st = Path(path).stat()
                    identity = (st.st_dev, st.st_ino)
                except FileNotFoundError:
                    identity = None
                owners[name].setdefault(component, set()).add(identity)
        except (OSError, ValueError):
            partial.add(component)
    return owners, partial


def artifact(path):
    match = LIBRARY.fullmatch(path)
    return match[1] if match else path


def assess(snapshot, targets, installed, previous, info=DPKG_INFO):
    units = snapshot["units"]
    observed = {path for row in units.values() for path, _, _, _ in row["files"]}
    owners, partial = file_owners(targets.keys() & installed.keys(), observed, info)
    history = defaultdict(set)
    old_owners = defaultdict(set)
    history_size = 0
    limited = snapshot["limited"]
    for component, paths in previous.get("paths", {}).items():
        if component in targets:
            for path in paths:
                if history_size >= MAX_HISTORY_PATHS:
                    limited = True
                    break
                history[component].add(path)
                old_owners[path].add(component)
                history_size += 1

    observations = defaultdict(dict)
    relations = 0
    for unit, process in units.items():
        for path, dev, inode, deleted in process["files"]:
            current = owners.get(path, {})
            candidates = current.keys() or (old_owners.get(path, ()) if deleted else ())
            if len(candidates) != 1:
                continue
            component = next(iter(candidates))
            if path not in history[component]:
                if history_size < MAX_HISTORY_PATHS:
                    history[component].add(path)
                    history_size += 1
                else:
                    limited = True
            unit_rows = observations[component]
            if unit not in unit_rows:
                if relations >= MAX_RELATIONS:
                    limited = True
                    continue
                unit_rows[unit] = {"loaded": set(), "replaced": set(), "uncertain": False}
                relations += 1
            row = unit_rows[unit]
            if (dev, inode) in current.get(component, ()):
                row["loaded"].add(artifact(path))
            elif deleted:
                row["replaced"].add(path)
            else:
                row["uncertain"] = True

    packages = {}
    retained = 0
    for component in sorted(targets):
        expected_versions = targets[component]
        identity = installed.get(component)
        if not identity:
            continue
        prior = previous.get("packages", {}).get(component, {}).get("services", {})
        current = observations[component]
        for unit in sorted(prior.keys() | current.keys()):
            old = prior.get(unit, {})
            evidence = current.get(unit, {})
            loaded = evidence.get("loaded", set())
            replaced = evidence.get("replaced", set()) if identity in expected_versions else set()
            required = set(old.get("required", [])) | {artifact(path) for path in replaced}
            if unit not in current:
                if relations >= MAX_RELATIONS:
                    limited = True
                    continue
                relations += 1
            all_artifacts = required | loaded
            remaining = min(MAX_REQUIRED, max(0, MAX_HISTORY_PATHS - retained))
            truncated = bool(old.get("truncated") or len(all_artifacts) > remaining)
            if truncated:
                limited = True
            if replaced:
                state = "restart-required"
            elif (identity in expected_versions and loaded and required <= loaded and not truncated
                  and not evidence["uncertain"]
                  and component not in partial and not units[unit]["partial"]
                  and not snapshot["limited"] and not snapshot["unreadable"]):
                state = "active"
            else:
                state = "unverified"
            services = packages.setdefault(component, {"version": list(identity), "services": {}})["services"]
            saved_artifacts = sorted(all_artifacts)[:remaining]
            retained += len(saved_artifacts)
            services[unit] = {"status": state, "required": saved_artifacts,
                              "pending": bool(replaced or (old.get("pending") and state != "active")),
                              "replaced_paths": sorted(replaced)[:MAX_REQUIRED],
                              "truncated": truncated}
    return {"at": snapshot["at"], "boot_id": BOOT_ID, "packages": packages,
            "paths": {component: sorted(paths) for component, paths in history.items() if paths},
            "coverage": {"units": len(units), "limited": limited, "unreadable": snapshot["unreadable"],
                         "partial_units": sum(row["partial"] for row in units.values()),
                         "unreadable_packages": len(partial)}}


def snapshot(host):
    if not host:
        return runtime_processes.collect()
    with runtime_processes.SNAPSHOT.open("rb") as stream:
        payload = stream.read(runtime_processes.MAX_SNAPSHOT_BYTES + 1)
    if len(payload) > runtime_processes.MAX_SNAPSHOT_BYTES:
        raise ValueError("Service process snapshot exceeds the size limit")
    data = json.loads(payload)
    if data["boot_id"] != BOOT_ID or not 0 <= time.time() - data["at"] < runtime_processes.SNAPSHOT_MAX_AGE:
        raise ValueError("Service process snapshot is stale")
    return data


def fresh(saved, now):
    return saved.get("boot_id") == BOOT_ID and 0 <= now - saved["at"] < MAX_AGE


def overlay(report, saved):
    findings = {}
    for key, row in report.get("findings", {}).items():
        evidence = saved.get("packages", {}).get(row["component"])
        if (row.get("fix_verification") == "installed-runtime-unverified"
                and row["scope"] in {"os", "dependency"} and evidence
                and evidence["version"] == [row["installed"], row["comparison_version"]]):
            services = evidence["services"]
            states = {service["status"] for service in services.values()}
            verification = ("service-restart-required" if "restart-required" in states else
                            "service-runtime-unverified" if any(service["pending"] for service in services.values()) else
                            "userspace-active" if states == {"active"} else "installed-runtime-unverified")
            row = {**row, "fix_verification": verification, "service_verification": services}
        findings[key] = row
    return {**report, "findings": findings}


def check(database, *, host=False):
    from . import vulnerabilities

    with store.connect(database) as db:
        report = store.property_get(db, "vulnerabilities", {})
        previous = store.property_get(db, PROPERTY, {})
    targets = defaultdict(set)
    for row in report.get("findings", {}).values():
        if (row["source"].startswith("Ubuntu:") and row.get("fix_verification") in
                {"fix-not-installed", "installed-runtime-unverified"} and not vulnerabilities.kernel_release(row["component"])):
            targets[row["component"]].add((row["installed"], row["comparison_version"]))
    if not targets:
        return {"status": "no-tracked-packages"}
    stamp = package_stamp()
    installed = {binary: (version, source_version)
                 for group in vulnerabilities.package_inventory().values() for binary, source_version, version in group}
    data = snapshot(host)
    if data["at"] < stamp[3] / 1_000_000_000:
        raise ValueError("Package metadata changed after the process snapshot")
    result = assess(data, targets, installed, previous)
    result["coverage"]["scope"] = "host" if host else "user"
    if stamp != package_stamp():
        raise ValueError("Package metadata changed during service verification")
    combined = vulnerabilities.report_summary(overlay(report, result))
    result["report_at"] = report["started_at"]
    summary = {"at": result["at"], "boot_id": BOOT_ID, "report_at": result["report_at"],
               "coverage": result["coverage"], "vulnerabilities": combined}
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        latest = store.property_get(db, PROPERTY, {})
        if latest.get("boot_id") == BOOT_ID and latest["at"] >= result["at"]:
            raise ValueError("A newer service verification was already recorded")
        store.property_set(db, PROPERTY, result)
        store.property_set(db, SUMMARY_PROPERTY, summary)
    return {"status": "recorded", "at": result["at"], "coverage": result["coverage"],
            "findings": combined["fixes"], "service_findings": combined["service_findings"]}
