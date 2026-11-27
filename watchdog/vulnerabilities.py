"""Match vendor advisories to local inventory and retain unresolved exposure."""
import fcntl
import functools
import http.client
import io
import json
import lzma
import platform
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from urllib.request import urlopen

from . import __version__, store
from .common import BOOT_ID

UBUNTU_FEED = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
KEV_FEED = ("https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/"
            "known_exploited_vulnerabilities.json")
STALE_AFTER = 48 * 3600
KEV_LIMIT = 8 * 1024 * 1024
UBUNTU_MEMBER = re.compile(r"osv/cve/\d{4}/UBUNTU-(CVE-\d{4}-\d{4,})\.json")
ADVISORY_ID = re.compile(r"(?:CVE-\d{4}-\d{4,}|WD-[0-9]{4}-[0-9]{3,})")
KERNEL_RELEASE = re.compile(r"(\d+\.\d+\.\d+-\d+)-([a-z0-9-]+)")
KERNEL_PACKAGE = re.compile(r"linux-(?:image(?:-unsigned)?|modules(?:-extra)?)-(.+)")
DEPENDENCIES = {"bpftrace", "iproute2", "nftables", "systemd", "python3-defaults",
                f"python{sys.version_info.major}.{sys.version_info.minor}", "ollama"}
LIMIT = 256 * 1024 * 1024


def os_release():
    fields = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        name, separator, raw = line.partition("=")
        if separator and name in {"ID", "VERSION_ID", "VERSION", "VERSION_CODENAME"}:
            parsed = shlex.split(raw)
            fields[name] = parsed[0] if len(parsed) == 1 else ""
    return fields


def ubuntu_ecosystem(release):
    if release.get("ID") != "ubuntu" or not re.fullmatch(r"\d{2}\.\d{2}", release.get("VERSION_ID", "")):
        return None
    version = release["VERSION_ID"]
    return f"Ubuntu:{version}" + (":LTS" if "LTS" in release.get("VERSION", "") else "")


def command(*args):
    return subprocess.check_output(args, text=True, timeout=20, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})


def package_inventory():
    out = command("/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}\t${binary:Package}\t"
                  "${source:Package}\t${source:Version}\t${Version}\n")
    packages = defaultdict(list)
    for line in out.splitlines():
        status, binary, source, source_version, binary_version = line.split("\t")
        if status == "installed" and source and source_version and binary_version:
            packages[source].append((binary, source_version, binary_version))
    return packages


def kernel_release(binary):
    match = KERNEL_PACKAGE.fullmatch(binary.partition(":")[0])
    return match[1] if match and KERNEL_RELEASE.fullmatch(match[1]) else None


def running_kernel(release):
    match = KERNEL_RELEASE.fullmatch(release)
    if match:
        try:
            vendor, build, _ = Path("/proc/version_signature").read_text().split()
        except (OSError, ValueError):
            return None
        suffix = "-" + match[2]
        version = build.removesuffix(suffix)
        if vendor == "Ubuntu" and build.endswith(suffix) and version.startswith(match[1] + "."):
            return version
    return None


def verify_kernel(row, packages, images, history, release, build, ranges):
    running = KERNEL_RELEASE.fullmatch(release)
    target = KERNEL_RELEASE.fullmatch(kernel_release(row["component"]))
    if not build or not running or target[2] != running[2]:
        return "runtime-unverified"
    current_versions = {version for binary, version, _ in packages if kernel_release(binary) == release}
    if not current_versions and not any(kernel_release(old["component"]) == release for old in history):
        return "runtime-unverified"
    affected = any(evaluate_range(build, events)[0] for events in ranges)
    if not affected and build in current_versions and version_compare(build, row["fixed"]) >= 0:
        return "active"
    if affected:
        for binary, version, _ in packages:
            candidate = kernel_release(binary)
            if ((candidate, version) in images and KERNEL_RELEASE.fullmatch(candidate)[2] == running[2]
                    and version_compare(version, row["fixed"]) >= 0
                    and not any(evaluate_range(version, events)[0] for events in ranges)):
                return "reboot-required"
        return "running-affected"
    return "runtime-unverified" if row["status"] != "affected" else "fix-not-installed"


@functools.cache
def apt_comparator():
    try:
        import apt_pkg
    except ImportError:
        return None
    apt_pkg.init()
    return apt_pkg.version_compare


@functools.lru_cache(maxsize=32768)
def version_compare(left, right):
    # Debian version ordering accounts for epochs and Ubuntu backports.
    compare = apt_comparator()
    if compare:
        return compare(left, right)
    for operation, number in (("lt", -1), ("gt", 1)):
        result = subprocess.run(["/usr/bin/dpkg", "--compare-versions", left, operation, right],
                                capture_output=True, timeout=5, check=False)
        if result.returncode == 0:
            return number
        if result.returncode != 1:
            raise ValueError("Invalid Debian version")
    return 0


def evaluate_range(version, events):
    """Return (affected, fixed_version) for supported OSV ECOSYSTEM events."""
    start = None
    for event in events:
        if len(event) != 1:
            raise ValueError("Invalid advisory range event")
        kind, bound = next(iter(event.items()))
        if not isinstance(bound, str) or not 0 < len(bound) <= 256:
            raise ValueError("Invalid advisory version")
        if kind == "introduced" and start is None:
            start = bound
            continue
        if start is None or kind not in {"fixed", "limit", "last_affected"}:
            raise ValueError("Unsupported advisory range event")
        relation = version_compare(version, bound)
        if (start == "0" or version_compare(version, start) >= 0) and (
            relation < 0 or (relation == 0 and kind == "last_affected")
        ):
            return True, bound if kind == "fixed" else None
        start = None
    return start is not None and (start == "0" or version_compare(version, start) >= 0), None


def ubuntu_records(archive):
    if archive.stat().st_size > LIMIT:
        raise ValueError("Ubuntu advisory archive exceeds the compressed size limit")
    count = 0
    content_size = 0
    with lzma.open(archive) as source, tarfile.open(fileobj=source, mode="r|", bufsize=256 * 1024) as bundle:
        while member := bundle.next():
            # Older Python versions still cache member metadata in streaming mode.
            bundle.members.clear()
            content_size += member.size
            if content_size > 24 * 1024 * 1024 * 1024:
                raise ValueError("Ubuntu advisory archive exceeds the expanded size limit")
            match = UBUNTU_MEMBER.fullmatch(member.name.removeprefix("./"))
            if not match:
                continue
            if not member.isfile() or member.size > 32 * 1024 * 1024:
                raise ValueError(f"Invalid Ubuntu CVE archive member: {match[1]} ({member.size} bytes)")
            record = json.load(bundle.extractfile(member))
            if record["id"] != "UBUNTU-" + match[1]:
                raise ValueError("Ubuntu advisory ID does not match its archive entry")
            count += 1
            yield match[1], record
    if count == 0:
        raise ValueError("Ubuntu advisory archive contains no CVE records")


def ubuntu_findings(archive, ecosystem, packages, existing, release, build):
    findings = {}
    release_present = False
    history = defaultdict(list)
    for row in existing.values():
        if row["source"] == ecosystem and kernel_release(row["component"]):
            history[row["advisory"], row["source_package"]].append(row)
    images = {(kernel_release(binary), version) for group in packages.values() for binary, _, version in group
              if binary.startswith("linux-image-") and kernel_release(binary)}
    for advisory, record in ubuntu_records(archive):
        for entry in record.get("affected", []):
            package = entry["package"]
            if package["ecosystem"] != ecosystem:
                continue
            release_present = True
            source = package["name"]
            older_kernels = history.get((advisory, source), ())
            if record.get("withdrawn") or (source not in packages and not older_kernels):
                continue
            ranges = [item["events"] for item in entry.get("ranges", []) if item["type"] == "ECOSYSTEM"]
            if not ranges:
                continue
            severity = next((s["score"] for s in record.get("severity", []) if s["type"] == "Ubuntu"), "unknown")
            installed = packages.get(source, ())
            for binary, source_version, binary_version in installed:
                matches = [fix for affected, fix in (evaluate_range(source_version, r) for r in ranges) if affected]
                running_matches = ([fix for affected, fix in (evaluate_range(build, r) for r in ranges) if affected]
                                   if build and kernel_release(binary) == release else [])
                key = f"{ecosystem}/{advisory}/{binary}"
                previous = findings.get(key)
                if previous and previous["status"] in {"affected", "vendor-listed"}:
                    matches.append(previous["fixed"])
                if not matches and not running_matches and key not in existing:
                    continue
                fixed = existing.get(key, {}).get("fixed") if not matches else None
                if not matches and running_matches and all(running_matches):
                    fixed = max(running_matches, key=functools.cmp_to_key(version_compare))
                if matches and all(matches):
                    fixed = max(matches, key=functools.cmp_to_key(version_compare))
                status = ("affected" if fixed else "vendor-listed") if matches else "outside-affected-range"
                findings[key] = {
                    "advisory": advisory, "component": binary, "source_package": source,
                    "scope": "dependency" if source in DEPENDENCIES or binary.split(":")[0] in DEPENDENCIES else "os",
                    "installed": binary_version, "comparison_version": source_version,
                    "fixed": fixed, "severity": severity, "status": status,
                    "reference": f"https://ubuntu.com/security/{advisory}", "source": ecosystem,
                }
                if fixed:
                    row = findings[key]
                    if kernel_release(binary):
                        row["fix_verification"] = verify_kernel(row, installed, images, older_kernels,
                                                                release, build, ranges)
                    else:
                        row["fix_verification"] = installed_fix(row)
                elif running_matches:
                    findings[key]["fix_verification"] = "running-affected"
            installed_binaries = {binary for binary, _, _ in installed} if older_kernels else ()
            for old in older_kernels:
                if old["component"] in installed_binaries or not old["fixed"]:
                    continue
                row = {**old, "status": "removed"}
                row["fix_verification"] = verify_kernel(row, installed, images, older_kernels, release, build, ranges)
                findings[f'{ecosystem}/{advisory}/{row["component"]}'] = row
    if not release_present:
        raise ValueError(f"Ubuntu archive contains no records for {ecosystem}")
    return findings


def installed_fix(row):
    if row["status"] == "affected":
        return "fix-not-installed"
    if row["fixed"] and version_compare(row["comparison_version"], row["fixed"]) >= 0:
        return "installed-runtime-unverified"
    return "runtime-unverified"


def read_local_json(path):
    with path.open("rb") as source:
        data = source.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("Local vulnerability data exceeds the size limit")
    return json.loads(data)


def watchdog_findings(manifest, existing):
    findings = {}
    for record in manifest["advisories"]:
        advisory = record["id"]
        if not ADVISORY_ID.fullmatch(advisory):
            raise ValueError("Invalid Watchdog advisory ID")
        affected, fixed = evaluate_range(__version__, record["events"])
        key = f"watchdog/{advisory}"
        if affected or key in existing:
            findings[key] = {
                "advisory": advisory, "component": "ai-watchdog", "scope": "watchdog",
                "installed": __version__, "comparison_version": __version__,
                "fixed": fixed if affected else existing[key]["fixed"],
                "severity": record.get("severity", "unknown"), "source": "watchdog",
                "status": ("affected" if fixed else "vendor-listed") if affected else "outside-affected-range",
            }
            if findings[key]["fixed"]:
                findings[key]["fix_verification"] = installed_fix(findings[key])
    candidate = manifest.get("available_version")
    if candidate is not None and (not isinstance(candidate, str) or not 0 < len(candidate) <= 256):
        raise ValueError("Invalid Watchdog release version")
    return findings, candidate


def download(url, output, limit):
    with urlopen(url, timeout=30) as response:
        if response.geturl() != url:
            raise ValueError("Unexpected advisory download URL")
        deadline = time.monotonic() + 180
        total = 0
        while chunk := response.read1(1024 * 1024):
            total += len(chunk)
            if total > limit or time.monotonic() > deadline:
                raise ValueError("Advisory download exceeded size or time limit")
            output.write(chunk)


def download_archive(path):
    with path.open("wb") as output:
        download(UBUNTU_FEED, output, LIMIT)


def kev_catalog(path):
    if path is not None:
        with path.open("rb") as source:
            payload = source.read(KEV_LIMIT + 1)
        if len(payload) > KEV_LIMIT:
            raise ValueError("CISA KEV catalog exceeds the size limit")
    else:
        with io.BytesIO() as output:
            download(KEV_FEED, output, KEV_LIMIT)
            payload = output.getvalue()
    data = json.loads(payload)
    entries = data["vulnerabilities"]
    if not isinstance(entries, list) or not entries or data["count"] != len(entries):
        raise ValueError("Invalid CISA KEV catalog size")
    ids = {entry["cveID"] for entry in entries}
    if len(ids) != len(entries) or any(not re.fullmatch(r"CVE-\d{4}-\d{4,19}", cve) for cve in ids):
        raise ValueError("Invalid CISA KEV catalog CVE IDs")
    return sorted(ids)


def refresh(database, *, archive=None, manifest=None, kev_path=None):
    with database.with_suffix(".vulnerability.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("A vulnerability refresh is already running") from error
        return refresh_locked(database, archive, manifest, kev_path)


def refresh_locked(database, archive, manifest, kev_path):
    started = time.time()
    with store.connect(database) as db:
        previous = store.property_get(db, "vulnerabilities", {})
    existing = previous.get("findings", {})
    sources = dict(previous.get("sources", {}))
    current = {}
    checked = set()
    release = os_release()
    ecosystem = ubuntu_ecosystem(release)
    kernel = platform.release()
    kernel_build = running_kernel(kernel) if ecosystem else None
    kernel_check = previous.get("kernel_check", {})
    kev_ids = previous.get("kev_ids", [])
    packages = None
    errors = []
    if ecosystem:
        try:
            packages = package_inventory()
            with tempfile.TemporaryDirectory(prefix="watchdog-cve-") as directory:
                local_archive = archive
                if archive is None:
                    local_archive = Path(directory) / "ubuntu.tar.xz"
                    download_archive(local_archive)
                current.update(ubuntu_findings(local_archive, ecosystem, packages, existing, kernel, kernel_build))
            checked.add(ecosystem)
            sources[ecosystem] = source_result(sources, ecosystem, started, UBUNTU_FEED, local=archive is not None)
            sources.pop("os", None)
            kernel_check = {"release": kernel, "build": kernel_build, "boot_id": BOOT_ID}
        except (OSError, EOFError, ValueError, KeyError, TypeError, RecursionError, http.client.HTTPException,
                lzma.LZMAError, tarfile.TarError, subprocess.SubprocessError) as error:
            sources[ecosystem] = {**sources.get(ecosystem, {}), "status": "failed", "attempted_at": started}
            errors.append(f"Ubuntu advisory lookup failed: {error}")
    else:
        sources["os"] = {"status": "unsupported-os", "attempted_at": started}
    if kev_path is not None or (archive is None and (ecosystem or manifest)):
        try:
            kev_ids = kev_catalog(kev_path)
            sources["kev"] = source_result(sources, "kev", started, KEV_FEED, local=kev_path is not None)
        except (OSError, ValueError, KeyError, TypeError, RecursionError, http.client.HTTPException) as error:
            sources["kev"] = {**sources.get("kev", {}), "status": "failed", "attempted_at": started,
                              "reference": KEV_FEED}
            errors.append(f"CISA KEV lookup failed: {error}")
    candidate = None
    if manifest:
        try:
            results, candidate = watchdog_findings(read_local_json(manifest), existing)
            current.update(results)
            checked.add("watchdog")
            sources["watchdog"] = {"status": "ready", "checked_at": started}
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            sources["watchdog"] = {**sources.get("watchdog", {}), "status": "failed", "attempted_at": started}
            errors.append(f"Watchdog advisory lookup failed: {error}")
    else:
        sources["watchdog"] = {"status": "unconfigured", "attempted_at": started}
    binaries = {binary for group in (packages or {}).values() for binary, _, _ in group}
    for key, old in existing.items():
        if key in current:
            continue
        if old["source"] in checked:
            status = "unverified"
            if old["source"] == ecosystem and old["component"] not in binaries:
                status = "removed"
            current[key] = {field: value for field, value in old.items() if field != "fix_verification"}
            current[key]["status"] = status
        elif old["source"] != ecosystem and old["source"] != "watchdog":
            current[key] = {field: value for field, value in old.items() if field != "fix_verification"}
            current[key]["status"] = "unverified"
        else:
            current[key] = old
    exploited = set(kev_ids)
    for key, finding in current.items():
        finding["first_seen"] = existing.get(key, {}).get("first_seen", started)
        if finding["source"] in checked:
            finding["checked_at"] = started
        if finding["advisory"] in exploited:
            finding["known_exploited"] = True
        else:
            finding.pop("known_exploited", None)
    report = {"started_at": started, "os": release, "kernel_check": kernel_check,
              "running_kernel": kernel, "running_kernel_build": kernel_build,
              "sources": sources, "kev_ids": kev_ids, "findings": current, "watchdog_version": __version__,
              "watchdog_candidate": candidate, "errors": errors}
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        store.property_set(db, "vulnerabilities", report)
        store.property_set(db, "vulnerability_summary", report_summary(report))
    return report


def unresolved(report):
    return [row for row in report.get("findings", {}).values()
            if (row["status"] in {"affected", "vendor-listed", "unverified"}
                or row.get("fix_verification") in {"reboot-required", "running-affected"})]


def select_findings(report, *, include_all=False, advisory=None, scope=None):
    rows = list(report.get("findings", {}).values()) if include_all else unresolved(report)
    statuses = {"affected": 0, "vendor-listed": 1, "unverified": 2}
    severities = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(
        (row for row in rows if (not advisory or row["advisory"] == advisory) and (not scope or row["scope"] == scope)),
        key=lambda row: (not row.get("known_exploited"), statuses.get(row["status"], 3),
                         severities.get(row["severity"], 4),
                         row["advisory"], row["component"]),
    )


def source_result(sources, name, now, reference, *, local):
    previous = sources.get(name, {})
    online_at = previous.get("online_at", previous.get("checked_at")) if local else now
    return {"status": "ready", "checked_at": now, "online_at": online_at, "local": local, "reference": reference}


def report_summary(report):
    matches = select_findings(report)
    exploited = [row for row in matches if row.get("known_exploited")]
    fixes = defaultdict(int)
    for row in report["findings"].values():
        if state := row.get("fix_verification"):
            fixes[state] += 1
    return {"status": "recorded", "unresolved": len(matches), "sources": report["sources"],
            "known_exploited": len(exploited), "fixes": dict(fixes),
            "kernel_check": report["kernel_check"],
            "priority_findings": [{key: row[key] for key in ("advisory", "component", "status", "fixed")}
                                  | {"fix_verification": row.get("fix_verification")} for row in exploited[:5]]}


def feed_status(sources, expected_since, now):
    def freshness(name, source):
        if name not in expected_since:
            return source
        # Older reports did not distinguish offline imports from public feed refreshes.
        last = source.get("online_at", source.get("checked_at"))
        anchor = last if last and last <= now else expected_since[name]
        if now - anchor >= STALE_AFTER:
            status = "stale"
        else:
            status = "fresh" if last and last <= now else "pending"
        return {**source, "freshness": status}

    return {name: freshness(name, sources.get(name, {"status": "not-checked"}))
            for name in dict.fromkeys((*sources, *expected_since))}


def check_feed_health(database, expected, now):
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        previous = store.property_get(db, "vulnerability_feed_health", {})
        previous_since = previous.get("since", {})
        since = {name: previous_since.get(name, now) for name in expected}
        sources = store.property_get(db, "vulnerability_summary", {}).get("sources", {})
        current = feed_status(sources, since, now)
        stale = sorted(name for name in since if current[name]["freshness"] == "stale")
        prior_stale = set(previous.get("stale", []))
        for name in sorted(set(stale) - prior_stale):
            label = "CISA KEV" if name == "kev" else name
            store.event(db, now, "medium", "vulnerability-feed", "Vulnerability feed stale",
                        f"{label} has no successful public refresh within 48 hours.", name)
        for name in sorted((prior_stale & since.keys()) - set(stale)):
            label = "CISA KEV" if name == "kev" else name
            store.event(db, now, "info", "vulnerability-feed", "Vulnerability feed refreshed", label, name)
        state = {"since": since, "stale": stale}
        if state != previous:
            store.property_set(db, "vulnerability_feed_health", state)


def summary(db, now=None):
    saved = store.property_get(db, "vulnerability_summary", {"status": "not-checked"})
    health = store.property_get(db, "vulnerability_feed_health", {})
    now = time.time() if now is None else now
    sources = saved.get("sources", {})
    since = {name: source.get("attempted_at", source.get("checked_at", now))
             for name, source in sources.items() if name == "kev" or name.startswith("Ubuntu:")}
    since.update(health.get("since", {}))
    return {**saved, "sources": feed_status(sources, since, now),
            "previous_boot": bool(saved.get("kernel_check") and saved["kernel_check"]["boot_id"] != BOOT_ID)}


def apt_candidates(packages):
    candidates = {}
    ordered = sorted(packages)
    for offset in range(0, len(ordered), 100):
        batch = ordered[offset:offset + 100]
        output = command("/usr/bin/apt-cache", "policy", *batch)
        component = None
        for line in output.splitlines():
            if not line.startswith(" ") and line.endswith(":"):
                component = line[:-1]
            elif component and line.startswith(("  Candidate: ", "  Installed: ")):
                label, version = line.strip().split(": ", 1)
                candidates.setdefault(component, {})[label.lower()] = None if version == "(none)" else version
    return candidates


def updates(report, rows=None):
    if rows is None:
        rows = unresolved(report)
    # apt normally labels native packages without their architecture suffix.
    requests = {row["component"] for row in rows if row["scope"] in {"os", "dependency"}}
    candidates = apt_candidates(requests)
    result = []
    for row in rows:
        component = row["component"]
        if row["scope"] == "watchdog":
            candidate = report.get("watchdog_candidate")
            installed = __version__
        else:
            policy = candidates.get(component, candidates.get(component.partition(":")[0], {}))
            candidate = policy.get("candidate")
            installed = policy.get("installed")
        # Canonical thresholds apply to source versions. A binary version can differ.
        comparable = row["scope"] == "watchdog" or row["installed"] == row["comparison_version"]
        result.append({**row, "candidate": candidate, "current_installed": installed,
                       "update_available": None if not (candidate and installed) else version_compare(candidate, installed) > 0,
                       "candidate_meets_fix_threshold": None if not (candidate and row["fixed"] and comparable)
                       else version_compare(candidate, row["fixed"]) >= 0})
    return result


def journal_events(unit, since):
    result = command("/usr/bin/journalctl", "--quiet", "--no-pager", f"--unit={unit}",
                     f"--since=@{int(since)}", "--lines=2001", "--output=json",
                     "--output-fields=MESSAGE", "--truncate-newline")
    entries = result.splitlines()
    return [json.loads(line) for line in entries[-2000:]], len(entries) > 2000


def evidence(db, report, rule_file, hours, advisory=None):
    rules = defaultdict(list)
    if rule_file:
        entries = read_local_json(rule_file)["rules"]
        if not isinstance(entries, list) or len(entries) > 128:
            raise ValueError("Expected at most 128 passive evidence rules")
        for rule in entries:
            rule_advisory = rule["advisory"]
            kind = rule.get("event_kind", "")
            unit = rule.get("journal_unit", "")
            if (not ADVISORY_ID.fullmatch(rule_advisory)
                or not isinstance(rule.get("reference"), str) or not rule["reference"].startswith("https://")
                or any(not isinstance(rule.get(key), str) or not 0 < len(rule[key]) <= 256
                       for key in ("subject", "detail_contains") if key in rule)
                or not (kind or unit)
                or (kind and (unit or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", kind)
                              or not ({"subject", "detail_contains"} & rule.keys())))
                or (unit and (not re.fullmatch(r"[A-Za-z0-9_.@-]{1,100}\.service", unit)
                              or "subject" in rule or "detail_contains" not in rule))):
                raise ValueError("Invalid passive evidence rule")
            rules[rule_advisory].append(rule)
    since = time.time() - 3600 * hours
    result = []
    findings = select_findings(report, include_all=bool(advisory), advisory=advisory)
    advisories = sorted({finding["advisory"] for finding in findings})
    journals = {}
    for advisory in advisories:
        matches = {}
        partial = False
        for rule in rules.get(advisory, []):
            if unit := rule.get("journal_unit"):
                if unit not in journals:
                    try:
                        journals[unit] = journal_events(unit, since)
                    except (OSError, ValueError, subprocess.SubprocessError):
                        journals[unit] = ([], True)
                logs, limited = journals[unit]
                partial |= limited or not logs
                matches_rows = (
                    {"id": row["__CURSOR"], "at": int(row["__REALTIME_TIMESTAMP"]) / 1_000_000,
                     "journal_unit": unit, "kind": "journal"}
                    for row in logs if isinstance(row.get("MESSAGE"), str)
                    and rule["detail_contains"] in row["MESSAGE"]
                )
            else:
                matches_rows = db.execute(
                    """SELECT id, at, severity, kind, title FROM events
                       WHERE at >= ? AND kind = ?
                       AND (? IS NULL OR subject = ?) AND (? IS NULL OR instr(detail, ?) > 0)
                       ORDER BY id DESC LIMIT 21""",
                    (since, rule["event_kind"], rule.get("subject"), rule.get("subject"),
                     rule.get("detail_contains"), rule.get("detail_contains")),
                )
            for row in matches_rows:
                match = matches.setdefault(row["id"], {**dict(row), "references": []})
                if rule["reference"] not in match["references"]:
                    match["references"].append(rule["reference"])
        status = ("signals-found" if matches else "partial-log-coverage" if partial else
                  "no-matching-events" if advisory in rules else "no-rule")
        result.append({"advisory": advisory, "status": status, "partial_log_coverage": partial,
                       "events": sorted(matches.values(), key=lambda row: row["at"], reverse=True)[:20],
                       "truncated": len(matches) > 20})
    return {"since": since, "advisories": result}
