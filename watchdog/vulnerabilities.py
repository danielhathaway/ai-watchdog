"""Match vendor advisories to local inventory and retain unresolved exposure."""
import fcntl
import functools
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

UBUNTU_FEED = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
UBUNTU_MEMBER = re.compile(r"osv/cve/\d{4}/UBUNTU-(CVE-\d{4}-\d{4,})\.json")
ADVISORY_ID = re.compile(r"(?:CVE-\d{4}-\d{4,}|WD-[0-9]{4}-[0-9]{3,})")
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
        for member in bundle:
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


def ubuntu_findings(archive, ecosystem, packages, existing):
    findings = {}
    release_present = False
    for advisory, record in ubuntu_records(archive):
        for entry in record.get("affected", []):
            package = entry["package"]
            if package["ecosystem"] != ecosystem:
                continue
            release_present = True
            source = package["name"]
            if record.get("withdrawn") or source not in packages:
                continue
            ranges = [item["events"] for item in entry.get("ranges", []) if item["type"] == "ECOSYSTEM"]
            if not ranges:
                continue
            severity = next((s["score"] for s in record.get("severity", []) if s["type"] == "Ubuntu"), "unknown")
            for binary, source_version, binary_version in packages[source]:
                matches = [fix for affected, fix in (evaluate_range(source_version, r) for r in ranges) if affected]
                key = f"{ecosystem}/{advisory}/{binary}"
                previous = findings.get(key)
                if previous and previous["status"] in {"affected", "vendor-listed"}:
                    matches.append(previous["fixed"])
                if not matches and key not in existing:
                    continue
                fixed = existing.get(key, {}).get("fixed") if not matches else None
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
    if not release_present:
        raise ValueError(f"Ubuntu archive contains no records for {ecosystem}")
    return findings


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
                "installed": __version__, "comparison_version": __version__, "fixed": fixed,
                "severity": record.get("severity", "unknown"), "source": "watchdog",
                "status": ("affected" if fixed else "vendor-listed") if affected else "outside-affected-range",
            }
    candidate = manifest.get("available_version")
    if candidate is not None and (not isinstance(candidate, str) or not 0 < len(candidate) <= 256):
        raise ValueError("Invalid Watchdog release version")
    return findings, candidate


def download_archive(path):
    with urlopen(UBUNTU_FEED, timeout=30) as response, path.open("wb") as output:
        if response.geturl() != UBUNTU_FEED:
            raise ValueError("Unexpected Ubuntu advisory download URL")
        deadline = time.monotonic() + 180
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > LIMIT or time.monotonic() > deadline:
                raise ValueError("Ubuntu advisory download exceeded size or time limit")
            output.write(chunk)


def refresh(database, *, archive=None, manifest=None):
    with database.with_suffix(".vulnerability.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("A vulnerability refresh is already running") from error
        return refresh_locked(database, archive, manifest)


def refresh_locked(database, archive, manifest):
    started = time.time()
    with store.connect(database) as db:
        previous = store.property_get(db, "vulnerabilities", {})
    existing = previous.get("findings", {})
    sources = dict(previous.get("sources", {}))
    current = {}
    checked = set()
    release = os_release()
    ecosystem = ubuntu_ecosystem(release)
    packages = None
    errors = []
    if ecosystem:
        try:
            packages = package_inventory()
            with tempfile.TemporaryDirectory(prefix="watchdog-cve-") as directory:
                if archive is None:
                    archive = Path(directory) / "ubuntu.tar.xz"
                    download_archive(archive)
                current.update(ubuntu_findings(archive, ecosystem, packages, existing))
            checked.add(ecosystem)
            sources[ecosystem] = {"status": "ready", "checked_at": started, "reference": UBUNTU_FEED}
        except (OSError, EOFError, ValueError, KeyError, TypeError, lzma.LZMAError, tarfile.TarError, subprocess.SubprocessError) as error:
            sources[ecosystem] = {**sources.get(ecosystem, {}), "status": "failed", "attempted_at": started}
            errors.append(f"Ubuntu advisory lookup failed: {error}")
    else:
        sources["os"] = {"status": "unsupported-os", "attempted_at": started}
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
            current[key] = {**old, "status": status}
        elif old["source"] != ecosystem and old["source"] != "watchdog":
            current[key] = {**old, "status": "unverified"}
        else:
            current[key] = old
    for key, finding in current.items():
        finding["first_seen"] = existing.get(key, {}).get("first_seen", started)
        if finding["source"] in checked:
            finding["checked_at"] = started
    report = {"started_at": started, "os": release, "running_kernel": platform.release(), "sources": sources,
              "findings": current, "watchdog_version": __version__, "watchdog_candidate": candidate, "errors": errors}
    with store.connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        store.property_set(db, "vulnerabilities", report)
        store.property_set(db, "vulnerability_summary", {
            "status": "recorded", "unresolved": len(unresolved(report)), "sources": sources,
        })
    return report


def unresolved(report):
    return [row for row in report.get("findings", {}).values()
            if row["status"] in {"affected", "vendor-listed", "unverified"}]


def select_findings(report, *, include_all=False, advisory=None, scope=None):
    rows = list(report.get("findings", {}).values()) if include_all else unresolved(report)
    statuses = {"affected": 0, "vendor-listed": 1, "unverified": 2}
    severities = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(
        (row for row in rows if (not advisory or row["advisory"] == advisory) and (not scope or row["scope"] == scope)),
        key=lambda row: (statuses.get(row["status"], 3), severities.get(row["severity"], 4),
                         row["advisory"], row["component"]),
    )


def summary(db):
    return store.property_get(db, "vulnerability_summary", {"status": "not-checked"})


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
