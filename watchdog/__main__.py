import argparse
import json
import logging
import os
import secrets
import signal
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from .common import BASELINE, CONFIG, MONITOR_RUNTIME, configuration, write_json

MONITOR_STATE = Path("/var/lib/ai-watchdog")


def serve(settings, state, runtime, demo=False, baseline=BASELINE, response_runtime=None,
          config=CONFIG, observe_directory=None):
    from .monitor import Monitor
    from .server import Console

    token = None
    if not demo:
        token_path = state / "token"
        if not token_path.exists():
            with token_path.open("x") as output:
                output.write(secrets.token_urlsafe(32) + "\n")
        token = token_path.read_text().strip()
        if len(token) < 40:
            raise ValueError("Dashboard token is missing or too short")
    monitor = Monitor(settings, state / "monitor.sqlite3", runtime, demo=demo,
                      baseline=baseline, response_runtime=response_runtime, config=config,
                      observe_directory=observe_directory)
    with Console(monitor, token) as console:
        console.start_workers()
        print(f"Dashboard: {console.origin}", flush=True)
        try:
            console.serve_forever()
        finally:
            monitor.stop.set()


def main():
    parser = argparse.ArgumentParser(description="Local Linux endpoint protection monitor")
    parser.add_argument("--config", type=Path, default=CONFIG)
    actions = parser.add_subparsers(dest="command", required=True)
    demo = actions.add_parser("demo", help="Start a dashboard using synthetic data")
    demo.add_argument("--port", type=int, default=8765)
    actions.add_parser("serve", help="Start the unprivileged monitor and authenticated dashboard")
    for name, help_text in (
        ("observe", "Start the unprivileged user monitor with enforcement disabled"),
        ("observe-supervisor", "Start the unprivileged heartbeat supervisor"),
    ):
        observe = actions.add_parser(name, help=help_text)
        observe.add_argument("--directory", type=Path, required=True)
    vulnerability = actions.add_parser("vulnerabilities", help="Inspect local exposure and passive evidence")
    vulnerability.add_argument("--directory", type=Path, default=MONITOR_STATE,
                               help="Monitor state directory, such as .watchdog in observe mode")
    operations = vulnerability.add_subparsers(dest="operation", required=True)
    refresh = operations.add_parser("refresh", help="Match public advisories to the installed inventory")
    refresh.add_argument("--ubuntu-archive", type=Path, help="Use a local copy of Canonical's OSV archive")
    refresh.add_argument("--watchdog-advisories", type=Path, help="Trusted first-party advisory manifest")
    listing = operations.add_parser("list", help="List saved findings")
    listing.add_argument("--all", action="store_true", help="Include findings outside the affected range")
    updates = operations.add_parser("updates", help="Check local APT candidates and manifest releases")
    evidence = operations.add_parser("evidence", help="Match reviewed indicators to recorded events")
    evidence.add_argument("--rules", type=Path, help="Trusted local passive indicator rules")
    evidence.add_argument("--hours", type=int, default=24)
    for operation in (listing, updates, evidence):
        operation.add_argument("--advisory", help="Limit results to this CVE or Watchdog advisory ID")
        operation.add_argument("--limit", type=int, default=100, help="Maximum rows to return (0 for all)")
    for operation in (listing, updates):
        operation.add_argument("--scope", choices=("os", "dependency", "watchdog"))
    actions.add_parser("supervise", help="Start the independent containment watchdog")
    baseline = actions.add_parser("baseline", help="Record a known-good integrity baseline")
    baseline.add_argument("--directory", type=Path, help="Record the Watchdog baseline for an observe-only installation")
    baseline.add_argument("--watchdog-only", action="store_true", help="Record only the Watchdog application baseline")
    rollback = actions.add_parser("rollback", help="Back up Watchdog state and install a trusted older checkout")
    rollback.add_argument("source", type=Path, help="Separate local checkout of the trusted rollback version")
    rollback.add_argument("--desktop", action="store_true", help="Roll back the desktop user installation")
    actions.add_parser("recover", help="Restore interfaces and clear containment while the responder is stopped")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    os.umask(0o077)
    if args.command == "demo":
        if not 1024 <= args.port <= 65535:
            parser.error("Demo port must be between 1024 and 65535")
        with tempfile.TemporaryDirectory(prefix="ai-watchdog-") as directory:
            state = Path(directory)
            serve({"port": args.port, "interval": 10, "ollama_model": ""}, state, state, demo=True)
        return
    if args.command == "vulnerabilities":
        from . import store, vulnerabilities

        database = args.directory / "monitor.sqlite3"
        try:
            if args.directory.stat().st_uid != os.geteuid() or (
                database.exists() and database.stat().st_uid != os.geteuid()
            ):
                parser.error("Run vulnerability checks as the account that owns the monitor state.")
            if args.operation == "refresh":
                store.initialize(database)
                default_manifest = args.directory / "watchdog-advisories.json"
                manifest = args.watchdog_advisories or (default_manifest if default_manifest.is_file() else None)
                report = vulnerabilities.refresh(database, archive=args.ubuntu_archive, manifest=manifest)
                result = {key: value for key, value in report.items() if key != "findings"}
                result["unresolved"] = len(vulnerabilities.unresolved(report))
                print(json.dumps(result, indent=2))
                if report["errors"]:
                    raise SystemExit(1)
                return
            if not database.is_file():
                parser.error("Monitor database is missing. Check --directory.")
            with store.connect(database) as db:
                report = store.property_get(db, "vulnerabilities", {})
                result = {key: value for key, value in report.items() if key != "findings"}
                result["status"] = "recorded" if report else "not-checked"
                if not 0 <= args.limit <= 10000:
                    parser.error("--limit must be between 0 and 10000")
                limit = args.limit or None
                if args.advisory and not vulnerabilities.ADVISORY_ID.fullmatch(args.advisory):
                    parser.error("--advisory must be a CVE or Watchdog advisory ID")
                if args.operation == "evidence":
                    if not 1 <= args.hours <= 24 * 365:
                        parser.error("--hours must be between 1 and 8760")
                    default_rules = args.directory / "vulnerability-rules.json"
                    rules = args.rules or (default_rules if default_rules.is_file() else None)
                    evidence = vulnerabilities.evidence(db, report, rules, args.hours, args.advisory)
                    rows = evidence["advisories"]
                    statuses = {row["status"] for row in rows}
                    result["evidence_counts"] = {status: sum(row["status"] == status for row in rows)
                                                 for status in sorted(statuses)}
                    result["since"] = evidence["since"]
                    priority = {"signals-found": 0, "partial-log-coverage": 1, "no-matching-events": 2, "no-rule": 3}
                    result["advisories"] = sorted(rows, key=lambda row: (priority[row["status"]], row["advisory"]))[:limit]
                else:
                    rows = vulnerabilities.select_findings(report, include_all=getattr(args, "all", False),
                                                            advisory=args.advisory, scope=args.scope)
                    result["matching_findings"] = len(rows)
                    if args.operation == "updates":
                        rows = vulnerabilities.updates(report, rows)
                        rows.sort(key=lambda row: (row["update_available"] is not True,
                                                  row["candidate_meets_fix_threshold"] is not True))
                        result["available_updates"] = sum(row["update_available"] is True for row in rows)
                        result["candidate_checked_at"] = time.time()
                    result["findings"] = rows[:limit]
                print(json.dumps(result, indent=2))
        except (OSError, KeyError, ValueError, TypeError, sqlite3.Error, subprocess.SubprocessError) as error:
            parser.exit(1, f"Vulnerability check failed: {error}\n")
        return
    if args.command == "rollback":
        from .rollback import Deployment, RollbackError

        if args.config != CONFIG:
            parser.error("Rollback uses the installed Watchdog configuration")
        try:
            Deployment(args.desktop).rollback(args.source)
        except (RollbackError, OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
            parser.exit(1, f"Rollback failed: {error}\n")
        print("Rollback completed. The dashboard health check passed.")
        return
    if args.command == "baseline" and args.directory is not None:
        from .system_checks import record_baseline

        directory = args.directory.resolve()
        if os.geteuid() == 0 or not directory.is_dir() or directory.stat().st_uid != os.geteuid() or (
            directory.stat().st_mode & 0o077
        ):
            parser.error("Use the observe-only account and its existing private state directory.")
        config = directory / "config.json" if args.config == CONFIG else args.config
        count = record_baseline(directory / "watchdog-integrity.json", config, directory)
        print(f"Recorded {count} Watchdog integrity paths.")
        return
    settings = configuration(args.config)
    if args.command == "serve":
        if os.geteuid() == 0:
            parser.error("The monitor must run as an unprivileged user")
        serve(settings, MONITOR_STATE, MONITOR_RUNTIME, config=args.config)
        return
    if args.command in {"observe", "observe-supervisor"}:
        if os.geteuid() == 0:
            parser.error("User observation must run as an unprivileged user")
        settings["enforce"] = False
        directory = args.directory.resolve()
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
            parser.error("User observation requires a private directory owned by the current user")
        response_dir = directory / "response"
        response_dir.mkdir(mode=0o700, exist_ok=True)
        if args.command == "observe":
            from .sensors import fingerprint

            baseline = directory / "baseline.json"
            if not baseline.exists():
                records = {}
                for path in settings["integrity_paths"]:
                    try:
                        records[path] = fingerprint(path)
                    except (OSError, ValueError):
                        logging.warning("Unable to record initial fingerprint for %s", path)
                write_json(baseline, {"files": records})
            serve(settings, directory, directory, baseline=baseline, response_runtime=response_dir,
                  config=args.config, observe_directory=directory)
        else:
            from .responder import loop

            loop(settings, user_directory=directory)
        return
    if os.geteuid() != 0:
        parser.error("This operation requires root")
    if args.command == "baseline":
        from .sensors import fingerprint
        from .system_checks import record_baseline

        if not args.watchdog_only:
            records = {path: fingerprint(path) for path in settings["integrity_paths"]}
            write_json(BASELINE, {"files": records}, mode=0o644)
            print(f"Recorded {len(records)} integrity paths in {BASELINE}")
        count = record_baseline(BASELINE.with_name("watchdog-integrity.json"), args.config, None)
        print(f"Recorded {count} Watchdog integrity paths.")
    elif args.command == "supervise":
        from .responder import supervise

        supervise(settings)
    else:
        from .responder import recover

        recover()
        print("Containment cleared. Restart the watchdog services after reviewing the incident.")


def terminate(*_):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, terminate)
    try:
        main()
    except KeyboardInterrupt:
        pass
