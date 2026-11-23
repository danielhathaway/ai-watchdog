import argparse
import logging
import os
import secrets
import signal
import tempfile
from pathlib import Path

from .common import BASELINE, CONFIG, MONITOR_RUNTIME, configuration, write_json

MONITOR_STATE = Path("/var/lib/ai-watchdog")


def serve(settings, state, runtime, demo=False, baseline=BASELINE, response_runtime=None):
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
                      baseline=baseline, response_runtime=response_runtime)
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
    actions.add_parser("supervise", help="Start the independent containment watchdog")
    actions.add_parser("baseline", help="Record a known-good integrity baseline")
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
    settings = configuration(args.config)
    if args.command == "serve":
        if os.geteuid() == 0:
            parser.error("The monitor must run as an unprivileged user")
        serve(settings, MONITOR_STATE, MONITOR_RUNTIME)
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
            serve(settings, directory, directory, baseline=baseline, response_runtime=response_dir)
        else:
            from .responder import loop

            loop(settings, user_directory=directory)
        return
    if os.geteuid() != 0:
        parser.error("This operation requires root")
    if args.command == "baseline":
        from .sensors import fingerprint

        records = {path: fingerprint(path) for path in settings["integrity_paths"]}
        write_json(BASELINE, {"files": records}, mode=0o644)
        print(f"Recorded {len(records)} integrity paths in {BASELINE}")
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
