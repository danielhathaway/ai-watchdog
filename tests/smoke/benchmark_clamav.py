"""Compare Watchdog's serial clamscan against a private warm ClamD Unix socket."""

import argparse
import json
import os
from pathlib import Path
import random
import socket
from statistics import median
import subprocess
import tempfile
import time

from watchdog.system_checks import antivirus


def command(endpoint, text):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(120)
        client.connect(str(endpoint))
        client.sendall(b"z" + os.fsencode(text) + b"\0")
        with client.makefile("rb") as response:
            return response.read().strip(b"\0")


def ready(endpoint, process, log):
    started = time.monotonic()
    while time.monotonic() - started < 150:
        if process.poll() is not None:
            raise RuntimeError(log.read_text(errors="replace")[-4000:])
        try:
            if command(endpoint, "PING") == b"PONG":
                return time.monotonic() - started
        except OSError:
            pass
        time.sleep(.2)
    raise RuntimeError("The private ClamD socket did not become ready")


def resident_mib(process):
    for line in Path(f"/proc/{process.pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return round(int(line.split()[1]) / 1024, 1)
    raise RuntimeError("ClamD memory usage was unavailable")


def sample(work, count):
    rng = random.Random(451)
    roots = []
    for index in range(count):
        root = work / f"path-{index}"
        root.mkdir()
        for file in range(24):
            (root / f"file-{file}.bin").write_bytes(rng.randbytes(16 * 1024))
        roots.append(str(root))
    return roots


def benchmark(binary, paths, trials):
    with tempfile.TemporaryDirectory(prefix="watchdog-clamd-") as directory:
        work = Path(directory)
        roots = sample(work, paths)
        config = work / "clamd.conf"
        endpoint = work / "clamd.sock"
        log = work / "daemon.log"
        config.write_text(
            f"Foreground yes\nDatabaseDirectory /var/lib/clamav\nLocalSocket {endpoint}\nLocalSocketMode 0600\n"
            "OfficialDatabaseOnly yes\nAlertExceedsMax yes\nCrossFilesystems no\n"
            "FollowDirectorySymlinks no\nFollowFileSymlinks no\nMaxThreads 1\n"
        )
        serial = {}
        persistent = {}
        with log.open("wb") as output:
            process = subprocess.Popen([binary, "--config-file", str(config)], stdout=output, stderr=subprocess.STDOUT)
            try:
                startup = ready(endpoint, process, log)
                for _ in range(trials):
                    started = time.monotonic()
                    scan = antivirus(roots)
                    if scan["status"] != "pass" or scan["files_scanned"] != paths * 24:
                        raise RuntimeError(scan)
                    print(f"clamscan trial: {time.monotonic() - started:.2f} s over {paths} paths", flush=True)
                    durations = [row["duration_seconds"] for row in scan["coverage"]]
                    warm = []
                    for root in roots:
                        started = time.monotonic()
                        response = command(endpoint, "CONTSCAN " + root)
                        if response != os.fsencode(root + ": OK"):
                            raise RuntimeError(f"Unexpected ClamD response: {response!r}")
                        warm.append(time.monotonic() - started)
                    for count in sorted({1, paths // 2, paths} - {0}):
                        serial.setdefault(count, []).append(sum(durations[:count]))
                        persistent.setdefault(count, []).append(sum(warm[:count]))
                return {
                    "scanner": subprocess.check_output(["clamscan", "--version"], text=True).strip(),
                    "paths_per_trial": paths, "files_per_path": 24, "bytes_per_file": 16 * 1024, "trials": trials,
                    "clamd_cold_start_seconds": round(startup, 3), "clamd_resident_mib": resident_mib(process),
                    "batches": [{"paths": count, "clamscan_median_seconds": round(median(serial[count]), 3),
                                 "warm_clamd_median_seconds": round(median(persistent[count]), 3)}
                                for count in serial],
                }
            finally:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clamd", default="/usr/sbin/clamd")
    parser.add_argument("--paths", type=int, default=4)
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.paths <= 64 or not 1 <= args.trials <= 10:
        parser.error("Use 1–64 paths and 1–10 trials")
    print(json.dumps(benchmark(args.clamd, args.paths, args.trials), indent=2))
