import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

BPFTRACE = "/usr/bin/bpftrace"
WINDOW_SECONDS = 5


def parse_map(line):
    message = json.loads(line)
    if message.get("type") != "map":
        return None
    data = message["data"]
    for map_name in ("@even", "@odd"):
        if map_name in data:
            break
    else:
        return None
    rows = defaultdict(lambda: [0, 0, 0, 0])
    counters = data[map_name]
    epoch = counters.get("0")
    if type(epoch) is not int or epoch <= 0:
        raise ValueError("Missing UDP window marker")
    for key, value in counters.items():
        encoded = int(key)
        if type(value) is not int or value < 0 or not 0 <= encoded < 2**34:
            raise ValueError("Invalid UDP counter")
        if encoded >= 4 and value:
            rows[encoded >> 2][encoded & 3] += value
    return epoch, rows


def process_name(pid, uid):
    path = Path("/proc") / str(pid)
    try:
        if path.stat().st_uid == uid:
            name = (path / "comm").read_text(errors="replace").strip()
            return "".join(char if char.isprintable() else " " for char in name)[:64] or "Process"
    except OSError:
        pass
    return "Process"


def publish(snapshot, uid):
    target = Path(f"/run/ai-watchdog-udp-{uid}/snapshot.json")
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as output:
        pending = Path(output.name)
        try:
            output.write(json.dumps(snapshot, ensure_ascii=True).encode())
            output.flush()
            os.fchmod(output.fileno(), 0o400)
            os.fchown(output.fileno(), uid, 0)
            os.replace(pending, target)
        finally:
            pending.unlink(missing_ok=True)


def notify_ready():
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as status:
        status.settimeout(1)
        status.sendto(b"READY=1", address)


def collect(uid):
    probe = Path(__file__).with_name("udp.bt")
    command = [BPFTRACE, "-q", "-B", "line", "-f", "json", str(probe), str(uid)]
    last_epoch = None
    announced = False
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, errors="replace") as child:
        try:
            for line in child.stdout:
                parsed = parse_map(line)
                if parsed is None:
                    continue
                epoch, counts = parsed
                ended = epoch * WINDOW_SECONDS
                if last_epoch is not None and epoch == last_epoch + 1 and 0 <= time.monotonic() - ended < WINDOW_SECONDS:
                    rows = [[pid, process_name(pid, uid), *values] for pid, values in counts.items()]
                    publish({"ended": ended, "seconds": WINDOW_SECONDS, "rows": [
                        row[:4] for row in rows
                    ], "packets": [[*row[:2], *row[4:]] for row in rows]}, uid)
                    if not announced:
                        notify_ready()
                        announced = True
                last_epoch = epoch
            raise RuntimeError(f"bpftrace exited with code {child.wait()}")
        finally:
            if child.poll() is None:
                child.terminate()


if __name__ == "__main__":
    uid = int(sys.argv[1])
    if os.geteuid() != 0 or uid <= 0 or uid >= 2**32 - 1:
        sys.exit("Run the UDP collector as root for a non-root user.")
    collect(uid)
