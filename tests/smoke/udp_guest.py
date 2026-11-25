"""Run in the smoke guest. The tracer and the traffic run as different UIDs."""
import json
import os
import select
import socket
import stat
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

UID = 12001
PAYLOADS = (b"watchdog IPv4 smoke", b"watchdog isolated IPv6 smoke test")


def traffic():
    for (family, host), payload in zip(((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")), PAYLOADS):
        with socket.socket(family, socket.SOCK_DGRAM) as client, socket.socket(family, socket.SOCK_DGRAM) as server:
            server.bind((host, 0))
            server.settimeout(2)
            assert client.sendto(payload, server.getsockname()) == len(payload)
            assert server.recv(2048) == payload
    print("sent", flush=True)
    time.sleep(20)


def verify(collector, snapshot, notifier):
    # Compiling and attaching under QEMU's software CPU can take longer than on a host.
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        assert collector.poll() is None, f"Collector exited with {collector.returncode} before readiness"
        if select.select([notifier], [], [], .2)[0]:
            assert notifier.recv(64) == b"READY=1"
            break
    else:
        raise AssertionError("Collector never reached readiness")
    with subprocess.Popen([sys.executable, __file__, "traffic"], user=UID, group=UID,
                          stdout=subprocess.PIPE, text=True) as sender:
        try:
            assert sender.stdout.readline().strip() == "sent", "Loopback traffic failed"
            payload_bytes = sum(map(len, PAYLOADS))
            expected = [payload_bytes, payload_bytes, 2, 2]
            observed = [0, 0, 0, 0]
            last = None
            deadline = time.monotonic() + 16
            while time.monotonic() < deadline:
                assert collector.poll() is None, f"Collector exited with {collector.returncode}"
                data = json.loads(snapshot.read_text())
                if last != data["ended"]:
                    last = data["ended"]
                    assert data["seconds"] == 5
                    rows = {pid: [received, sent] for pid, _, received, sent in data["rows"]}
                    packets = {pid: [received, sent] for pid, _, received, sent in data["packets"]}
                    for index, value in enumerate(rows.get(sender.pid, [0, 0]) + packets.get(sender.pid, [0, 0])):
                        observed[index] += value
                    if observed == expected:
                        info = snapshot.stat()
                        assert info.st_uid == UID and stat.S_IMODE(info.st_mode) == 0o400
                        print(f"UDP PID {sender.pid}: {observed} (RX/TX bytes, RX/TX datagrams)", flush=True)
                        return
                time.sleep(.2)
            raise AssertionError(f"PID {sender.pid}: expected {expected}, observed {observed}")
        finally:
            sender.terminate()


def main():
    snapshot = Path(f"/run/ai-watchdog-udp-{UID}/snapshot.json")
    snapshot.parent.mkdir(mode=0o711)
    address = "/run/udp-smoke-notify"
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
        notifier.bind(address)
        with subprocess.Popen([sys.executable, "-I", "-B", "/test/collector.py", str(UID)],
                              env={**os.environ, "NOTIFY_SOCKET": address}, start_new_session=True) as collector:
            try:
                verify(collector, snapshot, notifier)
            finally:
                with suppress(ProcessLookupError):
                    os.killpg(collector.pid, 15)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        traffic()
    else:
        main()
