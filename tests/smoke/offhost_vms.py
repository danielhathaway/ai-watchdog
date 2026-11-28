"""Verify off-host telemetry across two disposable Ubuntu VMs."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
CONFIG = "/etc/ai-watchdog"
APP = "/opt/ai-watchdog"
COLLECTOR_IP = "192.168.247.10"
ENDPOINT_IP = "192.168.247.20"
ENDPOINT = "endpoint-vm"
COLLECTOR = "ai-watchdog-collector.service"
MONITOR = "ai-watchdog.service"
SENDER = "ai-watchdog-offhost-sender.service"
TIMER = "ai-watchdog-offhost-sender.timer"
SILENCE_SECONDS = 65  # Leave room for the installed timer's 30-second cadence.
HIGH = "Two-host high-severity fixture"
MEDIUM = "Two-host medium-severity fixture"
CRITICAL = "Two-host critical fixture queued during outage"


def wait_for(description, check, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(2)
    raise TimeoutError(f"Timed out waiting for {description}")


def local_ports():
    with ExitStack() as stack:
        listeners = [stack.enter_context(socket.socket()) for _ in range(3)]
        for listener in listeners:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in listeners]


class Guest:
    def __init__(self, work, role, ssh_port, mac, address):
        self.work = work
        self.directory = work / role
        self.directory.mkdir()
        self.hostname = "watchdog-" + role
        self.ssh_port, self.mac, self.address = ssh_port, mac, address
        self.process = None

    def start(self, image, wire, stack):
        directory = self.directory
        ovmf = Path("/usr/share/OVMF")
        shutil.copyfile(ovmf / "OVMF_VARS_4M.fd", directory / "vars.fd")
        key = (self.work / "guest-key.pub").read_text().strip()
        (directory / "user-data").write_text(
            f"#cloud-config\nssh_pwauth: false\nssh_authorized_keys:\n  - {key}\n"
        )
        (directory / "meta-data").write_text(
            f"instance-id: {self.hostname}-smoke\nlocal-hostname: {self.hostname}\n"
        )
        subprocess.run([
            "xorriso", "-as", "mkisofs", "-quiet", "-output", directory / "seed.iso", "-volid", "CIDATA",
            "-joliet", "-rock", directory / "user-data", directory / "meta-data",
        ], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image,
                        directory / "disk.qcow2", "10G"], check=True)
        log = stack.enter_context((directory / "qemu.log").open("wb"))
        self.process = subprocess.Popen([
            "qemu-system-x86_64", "-machine", "q35", "-accel", "kvm", "-accel", "tcg",
            "-cpu", "max", "-m", "1024", "-smp", "2", "-display", "none", "-monitor", "none", "-no-reboot",
            "-serial", f"file:{directory / 'guest.log'}",
            "-qmp", f"unix:{directory / 'qmp'},server=on,wait=off",
            "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf / 'OVMF_CODE_4M.fd'}",
            "-drive", f"if=pflash,format=raw,file={directory / 'vars.fd'}",
            "-drive", f"if=virtio,format=qcow2,file={directory / 'disk.qcow2'}",
            "-drive", f"media=cdrom,format=raw,readonly=on,file={directory / 'seed.iso'}",
            "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22",
            "-netdev", f"socket,id=wire,{wire}",
            "-device", f"virtio-net-pci,netdev=wire,id=telemetry,mac={self.mac}",
        ], stdout=log, stderr=log)
        stack.callback(self.stop)

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def ssh(self, command, data=None, *, required=True, timeout=30):
        result = subprocess.run([
            "ssh", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "LogLevel=ERROR",
            "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.work / 'known_hosts'}",
            "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
            "-i", self.work / "guest-key", "-p", str(self.ssh_port), "ubuntu@127.0.0.1", command,
        ], input=data, capture_output=True, timeout=timeout)
        if result.returncode == 0:
            return result.stdout.decode().strip()
        if required:
            detail = (result.stdout + result.stderr).decode(errors="replace")[-3000:]
            raise RuntimeError(f"{self.hostname}: remote command exited {result.returncode}\n{detail}")
        return None

    def provision(self, source):
        def boot_id():
            if self.process.poll() is not None:
                raise RuntimeError(f"{self.hostname}: QEMU exited {self.process.returncode}")
            return self.ssh("hostname; cat /proc/sys/kernel/random/boot_id", required=False)

        identity = wait_for(self.hostname + " SSH", boot_id, 420)
        hostname, machine_boot = identity.splitlines()
        assert hostname == self.hostname, identity
        interface_command = (
            'for path in /sys/class/net/*/address; do '
            f'if [ "$(cat "$path")" = {self.mac} ]; then basename "$(dirname "$path")"; exit; fi; done; exit 1'
        )
        self.interface = self.ssh(interface_command)
        interface = shlex.quote(self.interface)
        self.ssh(f"sudo ip address add {self.address}/24 dev {interface} && sudo ip link set {interface} up")
        self.ssh("mkdir /tmp/watchdog-source && tar xzf - -C /tmp/watchdog-source", source)
        self.ssh(
            "if ! test -x /usr/sbin/nft; then sudo apt-get -qq update && "
            "sudo apt-get -qy install --no-install-recommends nftables || exit; fi; "
            "sudo sh /tmp/watchdog-source/deploy/install.sh --without-clamav", timeout=180,
        )
        print(f"Booted {hostname} ({machine_boot})", flush=True)
        return machine_boot

    def put(self, name, data):
        path = shlex.quote(f"{CONFIG}/{name}")
        self.ssh(f"sudo install -m 0600 -o ai-watchdog -g ai-watchdog /dev/null {path} && "
                 f"sudo tee {path} >/dev/null", data)

    def set_link(self, up):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect(str(self.directory / "qmp"))
            with client.makefile("rwb") as stream:
                assert "QMP" in json.loads(stream.readline())
                for command in (
                    {"execute": "qmp_capabilities"},
                    {"execute": "set_link", "arguments": {"name": "telemetry", "up": up}},
                ):
                    stream.write(json.dumps(command).encode() + b"\n")
                    stream.flush()
                    result = json.loads(stream.readline())
                    while "event" in result:
                        result = json.loads(stream.readline())
                    assert "return" in result, result

    def diagnostics(self):
        try:
            journal = self.ssh(f"sudo journalctl --no-pager -n 18 -u {MONITOR} -u {COLLECTOR} -u {SENDER}",
                               required=False, timeout=12)
            if journal:
                print(journal, file=sys.stderr)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(error, file=sys.stderr)
        for name in ("qemu.log", "guest.log"):
            path = self.directory / name
            if path.is_file():
                print(f"{self.hostname} {name}:\n" + "\n".join(
                    path.read_text(errors="replace").splitlines()[-15:]), file=sys.stderr)


def event(endpoint, severity, title):
    script = (
        "import time\nfrom pathlib import Path\nfrom watchdog import store\n"
        "with store.connect(Path('/var/lib/ai-watchdog/monitor.sqlite3')) as db:\n"
        f"    store.event(db, time.time(), {severity!r}, 'two-host-test', {title!r})\n"
    )
    endpoint.ssh(f"cd {APP} && sudo -u ai-watchdog python3 -B -", script.encode())


def heartbeat(endpoint, *, required=True):
    result = endpoint.ssh(f"systemctl show {MONITOR} -p MainPID --value; "
                          "sudo cat /run/ai-watchdog/heartbeat.json", required=required)
    if result:
        pid, payload = result.split("\n", 1)
        assert int(pid) > 0, result
        return pid, json.loads(payload)


def matching(snapshot, section, title):
    return [row for row in snapshot[section] if row["title"] == title]


def verify_outage(collector, endpoint):
    missing_title = f"Endpoint heartbeat missing: {ENDPOINT}"
    recovery_title = f"Endpoint heartbeat recovered: {ENDPOINT}"

    def snapshot():
        result = collector.ssh(f"cd {APP} && sudo -u ai-watchdog python3 -B -m watchdog off-host status")
        state = json.loads(result)
        host, = (row for row in state["endpoints"] if row["name"] == ENDPOINT)
        return state, host

    def delivery(status, title=None):
        state, host = snapshot()
        if host["status"] == status and (title is None or matching(state, "events", title)):
            return state, host

    def carrier(up):
        return endpoint.ssh(f"cat /sys/class/net/{shlex.quote(endpoint.interface)}/carrier") == str(int(up))

    before, host = wait_for("scheduled high-severity report", lambda: delivery("reporting", HIGH), 75)
    high, = matching(before, "events", HIGH)
    assert high["severity"] == "high" and high["endpoint"] == ENDPOINT, high
    assert not matching(before, "events", MEDIUM)
    last_heartbeat = host["last_heartbeat"]
    monitor_pid, initial_heartbeat = heartbeat(endpoint)
    print("High-severity event arrived over the private telemetry link.", flush=True)

    endpoint.set_link(False)
    wait_for("telemetry carrier loss", lambda: carrier(False), 10)
    endpoint.ssh(f"if timeout 4 openssl s_client -connect {COLLECTOR_IP}:9443 </dev/null >/dev/null 2>&1; "
                 "then exit 1; fi")
    event(endpoint, "critical", CRITICAL)
    print("Telemetry link disconnected. The endpoint monitor remains active.", flush=True)

    offline, host = wait_for("collector silence alert", lambda: delivery("silent"), SILENCE_SECONDS + 35)
    missing, = matching(offline, "alerts", missing_title)
    delay = missing["at"] - last_heartbeat
    assert missing["severity"] == "high" and delay >= SILENCE_SECONDS, missing
    assert host["last_heartbeat"] == last_heartbeat and not matching(offline, "events", CRITICAL), host
    assert not matching(offline, "alerts", recovery_title)
    pid, current = heartbeat(endpoint)
    assert pid == monitor_pid and current["boot_id"] == initial_heartbeat["boot_id"], (pid, current)
    assert current["at"] > initial_heartbeat["at"], current
    time.sleep(6)  # Span another collector silence check to catch duplicate alerts.
    assert len(matching(snapshot()[0], "alerts", missing_title)) == 1
    print(f"Collector recorded one silence alert {delay:.1f}s after the last heartbeat.", flush=True)

    endpoint.set_link(True)
    wait_for("telemetry carrier restoration", lambda: carrier(True), 10)
    recovered, host = wait_for("recovery and queued critical event", lambda: delivery("reporting", CRITICAL), 75)
    recovery, = matching(recovered, "alerts", recovery_title)
    queued, = matching(recovered, "events", CRITICAL)
    assert recovery["severity"] == "info" and recovery["at"] > missing["at"], recovery
    assert queued["severity"] == "critical" and queued["endpoint"] == ENDPOINT, queued
    assert host["last_heartbeat"] > last_heartbeat and heartbeat(endpoint)[0] == monitor_pid, host
    assert len(matching(recovered, "events", HIGH)) == 1 and not matching(recovered, "events", MEDIUM)
    assert len(matching(recovered, "alerts", missing_title)) == 1
    print("Collector recorded recovery and accepted the queued critical event exactly once.", flush=True)


def smoke(image, work):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", work / "guest-key"], check=True)
    source = subprocess.check_output(
        ["tar", "--exclude=__pycache__", "-czf", "-", "-C", REPO, "LICENSE", "deploy", "watchdog"]
    )
    collector_port, endpoint_port, wire_port = local_ports()
    collector = Guest(work, "collector", collector_port, "52:54:00:ae:91:01", COLLECTOR_IP)
    endpoint = Guest(work, "endpoint", endpoint_port, "52:54:00:ae:91:02", ENDPOINT_IP)
    with ExitStack() as stack:
        try:
            # The second NICs share an isolated wire. The first NICs keep SSH out of the test path.
            collector.start(image, f"listen=127.0.0.1:{wire_port}", stack)
            wait_for("collector QEMU control socket", lambda: (collector.directory / "qmp").exists(), 10)
            endpoint.start(image, f"connect=127.0.0.1:{wire_port}", stack)
            assert collector.provision(source) != endpoint.provision(source), "Guests must boot independently"

            cert, key = work / "certificate.pem", work / "tls.key"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=Watchdog two-host smoke", "-addext", f"subjectAltName=IP:{COLLECTOR_IP}",
                "-keyout", key, "-out", cert,
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            credential = secrets.token_hex(32).encode()
            for guest in (collector, endpoint):
                guest.put("peer.key", credential)
                guest.put("certificate.pem", cert.read_bytes())
            collector.put("tls.key", key.read_bytes())
            collector.put("off-host-collector.json", json.dumps({
                "listen": COLLECTOR_IP, "port": 9443, "certificate": "certificate.pem", "private_key": "tls.key",
                "endpoints": {ENDPOINT: "peer.key"}, "silence_seconds": SILENCE_SECONDS,
            }).encode())
            endpoint.put("off-host-sender.json", json.dumps({
                "endpoint": ENDPOINT, "url": f"https://{COLLECTOR_IP}:9443", "key_file": "peer.key",
                "ca_file": "certificate.pem",
            }).encode())

            endpoint.ssh(f"sudo systemctl start {MONITOR}")
            wait_for("endpoint monitor heartbeat", lambda: heartbeat(endpoint, required=False), 45)
            event(endpoint, "high", HIGH)
            event(endpoint, "medium", MEDIUM)
            collector.ssh(f"sudo systemctl start {COLLECTOR}")
            wait_for("collector TLS listener", lambda: endpoint.ssh(
                f"timeout 4 sudo -u ai-watchdog openssl s_client -brief -verify_return_error "
                f"-verify_ip {COLLECTOR_IP} -CAfile {CONFIG}/certificate.pem "
                f"-connect {COLLECTOR_IP}:9443 </dev/null 2>&1", required=False), 45)
            endpoint.ssh(f"sudo systemctl start {TIMER}")
            verify_outage(collector, endpoint)
        except Exception:
            for guest in (collector, endpoint):
                guest.diagnostics()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Verified Ubuntu 24.04 cloud image")
    image = parser.parse_args().image.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="watchdog-offhost-") as directory:
        smoke(image, Path(directory))
    print("WATCHDOG_OFFHOST_TWO_HOST_PASS")


if __name__ == "__main__":
    main()
