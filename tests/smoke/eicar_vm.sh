#!/usr/bin/env bash
# Boot a fresh overlay from an Ubuntu 24.04 amd64 cloud image.
set -euo pipefail
if [[ $# != 1 || ! -r $1 ]]; then
    echo "Usage: bash tests/smoke/eicar_vm.sh /path/to/ubuntu-24.04-server-cloudimg-amd64.img" >&2
    exit 2
fi
image=$(realpath -- "$1")
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
smoke=$repo/tests/smoke
firmware=${WATCHDOG_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
variables=${WATCHDOG_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
for command in python3 qemu-img qemu-system-x86_64 ssh ssh-keygen timeout xorriso; do
    command -v "$command" >/dev/null || { echo "Missing $command" >&2; exit 1; }
done
command -v "${WATCHDOG_GECKODRIVER:-geckodriver}" >/dev/null || { echo "Missing GeckoDriver." >&2; exit 1; }
for file in "$firmware" "$variables"; do
    [[ -r $file ]] || { echo "Cannot read OVMF firmware file: $file" >&2; exit 1; }
done

umask 077
work=$(mktemp -d)
vm=
cleanup() {
    status=$?
    trap - EXIT
    if [[ -n $vm ]]; then
        kill "$vm" 2>/dev/null || true
        wait "$vm" 2>/dev/null || true
    fi
    if (( status != 0 )); then
        for log in guest.log qemu.log geckodriver.log; do
            if [[ -s $work/$log ]]; then
                echo "Last lines of $log" >&2
                tail -n 35 -- "$work/$log" >&2
            fi
        done
    fi
    rm -rf -- "$work"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

read -r ssh_port dashboard_port < <(python3 - <<'PY'
import socket

with socket.socket() as ssh, socket.socket() as dashboard:
    for listener in (ssh, dashboard):
        listener.bind(("127.0.0.1", 0))
    print(ssh.getsockname()[1], dashboard.getsockname()[1])
PY
)
ssh-keygen -q -t ed25519 -N '' -C watchdog-smoke-vm -f "$work/vm-key"
tar -C "$repo" --exclude=__pycache__ -czf "$work/source.tgz" \
    LICENSE deploy/install-user.sh deploy/install-clamav.sh deploy/config.json watchdog
python3 - "$work" "$smoke/eicar_guest.sh" "$dashboard_port" <<'PY'
import base64
from pathlib import Path
import sys

work, guest_script = map(Path, sys.argv[1:3])
port = int(sys.argv[3])
key = (work / "vm-key.pub").read_text().strip()
config = ["#cloud-config", "ssh_pwauth: false", "ssh_authorized_keys:", f"  - {key}", "write_files:"]
for source, target, mode in (
    (work / "source.tgz", "/var/tmp/watchdog-source.tgz", "0644"),
    (guest_script, "/usr/local/sbin/watchdog-eicar-check", "0755"),
):
    payload = base64.b64encode(source.read_bytes()).decode()
    config.extend((f"  - path: {target}", f"    permissions: '{mode}'", "    encoding: b64", f"    content: {payload}"))
config.extend(("runcmd:", f"  - [/usr/local/sbin/watchdog-eicar-check, '{port}']"))
(work / "user-data").write_text("\n".join(config) + "\n")
(work / "meta-data").write_text("instance-id: watchdog-eicar-smoke\nlocal-hostname: watchdog-eicar\n")
PY
xorriso -as mkisofs -quiet -output "$work/seed.iso" -volid CIDATA -joliet -rock \
    "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$work/guest.qcow2" 12G
cp -- "$variables" "$work/vars.fd"

echo "Booting a fresh Ubuntu VM for the Watchdog installer and EICAR check."
timeout --kill-after=10s 600 qemu-system-x86_64 -machine q35 -accel kvm -accel tcg \
    -cpu max -m 2560 -smp 2 -display none -monitor none -serial "file:$work/guest.log" -no-reboot \
    -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
    -drive "if=pflash,format=raw,file=$work/vars.fd" \
    -drive "if=virtio,format=qcow2,file=$work/guest.qcow2" \
    -drive "media=cdrom,format=raw,readonly=on,file=$work/seed.iso" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    >"$work/qemu.log" 2>&1 &
vm=$!

deadline=$((SECONDS + 540))
until grep -aq WATCHDOG_EICAR_GUEST_PASS "$work/guest.log" 2>/dev/null; do
    if grep -aq WATCHDOG_EICAR_GUEST_FAIL "$work/guest.log" 2>/dev/null ||
        ! kill -0 "$vm" 2>/dev/null || (( SECONDS >= deadline )); then
        echo "Guest failed before reporting the EICAR detection." >&2
        exit 1
    fi
    sleep 2
done
grep -a 'WATCHDOG_EICAR_' "$work/guest.log"
PYTHONPATH="$repo/tests:$repo" python3 -B "$smoke/eicar_browser.py" "$work" "$ssh_port" "$dashboard_port"
echo WATCHDOG_EICAR_VM_PASS
