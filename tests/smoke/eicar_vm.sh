#!/usr/bin/env bash
# Boot a fresh overlay from an Ubuntu 24.04 amd64 cloud image.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 || ! -r $1 ]]; then
    echo "Usage: bash tests/smoke/eicar_vm.sh /path/to/ubuntu-24.04-server-cloudimg-amd64.img [desktop|desktop-upgrade|system-upgrade]" >&2
    exit 2
fi
mode=${2:-desktop}
case "$mode" in desktop|desktop-upgrade|system-upgrade) ;; *) echo "Unknown mode: $mode" >&2; exit 2 ;; esac
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
        if [[ -s $work/guest.log ]]; then
            grep -aE 'WATCHDOG_EICAR_|Rollback failed:' "$work/guest.log" >&2 || true
        fi
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
sources=(LICENSE deploy/install-user.sh deploy/install.sh deploy/install-clamav.sh deploy/config.json
         deploy/ai-watchdog.service deploy/ai-watchdog-response.service watchdog)
tar -C "$repo" --exclude=__pycache__ -czf "$work/source.tgz" "${sources[@]}"
if [[ $mode != desktop ]]; then
    # Last release before alert-review metadata was added.
    git -C "$repo" -c tar.umask=0022 archive --format=tar.gz ae1fe37ad4a4b3f85e5a95c5f32d091e02be624c "${sources[@]}" >"$work/legacy.tgz"
fi
python3 - "$work" "$smoke/eicar_guest.py" "$dashboard_port" "$mode" <<'PY'
import base64
from pathlib import Path
import sys

work, guest_script = map(Path, sys.argv[1:3])
port, mode = int(sys.argv[3]), sys.argv[4]
key = (work / "vm-key.pub").read_text().strip()
config = ["#cloud-config", "ssh_pwauth: false", "ssh_authorized_keys:", f"  - {key}", "write_files:"]
files = [
    (work / "source.tgz", "/var/tmp/watchdog-source.tgz", "0644"),
    (guest_script, "/usr/local/sbin/watchdog-eicar-check", "0755"),
]
if mode != "desktop":
    files.append((work / "legacy.tgz", "/var/tmp/watchdog-legacy.tgz", "0644"))
for source, target, permissions in files:
    payload = base64.b64encode(source.read_bytes()).decode()
    config.extend((f"  - path: {target}", f"    permissions: '{permissions}'", "    encoding: b64", f"    content: {payload}"))
config.extend(("runcmd:", f"  - [/usr/local/sbin/watchdog-eicar-check, '{port}', '{mode}']"))
(work / "user-data").write_text("\n".join(config) + "\n")
(work / "meta-data").write_text("instance-id: watchdog-eicar-smoke\nlocal-hostname: watchdog-eicar\n")
PY
xorriso -as mkisofs -quiet -output "$work/seed.iso" -volid CIDATA -joliet -rock \
    "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$work/guest.qcow2" 12G
cp -- "$variables" "$work/vars.fd"

echo "Booting a fresh Ubuntu VM for the Watchdog EICAR check ($mode)."
timeout --kill-after=10s 1320 qemu-system-x86_64 -machine q35 -accel kvm -accel tcg \
    -cpu max -m 2560 -smp 2 -display none -monitor none -serial "file:$work/guest.log" -no-reboot \
    -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
    -drive "if=pflash,format=raw,file=$work/vars.fd" \
    -drive "if=virtio,format=qcow2,file=$work/guest.qcow2" \
    -drive "media=cdrom,format=raw,readonly=on,file=$work/seed.iso" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    >"$work/qemu.log" 2>&1 &
vm=$!

deadline=$((SECONDS + 1140))
until grep -aq WATCHDOG_EICAR_GUEST_PASS "$work/guest.log" 2>/dev/null; do
    if grep -aq WATCHDOG_EICAR_GUEST_FAIL "$work/guest.log" 2>/dev/null ||
        ! kill -0 "$vm" 2>/dev/null || (( SECONDS >= deadline )); then
        echo "Guest failed before reporting the EICAR detection." >&2
        exit 1
    fi
    sleep 2
done
grep -a 'WATCHDOG_EICAR_' "$work/guest.log"
PYTHONPATH="$repo/tests:$repo" python3 -B "$smoke/eicar_browser.py" "$work" "$ssh_port" "$dashboard_port" "$mode"
echo WATCHDOG_EICAR_VM_PASS
