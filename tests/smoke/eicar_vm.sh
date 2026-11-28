#!/usr/bin/env bash
# Boot a fresh overlay from an Ubuntu 24.04 amd64 cloud image.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 3 || ! -r $1 ]]; then
    echo "Usage: bash tests/smoke/eicar_vm.sh /path/to/ubuntu-24.04-server-cloudimg-amd64.img [desktop|desktop-upgrade|system-upgrade|backup-restore|system-backup-restore|defensive]" >&2
    exit 2
fi
mode=${2:-desktop}
if [[ $mode == backup-restore ]]; then
    umask 077
    transfer=$(mktemp -d)
    trap 'rm -rf -- "$transfer"' EXIT
    bash "$0" "$1" backup-source "$transfer/backup.tgz"
    bash "$0" "$1" backup-destination "$transfer/backup.tgz"
    echo WATCHDOG_FRESH_RESTORE_VM_PASS
    exit
fi
if [[ $mode == system-backup-restore ]]; then
    umask 077
    transfer=$(mktemp -d)
    storage=
    policy=
    trap 'for process in "$policy" "$storage"; do if [[ -n $process ]]; then kill "$process" 2>/dev/null || true; wait "$process" 2>/dev/null || true; fi; done; rm -rf -- "$transfer"' EXIT
    keygen=${WATCHDOG_AGE_KEYGEN:-age-keygen}
    rclone=${WATCHDOG_RCLONE:-rclone}
    for key in retired current; do
        "$keygen" -o "$transfer/$key.identity" 2>"$transfer/keygen.log"
        "$keygen" -y "$transfer/$key.identity" >"$transfer/$key.recipient"
    done
    python3 -c 'import secrets; print(secrets.token_hex(32))' >"$transfer/report-key"
    read -r port backend_port password < <(python3 - <<'PY'
import secrets
import socket

with socket.socket() as listener, socket.socket() as backend:
    listener.bind(("127.0.0.1", 0))
    backend.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1], backend.getsockname()[1], secrets.token_hex(16))
PY
    )
    mkdir "$transfer/storage"
    "$rclone" serve webdav "$transfer/storage" --addr "127.0.0.1:$backend_port" --user watchdog --pass "$password" \
        >"$transfer/storage.log" 2>&1 &
    storage=$!
    python3 -B "$(dirname -- "$0")/immutable_webdav.py" "$port" "$backend_port" "$transfer/storage" \
        >"$transfer/policy.log" 2>&1 &
    policy=$!
    printf '[offsite]\ntype = webdav\nurl = http://10.0.2.2:%s\nvendor = other\nuser = watchdog\npass = %s\n' \
        "$port" "$("$rclone" obscure "$password")" >"$transfer/rclone.conf"
    bash "$0" "$1" system-backup-source "$transfer/donor-proof"
    bash "$0" "$1" system-backup-destination "$transfer/donor-proof"
    bash "$0" "$1" system-backup-primary "$transfer/donor-proof"
    echo WATCHDOG_ENCRYPTED_SYSTEM_RESTORE_VM_PASS
    exit
fi
case "$mode" in
    desktop|desktop-upgrade|system-upgrade|defensive) ;;
    backup-source|backup-destination|system-backup-source|system-backup-destination|system-backup-primary)
        : "${3:?Missing private backup transfer path}" ;;
    *) echo "Unknown mode: $mode" >&2; exit 2 ;;
esac
image=$(realpath -- "$1")
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
smoke=$repo/tests/smoke
firmware=${WATCHDOG_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
variables=${WATCHDOG_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
for command in python3 qemu-img qemu-system-x86_64 ssh ssh-keygen timeout xorriso; do
    command -v "$command" >/dev/null || { echo "Missing $command" >&2; exit 1; }
done
if [[ $mode != *backup-* && $mode != defensive ]]; then
    command -v "${WATCHDOG_GECKODRIVER:-geckodriver}" >/dev/null || { echo "Missing GeckoDriver." >&2; exit 1; }
fi
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
            grep -aE 'WATCHDOG_EICAR_|WATCHDOG_DEFENSIVE_|WATCHDOG_BACKUP_JOB_ERROR|Rollback failed:' "$work/guest.log" >&2 || true
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
jobs=(deploy/ai-watchdog-backup-{upload,drill,verifier@}.{service,timer})
scheduled=(deploy/ai-watchdog-vulnerability-refresh.{service,timer}
           deploy/ai-watchdog-userspace.{service,timer} deploy/ai-watchdog-runtime-processes.service)
tar -C "$repo" --exclude=__pycache__ -czf "$work/source.tgz" "${sources[@]}" "${jobs[@]}" "${scheduled[@]}"
if [[ $mode == *-upgrade ]]; then
    # Last release before alert-review metadata was added.
    git -C "$repo" -c tar.umask=0022 archive --format=tar.gz ae1fe37ad4a4b3f85e5a95c5f32d091e02be624c "${sources[@]}" >"$work/legacy.tgz"
fi
if [[ $mode == backup-destination ]]; then
    cp -- "$3" "$work/imported.tgz"
elif [[ $mode == system-backup-source ]]; then
    cp -- "$(dirname -- "$3")/"{retired,current}.recipient "$work/"
    cp -- "$(dirname -- "$3")/rclone.conf" "$work/rclone.conf"
elif [[ $mode == system-backup-destination ]]; then
    cp -- "$(dirname -- "$3")/"{retired,current}.identity "$work/"
    cp -- "$(dirname -- "$3")/rclone.conf" "$work/rclone.conf"
    cp -- "$3" "$work/donor-proof"
elif [[ $mode == system-backup-primary ]]; then
    cp -- "$(dirname -- "$3")/rclone.conf" "$work/rclone.conf"
fi
if [[ $mode == system-backup-destination || $mode == system-backup-primary ]]; then
    cp -- "$(dirname -- "$3")/report-key" "$work/report-key"
fi
guest_script=$smoke/eicar_guest.py
marker=WATCHDOG_EICAR_GUEST
memory=2560
if [[ $mode == defensive ]]; then
    guest_script=$smoke/defensive_guest.py
    marker=WATCHDOG_DEFENSIVE_GUEST
    memory=1536
fi
python3 - "$work" "$guest_script" "$dashboard_port" "$mode" <<'PY'
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
if mode.endswith("-upgrade"):
    files.append((work / "legacy.tgz", "/var/tmp/watchdog-legacy.tgz", "0644"))
if mode == "backup-destination":
    files.append((work / "imported.tgz", "/var/tmp/watchdog-imported.tgz", "0600"))
if mode == "system-backup-source":
    for key in ("retired", "current"):
        files.append((work / f"{key}.recipient", f"/var/tmp/watchdog-age-{key}.recipient", "0600"))
if mode.startswith("system-backup-"):
    files.append((work / "rclone.conf", "/var/tmp/watchdog-test-rclone.conf", "0600"))
if mode in ("system-backup-destination", "system-backup-primary"):
    files.append((work / "report-key", "/var/tmp/watchdog-report-key", "0600"))
if mode == "system-backup-destination":
    for key in ("retired", "current"):
        files.append((work / f"{key}.identity", f"/var/tmp/watchdog-age-{key}.identity", "0600"))
    files.append((work / "donor-proof", "/var/tmp/watchdog-donor-proof", "0600"))
for source, target, permissions in files:
    payload = base64.b64encode(source.read_bytes()).decode()
    config.extend((f"  - path: {target}", f"    permissions: '{permissions}'", "    encoding: b64", f"    content: {payload}"))
config.extend(("runcmd:", f"  - [/usr/local/sbin/watchdog-eicar-check, '{port}', '{mode}']"))
(work / "user-data").write_text("\n".join(config) + "\n")
hostname = "watchdog-defensive" if mode == "defensive" else "watchdog-eicar"
(work / "meta-data").write_text(f"instance-id: {hostname}-smoke\nlocal-hostname: {hostname}\n")
PY
xorriso -as mkisofs -quiet -output "$work/seed.iso" -volid CIDATA -joliet -rock \
    "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$work/guest.qcow2" 12G
cp -- "$variables" "$work/vars.fd"

echo "Booting a fresh Ubuntu VM for the Watchdog check ($mode)."
timeout --kill-after=10s 1320 qemu-system-x86_64 -machine q35 -accel kvm -accel tcg \
    -cpu max -m "$memory" -smp 2 -display none -monitor none -serial "file:$work/guest.log" -no-reboot \
    -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
    -drive "if=pflash,format=raw,file=$work/vars.fd" \
    -drive "if=virtio,format=qcow2,file=$work/guest.qcow2" \
    -drive "media=cdrom,format=raw,readonly=on,file=$work/seed.iso" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    >"$work/qemu.log" 2>&1 &
vm=$!

deadline=$((SECONDS + 1140))
until grep -aq "${marker}_PASS" "$work/guest.log" 2>/dev/null; do
    if grep -aq "${marker}_FAIL" "$work/guest.log" 2>/dev/null ||
        ! kill -0 "$vm" 2>/dev/null || (( SECONDS >= deadline )); then
        echo "Guest failed before reporting success ($mode)." >&2
        exit 1
    fi
    sleep 2
done
if [[ $mode == defensive ]]; then
    grep -a 'WATCHDOG_DEFENSIVE_' "$work/guest.log"
    echo WATCHDOG_DEFENSIVE_VM_PASS
    exit
fi
grep -a 'WATCHDOG_EICAR_' "$work/guest.log"
if [[ $mode == *backup-source ]]; then
    fetch=(cat /var/tmp/watchdog-backup-export.tgz)
    [[ $mode != system-backup-source ]] || fetch=(sudo -n cat /var/tmp/watchdog-donor-proof)
    ssh -T -i "$work/vm-key" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$work/known_hosts" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=6 \
        -p "$ssh_port" ubuntu@127.0.0.1 "${fetch[@]}" >"$3"
    test -s "$3"
    exit
elif [[ $mode == *backup-destination || $mode == system-backup-primary ]]; then
    exit
fi
PYTHONPATH="$repo/tests:$repo" python3 -B "$smoke/eicar_browser.py" "$work" "$ssh_port" "$dashboard_port" "$mode"
echo WATCHDOG_EICAR_VM_PASS
