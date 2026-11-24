#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "Usage: sudo ./deploy/install-udp.sh USERNAME" >&2
    exit 1
fi
uid=$(id -u -- "$1")
if [ "$uid" -eq 0 ]; then
    echo "Choose the non-root account running Watchdog." >&2
    exit 1
fi
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/udp" && pwd)
test -r /sys/kernel/btf/vmlinux
test -x /usr/bin/bpftrace
/usr/bin/bpftrace --dry-run "$source_dir/udp.bt" "$uid"
install -d -o root -g root -m 0755 /opt/ai-watchdog-udp
install -o root -g root -m 0644 "$source_dir/collector.py" "$source_dir/udp.bt" /opt/ai-watchdog-udp/
install -o root -g root -m 0644 "$source_dir/ai-watchdog-udp@.service" /etc/systemd/system/
systemctl daemon-reload
unit="ai-watchdog-udp@$uid.service"
if ! systemctl restart "$unit"; then
    systemctl stop "$unit"
    echo "UDP tracing did not publish a usable sample. Check the service journal." >&2
    exit 1
fi
systemctl enable "$unit"
