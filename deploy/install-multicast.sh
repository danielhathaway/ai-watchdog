#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "Usage: sudo ./deploy/install-multicast.sh USERNAME" >&2
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
/usr/bin/bpftrace -q "$source_dir/multicast.bt" "$uid" > /dev/null
install -d -o root -g root -m 0755 /opt/ai-watchdog-multicast
install -o root -g root -m 0644 "$source_dir/multicast_collector.py" "$source_dir/multicast.bt" \
    "$source_dir/COPYING" /opt/ai-watchdog-multicast/
install -o root -g root -m 0644 "$source_dir/../../LICENSE" /opt/ai-watchdog-multicast/LICENSE
install -o root -g root -m 0644 "$source_dir/ai-watchdog-multicast@.service" \
    "$source_dir/ai-watchdog-multicast@.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl start "ai-watchdog-multicast@$uid.service"
systemctl enable --now "ai-watchdog-multicast@$uid.timer"
