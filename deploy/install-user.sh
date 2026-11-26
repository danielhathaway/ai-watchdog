#!/bin/sh
set -eu
if [ "$(id -u)" -eq 0 ]; then
    echo "Run this installer as the desktop user." >&2
    exit 1
fi
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
case "$source_dir" in
    *[!a-zA-Z0-9_./-]*)
        echo "The checkout path must use letters, numbers, slashes, periods, underscores, and hyphens." >&2
        exit 1
        ;;
esac
sh "$source_dir/deploy/install-clamav.sh" "$@"
umask 077
state_dir="$source_dir/.watchdog"
mkdir -p "$state_dir"
if [ ! -e "$state_dir/config.json" ]; then
    install -m 0600 "$source_dir/deploy/config.json" "$state_dir/config.json"
fi

cat > "$state_dir/ai-watchdog-observe.service" <<UNIT
[Unit]
Description=AI Watchdog live observe-only monitor

[Service]
WorkingDirectory=$source_dir
ExecStart=/usr/bin/python3 -B -m watchdog --config $state_dir/config.json observe --directory $state_dir
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=default.target
UNIT

cat > "$state_dir/ai-watchdog-observe-supervisor.service" <<UNIT
[Unit]
Description=AI Watchdog observe-only heartbeat supervisor
Wants=ai-watchdog-observe.service
After=ai-watchdog-observe.service

[Service]
Type=notify
NotifyAccess=main
WatchdogSec=90s
WorkingDirectory=$source_dir
ExecStart=/usr/bin/python3 -B -m watchdog --config $state_dir/config.json observe-supervisor --directory $state_dir
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=default.target
UNIT

systemctl --user enable --now \
    "$state_dir/ai-watchdog-observe.service" \
    "$state_dir/ai-watchdog-observe-supervisor.service"
