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
Wants=ai-watchdog-observe-vulnerability-refresh.timer

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

cat > "$state_dir/ai-watchdog-observe-vulnerability-refresh.service" <<UNIT
[Unit]
Description=Refresh AI Watchdog user vulnerability advisories
PartOf=ai-watchdog-observe.service
After=ai-watchdog-observe.service

[Service]
Type=oneshot
WorkingDirectory=$source_dir
ExecStart=/usr/bin/python3 -B -m watchdog vulnerabilities --directory $state_dir refresh
TimeoutStartSec=20min
MemoryHigh=192M
MemoryMax=384M
Nice=10
NoNewPrivileges=yes
UMask=0077
UNIT

sed 's/PartOf=ai-watchdog.service/PartOf=ai-watchdog-observe.service/' \
    "$source_dir/deploy/ai-watchdog-vulnerability-refresh.timer" \
    > "$state_dir/ai-watchdog-observe-vulnerability-refresh.timer"
systemctl --user link \
    "$state_dir/ai-watchdog-observe-vulnerability-refresh.service" \
    "$state_dir/ai-watchdog-observe-vulnerability-refresh.timer"

systemctl --user enable --now \
    "$state_dir/ai-watchdog-observe.service" \
    "$state_dir/ai-watchdog-observe-supervisor.service"
systemctl --user start ai-watchdog-observe-vulnerability-refresh.timer
