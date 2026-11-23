#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root." >&2
    exit 1
fi
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
for command in /usr/bin/python3 /usr/bin/journalctl /usr/bin/systemctl /usr/sbin/ip /usr/sbin/nft; do
    test -x "$command" || { echo "Missing $command" >&2; exit 1; }
done
getent group systemd-journal > /dev/null
if ! getent group ai-watchdog > /dev/null; then
    groupadd --system ai-watchdog
fi
if ! id ai-watchdog > /dev/null 2>&1; then
    useradd --system --gid ai-watchdog --no-create-home --shell /usr/sbin/nologin ai-watchdog
fi
install -d -o root -g root -m 0755 /opt/ai-watchdog/watchdog/static /etc/ai-watchdog
install -o root -g root -m 0644 "$source_dir"/watchdog/*.py /opt/ai-watchdog/watchdog/
install -o root -g root -m 0644 "$source_dir"/watchdog/static/* /opt/ai-watchdog/watchdog/static/
install -o root -g root -m 0644 "$source_dir"/deploy/*.service /etc/systemd/system/
if [ ! -e /etc/ai-watchdog/config.json ]; then
    install -o root -g root -m 0644 "$source_dir/deploy/config.json" /etc/ai-watchdog/config.json
fi
systemctl daemon-reload
echo "AI Watchdog files installed. Services can be started from the local console."
