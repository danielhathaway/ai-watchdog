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
sh "$source_dir/deploy/install-clamav.sh" "$@"
getent group systemd-journal > /dev/null
if ! getent group ai-watchdog > /dev/null; then
    groupadd --system ai-watchdog
fi
if ! id ai-watchdog > /dev/null 2>&1; then
    useradd --system --gid ai-watchdog --no-create-home --shell /usr/sbin/nologin ai-watchdog
fi
install -d -o root -g root -m 0755 /opt/ai-watchdog/watchdog/static /etc/ai-watchdog
install -d -o root -g root -m 0755 /var/lib/ai-watchdog-backup-health
install -o root -g root -m 0644 "$source_dir/LICENSE" /opt/ai-watchdog/LICENSE
install -o root -g root -m 0644 "$source_dir"/watchdog/*.py /opt/ai-watchdog/watchdog/
for asset in index.html app.css app.js; do
    install -o root -g root -m 0644 "$source_dir/watchdog/static/$asset" /opt/ai-watchdog/watchdog/static/
done
for unit in ai-watchdog.service ai-watchdog-response.service \
    ai-watchdog-vulnerability-refresh.service ai-watchdog-vulnerability-refresh.timer \
    ai-watchdog-backup-upload.service ai-watchdog-backup-upload.timer \
    ai-watchdog-backup-drill.service ai-watchdog-backup-drill.timer \
    ai-watchdog-backup-verifier@.service ai-watchdog-backup-verifier@.timer; do
    install -o root -g root -m 0644 "$source_dir/deploy/$unit" /etc/systemd/system/
done
if [ ! -e /etc/ai-watchdog/config.json ]; then
    install -o root -g root -m 0644 "$source_dir/deploy/config.json" /etc/ai-watchdog/config.json
fi
systemctl daemon-reload
echo "AI Watchdog files installed. Services can be started from the local console."
