#!/bin/sh
set -eu

case "${1-}:$#" in
    --without-clamav:1) exit 0 ;;
    :0) ;;
    *)
        echo "Usage: $0 [--without-clamav]" >&2
        exit 2
        ;;
esac

if [ ! -x /usr/bin/apt-get ]; then
    echo "Automatic ClamAV setup is available on APT-based hosts."
    exit 0
fi

run_as_admin() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif [ -x /usr/bin/sudo ]; then
        /usr/bin/sudo "$@"
    else
        echo "ClamAV setup needs administrator access. Use --without-clamav to skip it." >&2
        return 1
    fi
}

if [ ! -x /usr/bin/clamscan ] || [ ! -x /usr/bin/freshclam ]; then
    echo "Installing ClamAV and FreshClam."
    run_as_admin /usr/bin/apt-get update
    run_as_admin /usr/bin/apt-get install -y clamav clamav-freshclam
fi

updater=clamav-freshclam.service
if [ "$(/usr/bin/systemctl is-enabled clamav-freshclam-once.timer 2>/dev/null || true)" = enabled ]; then
    updater=clamav-freshclam-once.timer
fi
if [ "$(/usr/bin/systemctl is-enabled "$updater" 2>/dev/null || true)" != enabled ]; then
    run_as_admin /usr/bin/systemctl enable --now "$updater"
elif ! /usr/bin/systemctl is-active --quiet "$updater"; then
    run_as_admin /usr/bin/systemctl start "$updater"
fi
