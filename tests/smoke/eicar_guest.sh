#!/usr/bin/env bash
# Invoked by cloud-init inside the disposable guest.
set -euo pipefail
trap 'echo WATCHDOG_EICAR_GUEST_FAIL' ERR
port=$1
source /etc/os-release
echo "Testing on $PRETTY_NAME"
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
test ! -e /usr/bin/clamscan
test ! -e /usr/bin/freshclam
test ! -e /var/lib/clamav
echo "WATCHDOG_EICAR_PRECHECK ClamAV and its databases are absent"

uid=$(id -u ubuntu)
loginctl enable-linger ubuntu
systemctl start "user@$uid.service"
as_ubuntu() {
    runuser -u ubuntu -- env "XDG_RUNTIME_DIR=/run/user/$uid" \
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" "$@"
}
as_ubuntu mkdir /home/ubuntu/watchdog-smoke
cd /home/ubuntu/watchdog-smoke
as_ubuntu tar -xzf /var/tmp/watchdog-source.tgz
as_ubuntu ./deploy/install-user.sh
test "$(systemctl is-enabled clamav-freshclam.service)" = enabled
systemctl is-active --quiet clamav-freshclam.service
as_ubuntu systemctl --user is-active --quiet ai-watchdog-observe.service
echo "WATCHDOG_EICAR_INSTALL FreshClam is enabled and active and Watchdog is running"

has_database() {
    test -s "/var/lib/clamav/$1.cvd" || test -s "/var/lib/clamav/$1.cld"
}
deadline=$((SECONDS + 240))
until has_database daily && has_database main && has_database bytecode; do
    if (( SECONDS >= deadline )); then
        journalctl -u clamav-freshclam.service -n 25 --no-pager
        echo "WATCHDOG_EICAR_GUEST_FAIL FreshClam did not download the signature databases"
        exit 1
    fi
    sleep 2
done

as_ubuntu python3 -B - "$port" <<'PY'
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from watchdog.common import write_json

engine = subprocess.check_output(["clamscan", "--version"], text=True).strip()
print("WATCHDOG_EICAR_ENGINE", engine, flush=True)
port = int(sys.argv[1])
state = Path(".watchdog")
scope = Path.home() / "Downloads" / "Watchdog Scan"
scope.mkdir(mode=0o700, parents=True)
(scope / "benign.txt").write_text("Benign file for the clean antivirus rescan.\n")
sample = scope / "eicar.com.txt"
# The official 68-byte EICAR test string. The guest only writes it as text.
sample.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
try:
    config_path = state / "config.json"
    config = json.loads(config_path.read_text())
    config.update(port=port, antivirus_paths=[str(scope)])
    write_json(config_path, config)
    started = time.time()
    subprocess.run(["systemctl", "--user", "restart", "ai-watchdog-observe.service"], check=True)
    token = (state / "token").read_text().strip()
    request = Request(f"http://127.0.0.1:{port}/api/status", headers={"Authorization": "Bearer " + token})
    deadline = time.monotonic() + 110
    while time.monotonic() < deadline:
        time.sleep(1)
        try:
            with urlopen(request, timeout=5) as response:
                payload = json.load(response)
        except URLError:
            continue
        report = payload["system_checks"].get("antivirus", {})
        if report.get("at", 0) < started:
            continue
        row, = report["checks"]
        signature = re.search(re.escape(str(sample)) + r": [^\n]*eicar[^\n]* FOUND", row["detail"], re.IGNORECASE)
        if row["status"] != "fail" or not signature:
            raise AssertionError(f"Expected an EICAR detection in the scheduled scan: {row}")
        event, = [item for item in payload["events"] if item["subject"] == "antivirus/clamav"]
        if (event["severity"], event["title"], event["detail"]) != ("high", "ClamAV detected malware", row["detail"]):
            raise AssertionError(f"Unexpected antivirus event: {event}")
        print(f"WATCHDOG_EICAR_ACTIVITY event={event['id']} severity={event['severity']} detail={event['detail']}", flush=True)
        break
    else:
        raise SystemExit("The scheduled scan did not reach the dashboard")
finally:
    sample.unlink()
PY
echo WATCHDOG_EICAR_GUEST_PASS
