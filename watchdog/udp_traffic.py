import json
import os
import stat
from pathlib import Path

from .common import uptime

SNAPSHOT = Path(f"/run/ai-watchdog-udp-{os.geteuid()}/snapshot.json")
MAX_SIZE = 262144


def read_snapshot(path=SNAPSHOT):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (FileNotFoundError, PermissionError):
        return {"state": "off"}
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o400 or not 0 < info.st_size <= MAX_SIZE):
            raise ValueError("Invalid UDP snapshot file")
        data = json.loads(stream.read(MAX_SIZE + 1))

    ended, seconds, rows = data["ended"], data["seconds"], data["rows"]
    if type(ended) is not int or type(seconds) is not int or seconds != 5:
        raise ValueError("Invalid UDP sampling window")
    if not ended <= uptime() < ended + 3 * seconds:
        return {"state": "stale"}
    if not isinstance(rows, list) or len(rows) > 1024:
        raise ValueError("Invalid UDP process count")
    rates = {}
    for pid, name, rx, tx in rows:
        if (type(pid) is not int or not 0 < pid < 2**32 or not isinstance(name, str)
                or not 0 < len(name) <= 64 or not name.isprintable() or (pid, name) in rates
                or any(type(value) is not int or not 0 <= value < 2**64 for value in (rx, tx))):
            raise ValueError("Invalid UDP process reading")
        rates[pid, name] = (rx / seconds, tx / seconds)
    return {"state": "ready", "rates": rates}
