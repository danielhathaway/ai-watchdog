import math
import random
import time

from . import store

DEVICES = [
    ("c4:0a:cb:72:1e:08", "192.168.1.1", "wlan0"),
    ("d8:bb:c1:36:e2:91", "192.168.1.12", "wlan0"),
    ("a4:83:e7:12:fb:11", "192.168.1.18", "wlan0"),
    ("28:bd:89:01:4f:0c", "192.168.1.24", "wlan0"),
]
SENSORS = {name: "ready" for name in (
    "Traffic", "TCP connections", "Neighbor discovery", "SSH journal", "File integrity",
)}


def sample(path, active):
    at = time.time()
    with store.connect(path) as db:
        if not db.execute("SELECT 1 FROM samples LIMIT 1").fetchone():
            randomizer = random.Random(27)
            for index in range(61):
                shape = math.exp(-((index - 38) / 5) ** 2)
                noise = randomizer.random()
                at_sample = at - (61 - index) * 60
                db.execute("INSERT INTO samples VALUES(NULL,?,?,?,?,?,?,1)", (
                    at_sample, round(16000 + 54000 * noise + shape * 315000),
                    round(7000 + 25000 * noise + shape * 137000), 8 + int(10 * noise),
                    3 if 37 <= index <= 39 else 0, 32 if 37 <= index <= 39 else 12,
                ))
            for index, (mac, ip, interface) in enumerate(DEVICES):
                db.execute("INSERT INTO devices VALUES(?,?,?,?,?,?,?)",
                           (mac + "@" + interface, mac, ip, interface, at - 86000, at - index * 33, 16))
            store.event(db, at - 4800, "info", "integrity", "Integrity baseline loaded", "3 paths verified")
            store.event(db, at - 2200, "medium", "anomaly", "Outbound traffic above baseline",
                        "The rate returned to the expected range.", "wlan0")
            store.event(db, at - 740, "info", "device", "New neighbor observed", "via wlan0", "192.168.1.24")
            store.event(db, at - 96, "info", "watchdog", "Containment watchdog ready", "Sample environment")
        if not active:
            wave = abs(math.sin(at / 36))
            db.execute("INSERT INTO samples VALUES(NULL,?,?,?,?,?,?,1)",
                       (at, 28000 + 25000 * wave, 10000 + 18000 * wave, 12, 0, 12))
        store.property_set(db, "sensors", SENSORS)
    return {"risk": 12, "deviations": [], "failed_ssh": 0, "sensor_health": SENSORS,
            "baseline_samples": {"rx": 61, "tx": 61, "connections": 61},
            "block_candidates": 0, "containment_requested": False}
