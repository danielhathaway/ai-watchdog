import json
import logging
import subprocess
import threading
import time

from . import analysis, sensors, ssh_activity, store, system_checks
from .network_window import NetworkSampler
from .common import BASELINE, BOOT_ID, CONFIG, RESPONSE_RUNTIME, blockable, uptime, write_json

SENSOR_ERRORS = (OSError, ValueError, KeyError, subprocess.SubprocessError)


class Monitor:
    def __init__(self, settings, database, runtime, demo=False, baseline=BASELINE, response_runtime=None,
                 config=CONFIG, observe_directory=None):
        self.settings = settings
        self.database = database
        self.runtime = runtime
        self.demo = demo
        self.baseline = baseline
        self.response_runtime = response_runtime or RESPONSE_RUNTIME
        self.config = config
        self.observe_directory = observe_directory
        self.network = NetworkSampler(settings.get("interval", 10))
        self.integrity_seen = {}
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.antivirus = system_checks.AntivirusWorker(self) if not demo and settings.get("antivirus_paths") else None
        self.blocks = {}
        self.isolation_request = False
        store.initialize(database)
        if not demo and settings["enforce"]:
            with store.connect(database) as db:
                saved = store.property_get(db, "leased_blocks", {})
            if saved.get("boot_id") == BOOT_ID:
                self.blocks = saved["blocks"]

    def start(self):
        if not self.demo:
            self.network_worker = threading.Thread(
                target=self.network.run, args=(self.stop,), name="network-sampler", daemon=True,
            )
            self.network_worker.start()
        self.worker = threading.Thread(target=self.run, name="passive-monitor", daemon=True)
        self.worker.start()
        if not self.demo:
            threading.Thread(target=system_checks.run, args=(self,), name="scheduled-system-checks",
                             daemon=True).start()
            threading.Thread(target=ssh_activity.run, args=(self,), name="ssh-activity", daemon=True).start()
            if self.antivirus:
                threading.Thread(target=self.antivirus.run, name="antivirus", daemon=True).start()

    def run(self):
        while not self.stop.is_set():
            start = uptime()
            try:
                with self.lock:
                    self.scan()
                self.ready.set()
            except Exception:
                logging.exception("Monitoring cycle failed")
            self.stop.wait(max(0, self.settings["interval"] - (uptime() - start)))

    def response(self):
        if self.demo:
            return {"mode": "demo", "status": "observing", "isolated": False, "blocked": [],
                    "reason": "", "watchdog_alive": True}
        try:
            state = json.loads((self.response_runtime / "status.json").read_text())
            state["watchdog_alive"] = state["boot_id"] == BOOT_ID and 0 <= uptime() - state["at"] < 20
            return state
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            return {"mode": "enforce" if self.settings["enforce"] else "observe", "status": "unavailable",
                    "isolated": False, "blocked": [], "reason": "", "watchdog_alive": False}

    def scan(self, active=False):
        if self.demo:
            from .demo import sample
            return sample(self.database, active)
        at, now = uptime(), time.time()
        status = {}
        response = self.response()
        self.blocks = {address: deadline for address, deadline in self.blocks.items() if deadline > at}
        with store.connect(self.database) as db:
            db.execute("BEGIN IMMEDIATE")

            def read(name, function, default):
                try:
                    value = function()
                except SENSOR_ERRORS as error:
                    status[name] = "degraded"
                    store.event(db, now, "medium", "sensor", f"{name} sensor unavailable",
                                type(error).__name__, name, cooldown=600)
                    return default
                status[name] = "ready"
                return value

            window = self.network.snapshot()
            window_details = (
                {key: window[key] for key in ("at", "window_start", "window_seconds")} if window else {}
            )
            interface = window["interface"] if window else {
                "method": "unavailable", "uplinks": [], "interfaces": [], "rx": None, "tx": None,
            }
            attribution = window["attribution"] if window else {
                "state": "warming", "protocols": {"tcp": "warming", "udp": "off"},
            }
            rx, tx = interface["rx"], interface["tx"]
            status["Traffic"] = "warming" if not window else (
                "ready" if interface["uplinks"] and (rx is not None or tx is not None) else "degraded"
            )
            tcp = attribution["protocols"]["tcp"]
            udp = attribution["protocols"]["udp"]
            status["TCP process attribution"] = "degraded" if tcp == "unavailable" else tcp
            if udp != "off":
                status["UDP process attribution"] = "ready" if udp == "ready" else "degraded"
            baseline = store.property_get(db, "traffic_baseline", {})
            if window and interface["uplinks"]:
                basis = {key: interface[key] for key in ("method", "uplinks")}
                basis["window_seconds"] = window["window_seconds"]
                if baseline.get("basis") != basis:
                    baseline = {"basis": basis, "since": now}
                    store.property_set(db, "traffic_baseline", baseline)
            store.property_set(db, "interface_traffic", {
                **interface, **window_details, "baseline_since": baseline.get("since"),
            })
            connections, outbound, inbound = read("TCP connections", sensors.sockets, (None, 0, 0))
            devices = read("Neighbor discovery", sensors.neighbors, [])
            for mac, address, device_interface in devices[:500]:
                self.remember(db, now, mac, address, device_interface)
            cursor = store.property_get(db, "journal_cursor")
            failures, cursor, gap = read("SSH journal", lambda: sensors.ssh_failures(cursor, now), ([], cursor, False))
            if gap:
                status["SSH journal"] = "degraded"
                store.event(db, now, "medium", "sensor", "SSH journal coverage gap",
                            "The cursor expired or the journal exceeded the per-scan limit.", "ssh-gap", cooldown=600)
            db.executemany("INSERT OR IGNORE INTO failures VALUES (?,?,?)", failures)
            store.property_set(db, "journal_cursor", cursor)
            db.execute("DELETE FROM failures WHERE at < ?", (now - 120,))
            bursts = db.execute(
                "SELECT address, count(*) AS attempts FROM failures GROUP BY address HAVING attempts >= 8 "
                "ORDER BY attempts DESC LIMIT 64"
            ).fetchall()
            risk = self.integrity(db, now, status)
            new_sources = {address for _, address, _ in failures}
            for row in bursts:
                address = blockable(row["address"], self.settings["protected_networks"])
                severity = "high" if row["attempts"] >= 12 else "medium"
                store.event(db, now, severity, "authentication", "Repeated SSH authentication failures",
                            f'{row["attempts"]} failures within two minutes', row["address"], cooldown=180)
                if (address and row["attempts"] >= 12 and address in new_sources
                        and not gap and address not in self.blocks and len(self.blocks) < 64):
                    self.blocks[address] = at + 900
                    if not self.settings["enforce"]:
                        store.event(db, now, "info", "response", "Temporary block recommended",
                                    "Observed 12 or more SSH failures in two minutes.", address)
                risk = max(risk, 70 if severity == "high" else 45)

            metrics = {"rx": rx, "tx": tx, "connections": connections, "failures": (
                db.execute("SELECT count(*) FROM failures").fetchone()[0] if status["SSH journal"] == "ready" else None
            )}
            history = {
                metric: [row[0] for row in db.execute(
                    f"SELECT {metric} FROM samples WHERE training=1 AND {metric} IS NOT NULL AND at>=? "
                    "ORDER BY id DESC LIMIT 720", (
                        max(now - 86400, baseline.get("since", 0)) if metric in {"rx", "tx"} else now - 86400,
                    ),
                )]
                for metric in analysis.FLOORS
            }
            deviations = analysis.deviations(metrics, history)
            traffic_spikes = [item for item in deviations if item["metric"] in {"rx", "tx"}]
            fresh_spike = False
            if traffic_spikes:
                # Save the window once, including its process rates, independent of the alert cooldown.
                spike_at = window["at"]
                if not db.execute("SELECT 1 FROM interface_spikes WHERE at=?", (spike_at,)).fetchone():
                    spike = {**interface, **window_details, "deviations": traffic_spikes, "attribution": attribution}
                    db.execute("INSERT INTO interface_spikes(at,snapshot) VALUES (?,?)", (spike_at, json.dumps(spike)))
                    fresh_spike = True
            for item in deviations:
                metric = item["metric"]
                traffic_metric = metric in {"rx", "tx"}
                if traffic_metric and not fresh_spike:
                    continue
                event_at = window["at"] if traffic_metric else now
                event_id = store.event(
                    db, event_at, "medium", "anomaly", "Activity exceeded its local baseline",
                    f'{item["observed"]:,} observed vs {item["threshold"]:,} threshold'
                    + (" B/s" if traffic_metric else " connections"), metric, cooldown=300,
                )
                if event_id and traffic_metric:
                    snapshot = {"state": attribution["state"], "direction": metric,
                                "protocols": attribution["protocols"], **window_details}
                    if attribution["state"] == "ready":
                        snapshot.update(processes=attribution[metric], unattributed=attribution["unattributed"][metric])
                    db.execute("INSERT INTO traffic_attribution VALUES (?,?,?)",
                               (event_id, event_at, json.dumps(snapshot)))
            if outbound >= 25 or inbound >= 25:
                risk = max(risk, 55)
                store.event(db, now, "medium", "connections", "Unusual TCP handshake activity",
                            f"{outbound} pending outbound sockets and {inbound} pending inbound peers.",
                            cooldown=300)
            if deviations:
                risk = max(risk, min(65, 30 + 15 * len(deviations)))

            previous_response = store.property_get(db, "response_event")
            response_key = [response["status"], response["reason"], response["watchdog_alive"]]
            if previous_response != response_key:
                if response["reason"] or not response["watchdog_alive"]:
                    severity = "critical" if response["status"] in {"isolated", "failed", "would-isolate"} else "medium"
                    store.event(db, now, severity, "watchdog", "Containment watchdog: " + response["status"],
                                response["reason"])
                store.property_set(db, "response_event", response_key)
            old_blocks = set(store.property_get(db, "applied_blocks", []))
            if response["watchdog_alive"]:
                new_blocks = set(response["blocked"])
                for address in sorted(new_blocks - old_blocks):
                    store.event(db, now, "high", "response", "Firewall block applied", "Temporary IP quarantine.", address)
                for address in sorted(old_blocks - new_blocks):
                    store.event(db, now, "info", "response", "Firewall block cleared", "", address)
                store.property_set(db, "applied_blocks", sorted(new_blocks))
            if response["status"] in {"isolated", "failed", "would-isolate"}:
                risk = max(risk, 95)

            store.property_set(db, "process_traffic", {
                **window_details, **{key: value for key, value in attribution.items() if key not in {"rx", "tx"}},
            })
            if not active:
                training = int(risk < 45 and not deviations and response["status"] == "observing")
                last_recorded = store.property_get(db, "last_recorded_network_window")
                new_window = window and window["at"] != last_recorded
                if new_window:
                    store.property_set(db, "last_recorded_network_window", window["at"])
                db.execute("INSERT INTO samples(at,rx,tx,connections,failures,risk,training) VALUES (?,?,?,?,?,?,?)",
                           (now, rx if new_window else None, tx if new_window else None,
                            connections, metrics["failures"], risk, training))
            store.property_set(db, "sensors", status)
            if self.settings["enforce"]:
                saved_lease = {"boot_id": BOOT_ID, "blocks": self.blocks}
                if store.property_get(db, "leased_blocks") != saved_lease:
                    store.property_set(db, "leased_blocks", saved_lease)
            if now - store.property_get(db, "last_cleanup", 0) >= 3600:
                store.expire(db, now, self.settings["retention_days"])
                store.property_set(db, "last_cleanup", now)
        write_json(self.runtime / "heartbeat.json", {
            "boot_id": BOOT_ID, "at": uptime(), "blocks": self.blocks, "isolate": self.isolation_request,
        }, mode=0o640)
        return {
            "risk": risk, "deviations": deviations, "failed_ssh": metrics["failures"],
            "sensor_health": status, "baseline_samples": {key: len(values) for key, values in history.items()},
            "block_candidates": len(self.blocks), "containment_requested": self.isolation_request,
            "network_window": window_details or None,
        }

    def remember(self, db, now, mac, address, interface):
        identity = f"{mac}@{interface}"
        if not db.execute("SELECT 1 FROM devices WHERE identity=?", (identity,)).fetchone():
            previous = db.execute(
                "SELECT mac FROM devices WHERE address=? AND interface=? AND last_seen>=? LIMIT 1",
                (address, interface, now - 3600),
            ).fetchone()
            store.event(db, now, "medium" if previous else "info", "device",
                        "Neighbor address changed hardware identity" if previous else "New neighbor observed",
                        f"{mac} via {interface}", address, cooldown=60)
        db.execute("""INSERT INTO devices VALUES (?,?,?,?,?,?,1)
            ON CONFLICT(identity) DO UPDATE SET address=excluded.address,
            last_seen=excluded.last_seen, observations=devices.observations+1""",
                   (identity, mac, address, interface, now, now))

    def integrity(self, db, now, status):
        status["File integrity"] = "ready"
        try:
            baseline = json.loads(self.baseline.read_text()).get("files", {})
            if not isinstance(baseline, dict):
                raise ValueError("Invalid baseline")
        except (OSError, ValueError, AttributeError):
            status["File integrity"] = "needs baseline"
            self.integrity_seen.clear()
            return 0
        risk = 0
        for path in self.settings["integrity_paths"]:
            prior = self.integrity_seen.pop(path, None)
            if path not in baseline:
                status["File integrity"] = "degraded"
                continue
            try:
                observed = sensors.fingerprint(path)
            except SENSOR_ERRORS:
                status["File integrity"] = "degraded"
                store.event(db, now, "medium", "sensor", "Integrity path unreadable", "", path, cooldown=600)
                continue
            if baseline[path] != observed:
                first_seen = prior[1] if prior and observed == prior[0] else uptime()
                self.integrity_seen[path] = (observed, first_seen)
                confirmed = (path in self.settings["isolate_on_integrity"]
                             and uptime() - first_seen >= self.settings["interval"] - 1)
                self.isolation_request |= confirmed
                risk = max(risk, 95 if confirmed else 75)
                store.event(db, now, "high", "integrity", "Trusted file changed",
                            "Content, ownership, permissions, or target differs from the saved baseline.",
                            path, cooldown=900)
        return risk
