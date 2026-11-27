import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import ssh_activity as activity, store
from watchdog.common import configuration

AT = 1_800_000_000
TARGET = "example.service"


def entry(number, message, exe, *, at=AT, pid="12", audit="20", uid="1000", **fields):
    return {"__CURSOR": f"cursor-{number}", "__REALTIME_TIMESTAMP": str(int(at * 1_000_000)),
            "_BOOT_ID": activity.BOOT_ID.replace("-", ""), "_EXE": exe, "_PID": pid,
            "_UID": "0", "_AUDIT_SESSION": audit, "_AUDIT_LOGINUID": uid, "MESSAGE": message, **fields}


def login(at=AT):
    return [
        entry(1, "Accepted publickey for deploy from 2001:db8::5 port 2234 ssh2: ED25519 SHA256:private",
              activity.SSH[1], at=at, audit="4294967295", uid="4294967295"),
        entry(2, "pam_unix(sshd:session): session opened for user deploy(uid=1000) by (uid=0)",
              activity.SSH[1], at=at + 1),
    ]


def sudo(command="/usr/bin/systemctl start example.service", at=AT + 2, number=3):
    return [
        entry(number, f"  deploy : TTY=pts/9 ; PWD=/private/work ; USER=root ; COMMAND={command}",
              "/usr/bin/sudo.ws", at=at, pid="99"),
        entry(number + 1, "pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1000)",
              "/usr/bin/sudo.ws", at=at + 1, pid="99"),
    ]


def start(target=TARGET, at=AT + 4):
    return entry(5, "Started Example.", activity.SYSTEMD[0], at=at, pid="1",
                 UNIT=target, MESSAGE_ID=activity.UNIT_STARTED)


class SSHActivityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.database = self.directory / "watchdog.sqlite3"
        store.initialize(self.database)

    def feed(self, records, now=AT + 5, allowed=()):
        output = "\n".join(map(json.dumps, records))
        with patch.object(activity, "execute", return_value=output) as query:
            activity.check(self.database, now, allowed)
        return query.call_args.args

    def events(self):
        with store.connect(self.database) as db:
            return db.execute("SELECT severity, detail, subject FROM events WHERE kind='ssh-activity'").fetchall()

    def test_correlation_survives_separate_scans_and_replays_without_sensitive_fields(self):
        args = self.feed(login(), AT + 1)
        self.assertIn("--since", args)
        self.assertEqual([], self.events())
        args = self.feed(sudo(), AT + 3)
        self.assertEqual("cursor-2", args[args.index("--after-cursor") + 1])
        self.assertIn("@1800000003.000000", args)
        self.feed([start()])
        self.feed([start()], AT + 7)
        alert, = self.events()
        self.assertEqual("medium", alert["severity"])
        self.assertIn("deploy from 2001:db8::5", alert["detail"])
        self.assertIn("Systemd recorded a start for example.service", alert["detail"])
        with store.connect(self.database) as db:
            state = store.property_get(db, activity.STATE)
            self.assertEqual("ready", store.sensor_status(db)[activity.SENSOR])
        self.assertNotIn("private", json.dumps(state))
        self.assertNotIn("COMMAND=", json.dumps(state))

    def test_other_sessions_unconfirmed_actions_and_untrusted_records_do_not_join(self):
        cases = (
            (login(), [{**row, "_AUDIT_SESSION": "22"} for row in sudo()], start()),
            (login(), [{**row, "_AUDIT_LOGINUID": "1001"} for row in sudo()], start()),
            ([login()[0], {**login()[1], "_PID": "13"}], sudo(), start()),
            ([{**row, "_EXE": "/usr/bin/logger"} for row in login()], sudo(), start()),
            (login(), [sudo()[0]], start()),
            (login(), [sudo()[0], {**sudo()[1], "_PID": "98"}], start()),
            (login(), sudo(), start("other.service")),
            (login(), sudo(), {**start(), "_PID": "900"}),
            (login(), sudo(), start(at=AT + 1.1)),
            (login(), sudo(), {**start(), "_BOOT_ID": "a" * 32}),
        )
        for ssh, privileged, unit in cases:
            with self.subTest(ssh=ssh, privileged=privileged, unit=unit):
                with store.connect(self.database) as db:
                    db.execute("DELETE FROM properties WHERE key=?", (activity.STATE,))
                self.feed([*ssh, *privileged, unit])
                self.assertEqual([], self.events())

    def test_expected_targets_and_nonchanging_commands_do_not_alert(self):
        self.feed([*login(), *sudo(), start()], allowed=[TARGET])
        self.assertEqual([], self.events())
        for command in (
            "/usr/bin/systemctl status example.service",
            "/usr/bin/systemctl --user start example.service",
            "/usr/bin/cp /tmp/data /home/deploy/notes",
            "/usr/bin/sh -c 'systemctl start example.service'",
        ):
            self.assertIsNone(activity.approved_target(command))
        self.assertEqual(("file", "/etc/cron.d/example"), activity.approved_target(
            "/usr/bin/install -m 0644 /tmp/file /etc/cron.d/example"))
        self.assertIsNone(activity.approved_target("/usr/bin/tee /etc/systemd/system/../example.service"))

    def test_persistence_requires_fresh_file_or_matching_enablement_link(self):
        directory = self.directory / "multi-user.target.wants"
        directory.mkdir()
        base = time.time()
        at = base - 8
        unit_file = self.directory / TARGET
        unit_file.write_text("[Unit]\nDescription=Test only\n")
        with patch.object(activity, "SYSTEM_UNITS", self.directory):
            command = f"/usr/bin/install -m 0644 /tmp/example {unit_file}"
            self.feed([*login(at), *sudo(command, at + 2)], time.time())
            installed, = self.events()
            self.assertEqual("high", installed["severity"])
            self.assertIn(str(unit_file), installed["detail"])
            enabled = directory / "enabled.service"
            enabled.symlink_to("/usr/lib/systemd/system/enabled.service")
            self.feed(sudo("/usr/bin/systemctl --now enable enabled.service", at + 3, number=6), time.time())
            self.assertEqual(2, len(self.events()))
            self.assertTrue(any(str(enabled) in row["detail"] for row in self.events()))
            stale = self.directory / "stable.service"
            stale.touch()
            later = time.time() + 5
            self.feed(sudo(f"sudoedit {stale}", later, number=8), later + 2)
        self.assertEqual(2, len(self.events()))

    def test_cursor_gap_discards_pending_login_and_recovers(self):
        self.feed(login(), AT + 1)
        error = subprocess.CalledProcessError(1, [activity.sensors.JOURNAL])
        raw = "\n".join(map(json.dumps, [*sudo(), start()]))
        with patch.object(activity, "execute", side_effect=[error, raw]):
            activity.check(self.database, AT + 5)
        with store.connect(self.database) as db:
            self.assertEqual("degraded", store.sensor_status(db)[activity.SENSOR])
            state = store.property_get(db, activity.STATE)
            self.assertEqual([], state["signals"])
            self.assertEqual("cursor-5", state["cursor"])
        self.feed([*sudo(at=AT + 6, number=6), {**start(at=AT + 8), "__CURSOR": "cursor-8"}], AT + 9)
        self.assertEqual([], self.events())
        with store.connect(self.database) as db:
            self.assertEqual("ready", store.sensor_status(db)[activity.SENSOR])

    def test_systemd_session_binding_can_replace_missing_audit_session(self):
        rows = [*login(), *sudo(), start()]
        for row in rows[1:-1]:
            row["_AUDIT_SESSION"] = "4294967295"
            row["_SYSTEMD_SESSION"] = "c12"
        self.feed(rows)
        self.assertEqual(1, len(self.events()))

    def test_scan_limit_marks_coverage_degraded_and_skips_partial_batch(self):
        rows = [*login(), *sudo(), start()]
        with patch.object(activity, "MAX_BATCH", len(rows) - 1):
            self.feed(rows)
        self.assertEqual([], self.events())
        with store.connect(self.database) as db:
            self.assertEqual("degraded", store.sensor_status(db)[activity.SENSOR])
            self.assertEqual("cursor-5", store.property_get(db, activity.STATE)["cursor"])

    def test_confirmation_window_can_extend_past_the_login_window(self):
        self.feed(login(), AT + 2)
        promoted = AT + activity.WINDOW - 1
        self.feed(sudo(at=promoted), promoted + 1)
        self.feed([start(at=promoted + 10)], promoted + 11)
        self.assertEqual(1, len(self.events()))

    def test_allowlist_accepts_exact_targets_only(self):
        path = self.directory / "config.json"
        path.write_text(json.dumps({"ssh_activity_allowed_targets": [TARGET, "/etc/cron.d/example", TARGET]}))
        self.assertEqual(["/etc/cron.d/example", TARGET], configuration(path)["ssh_activity_allowed_targets"])
        for invalid in ("*.service", "/etc/systemd/system/../example.service", "/tmp/example", 42):
            with self.subTest(invalid=invalid):
                path.write_text(json.dumps({"ssh_activity_allowed_targets": [invalid]}))
                with self.assertRaisesRegex(ValueError, "ssh_activity_allowed_targets"):
                    configuration(path)
