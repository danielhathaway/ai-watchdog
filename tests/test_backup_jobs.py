import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import backup_health, backup_job, backup_verifier, store


class BackupJobTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.remote = backup_job.Remote({"remote": "offsite:watchdog/endpoint", "rclone_config": Path("/private/rclone.conf")})
        self.ciphertext = self.workspace / "sealed.age"
        self.ciphertext.write_bytes(b"test ciphertext")

    def test_rotation_only_deletes_old_managed_archives_after_verified_upload(self):
        old = [f"watchdog-2026010{day}T000000000000Z-{'a' * 16}-{'b' * 64}.age" for day in range(1, 4)]
        commands = []

        def run(operation, *arguments, capture=False):
            commands.append((operation, *arguments))
            if len(commands) == 2:
                Path(arguments[-1]).write_bytes(self.ciphertext.read_bytes())
            elif operation == "lsjson":
                uploaded = commands[0][2].rsplit("/", 1)[-1]
                return json.dumps([{"Name": name} for name in [*old, uploaded, "unrelated.age"]]).encode()

        with patch.object(self.remote, "run", side_effect=run):
            current = self.remote.publish(self.ciphertext, self.workspace, 2)
        self.assertRegex(current, backup_job.OBJECT)
        self.assertEqual(["copyto", "copyto", "lsjson", "deletefile", "deletefile"], [item[0] for item in commands])
        self.assertEqual(old[:2], sorted(item[1].rsplit("/", 1)[-1] for item in commands[3:]))

    def test_failed_readback_prevents_any_retention_deletion(self):
        calls = []

        def run(operation, *arguments):
            calls.append(operation)
            if len(calls) == 2:
                Path(arguments[-1]).write_bytes(b"different ciphertext")

        with patch.object(self.remote, "run", side_effect=run):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                self.remote.publish(self.ciphertext, self.workspace, 2)
        self.assertEqual(["copyto", "copyto"], calls)

    def test_provider_retention_verifies_archive_without_deleting_older_objects(self):
        commands = []

        def run(operation, *arguments, capture=False):
            commands.append((operation, *arguments))
            if len(commands) == 2:
                Path(arguments[-1]).write_bytes(self.ciphertext.read_bytes())
            elif operation == "lsjson":
                uploaded = commands[0][2].rsplit("/", 1)[-1]
                older = f"watchdog-20260101T000000000000Z-{'a' * 16}-{'b' * 64}.age"
                return json.dumps([{"Name": uploaded}, {"Name": older}]).encode()

        with patch.object(self.remote, "run", side_effect=run):
            self.remote.publish(self.ciphertext, self.workspace, 0)
        self.assertEqual(["copyto", "copyto", "lsjson"], [item[0] for item in commands])

    def test_job_requires_dedicated_remote_and_private_credentials(self):
        job = self.workspace / "job.json"
        job.touch(mode=0o600)
        credentials = self.workspace / "rclone.conf"
        credentials.touch(mode=0o644)
        identity = self.workspace / "identity"
        identity.touch(mode=0o600)
        options = {"remote": "offsite:folder/../other", "rclone_config": credentials.name, "identity": identity.name}
        job.write_text(json.dumps(options))
        with self.assertRaisesRegex(ValueError, "dedicated subdirectory"):
            backup_job.settings(job, "drill")
        job.write_text(json.dumps({**options, "remote": "offsite:backups/endpoint"}))
        with self.assertRaisesRegex(ValueError, "private file"):
            backup_job.settings(job, "drill")
        credentials.chmod(0o600)
        self.assertEqual(credentials, backup_job.settings(job, "drill")["rclone_config"])


class BackupHealthTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.config = Path(workspace.name)
        self.database = self.config / "monitor.sqlite3"
        store.initialize(self.database)
        for name in backup_health.JOBS.values():
            path = self.config / name
            path.touch(mode=0o600)
            os.utime(path, (100, 100))
        self.receipts = {"upload": {}, "drill": {}}
        self.verifier_report = {}

    def refresh(self, now):
        with patch.object(backup_health, "CONFIG", self.config), patch.object(backup_health, "receipt", self.receipts.get), \
             patch.object(backup_health, "read_record", return_value=self.verifier_report):
            backup_health.refresh(self.database, now, 2, 2)
        with store.connect(self.database) as db:
            report = store.property_get(db, "backup_health", {})
            events = [row[0] for row in db.execute("SELECT title FROM events ORDER BY id")]
            return report, events

    def test_upload_alert_opens_once_recovers_after_success_and_can_recur(self):
        (self.config / backup_health.JOBS["drill"]).unlink()
        report, events = self.refresh(7299)
        self.assertEqual(("waiting", 7300, []), (report["upload"]["status"], report["upload"]["deadline"], events))
        self.refresh(7300)
        report, events = self.refresh(7301)
        self.assertEqual(("overdue", ["Scheduled backup upload missed"]), (report["upload"]["status"], events))
        self.receipts["upload"] = {"success_at": 7301}
        report, events = self.refresh(7302)
        self.assertEqual("healthy", report["upload"]["status"])
        self.assertEqual("Scheduled backup uploads recovered", events[-1])
        _, events = self.refresh(14501)
        self.assertEqual("Scheduled backup upload missed", events[-1])

    def test_failed_drill_is_retained_when_recovery_precedes_the_next_poll(self):
        self.receipts["drill"] = {"failure_at": 1000, "success_at": 1001}
        self.refresh(1002)
        report, events = self.refresh(1003)
        self.assertEqual("healthy", report["drill"]["status"])
        self.assertEqual(["Scheduled restore drill failed", "Scheduled restore drill recovered"], events)
        (self.config / backup_health.JOBS["drill"]).unlink()
        report, _ = self.refresh(1004)
        self.assertNotIn("drill", report)

    def test_drill_remains_overdue_until_success_without_repeating_failure_alerts(self):
        self.receipts["upload"] = {"success_at": 7299}
        self.receipts["drill"] = {"failure_at": 7299}
        self.refresh(7301)
        self.receipts["drill"] = {"failure_at": 7302}
        report, events = self.refresh(7303)
        self.assertEqual("overdue", report["drill"]["status"])
        self.assertEqual(["Scheduled restore drill failed", "Scheduled restore drill overdue"], events)
        self.receipts["drill"]["success_at"] = 7304
        report, events = self.refresh(7305)
        self.assertEqual("healthy", report["drill"]["status"])
        self.assertEqual(["Scheduled restore drill recovered", "Scheduled restore drill is current again"], events[-2:])

    def test_first_authenticated_verifier_report_can_close_an_overdue_alert(self):
        path = self.config / backup_health.VERIFIER_CONFIG["import"]
        path.touch(mode=0o600)
        os.utime(path, (100, 100))
        report, events = self.refresh(7301)
        self.assertEqual("overdue", report["verifier"]["status"])
        self.assertIn("Verifier restore drill overdue", events)
        self.verifier_report = {"verifier": "test-verifier", "sent_at": 7303, "success_at": 7302}
        report, events = self.refresh(7304)
        self.assertEqual(("healthy", "test-verifier"), (report["verifier"]["status"], report["verifier"]["verifier"]))
        self.assertIn("Verifier restore drill is current again", events)


class BackupVerifierTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.report = {"version": 1, "verifier": "test-verifier", "sent_at": 1000, "failure_at": 990}

    def envelope(self, payload):
        return json.dumps({"payload": payload, "mac": backup_verifier.signature(payload, self.key)}).encode()

    def test_rejects_forged_payload_wrong_verifier_and_future_time(self):
        raw = self.envelope(self.report)
        self.assertEqual(self.report, backup_verifier.validate(raw, "test-verifier", self.key, 1000))
        forged = json.loads(raw)
        forged["payload"]["success_at"] = 999
        for message, identity, now in ((json.dumps(forged).encode(), "test-verifier", 1000),
                                       (raw, "other-verifier", 1000), (raw, "test-verifier", 800),
                                       (self.envelope({**self.report, "failure_at": 1001}), "test-verifier", 1000)):
            with self.assertRaisesRegex(ValueError, "invalid or its signature"):
                backup_verifier.validate(message, identity, self.key, now)

    def test_import_preserves_latest_verified_report_on_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verifier.json"
            with patch.object(backup_health, "STATE", path.parent), patch.object(backup_health, "check_directory"), \
                 patch.object(backup_health, "read_record", side_effect=lambda _: json.loads(path.read_bytes()) if path.exists() else {}):
                backup_verifier.import_report(self.report)
                backup_verifier.import_report({**self.report, "sent_at": 999})
                self.assertEqual(self.report, json.loads(path.read_bytes()))
