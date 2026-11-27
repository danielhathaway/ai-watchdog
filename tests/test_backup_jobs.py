import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import backup_job


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
