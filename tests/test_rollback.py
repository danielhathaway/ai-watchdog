import io
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from watchdog import rollback, store


class RollbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def test_backup_includes_committed_wal_and_restores_a_private_database(self):
        current = self.directory / "monitor.sqlite3"
        store.initialize(current)
        backup = self.directory / "backup.sqlite3"
        writer = sqlite3.connect(current)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO properties VALUES ('marker', '1')")
        writer.commit()
        self.assertTrue(current.with_name("monitor.sqlite3-wal").stat().st_size)
        metadata = rollback.backup_database(current, backup)
        self.assertEqual(0o600, backup.stat().st_mode & 0o777)
        writer.execute("UPDATE properties SET value='2'")
        writer.commit()
        writer.close()
        rollback.restore_database(backup, current, metadata)
        with store.connect(current) as db:
            self.assertEqual(1, store.property_get(db, "marker"))

    def test_failed_candidate_restores_code_database_and_service(self):
        deployment = rollback.Deployment(desktop=True)
        deployment.root = self.directory / "checkout"
        deployment.state = deployment.root / ".watchdog"
        deployment.config = deployment.state / "config.json"
        deployment.backups = deployment.state / "rollbacks"
        deployment.backups.mkdir(parents=True)
        deployment.config.write_text("{}")
        (deployment.state / "token").write_text("a" * 43)
        database = deployment.state / "monitor.sqlite3"
        store.initialize(database)
        with store.connect(database) as connection:
            store.property_set(connection, "marker", "original")

        source = self.directory / "source"
        for root, marker in ((deployment.root, "original"), (source, "candidate")):
            package = root / "watchdog"
            (package / "static").mkdir(parents=True)
            for file in ("__init__.py", "__main__.py", "common.py", "monitor.py", "server.py"):
                (package / file).write_text(marker)
            for file in rollback.ASSETS:
                (package / "static" / file).write_text(marker)

        health = []
        def start(port, token, supervise):
            package = deployment.root / "watchdog"
            marker = (package / "__main__.py").read_text()
            health.append((marker, port, supervise))
            self.assertEqual("a" * 43, token)
            if marker == "candidate":
                with store.connect(database) as connection:
                    store.property_set(connection, "marker", "failed-start")
                raise rollback.RollbackError("candidate failed health check")

        with patch.object(deployment, "active", return_value=True), patch.object(deployment, "stop") as stop, \
             patch.object(deployment, "start_healthy", side_effect=start), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(rollback.RollbackError, "original installation was restored"):
                deployment.replace(source, 8765)
        self.assertEqual(2, stop.call_count)
        self.assertEqual([("candidate", 8765, True), ("original", 8765, True)], health)
        self.assertEqual("original", (deployment.root / "watchdog/__main__.py").read_text())
        with store.connect(database) as connection:
            self.assertEqual("original", store.property_get(connection, "marker"))
        backup, = deployment.backups.glob("backup-*")
        self.assertEqual(0o700, backup.stat().st_mode & 0o777)
        self.assertEqual(os.getuid(), backup.stat().st_uid)
        with store.connect(backup / "state/monitor.sqlite3") as connection:
            self.assertEqual("original", store.property_get(connection, "marker"))

    def test_backup_rejects_symbolic_links(self):
        original = self.directory / "original"
        original.write_text("fixture")
        link = self.directory / "link"
        link.symlink_to(original)
        output = self.directory / "copy"
        with self.assertRaises(OSError):
            rollback.copy_regular(link, output)
        self.assertFalse(output.exists())
