import io
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from watchdog import backup_crypto, backups, rollback, store


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

    def test_encrypted_backup_rejects_path_traversal_and_links(self):
        for member in (tarfile.TarInfo("../outside"), tarfile.TarInfo("state/token")):
            if member.name == "state/token":
                member.type = tarfile.SYMTYPE
                member.linkname = "/outside"
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as archive:
                archive.addfile(member)
            stream.seek(0)
            with self.assertRaisesRegex(ValueError, "unsafe or duplicate"):
                backup_crypto.unpack(stream, self.directory)
        self.assertEqual([], list(self.directory.iterdir()))

    def test_native_age_roundtrip_and_ciphertext_tampering(self):
        binary = Path(os.environ.get("WATCHDOG_TEST_AGE", backup_crypto.AGE))
        keygen = binary.with_name("age-keygen")
        if not binary.is_file() or not keygen.is_file():
            self.skipTest("age and age-keygen are required")
        source = self.directory / "backup"
        source.mkdir(mode=0o700)
        state = source / "state"
        state.mkdir(mode=0o700)
        (state / "config.json").write_text('{"port":9001}')
        (state / "token").write_text("a" * 43)
        store.initialize(state / "monitor.sqlite3")
        backups.seal(source, desktop=True)
        identity = self.directory / "identity"
        subprocess.run([keygen, "-o", identity], capture_output=True, check=True)
        recipient = subprocess.check_output([keygen, "-y", identity], text=True).strip()
        encrypted = self.directory / "backup.age"
        with patch.object(backup_crypto, "AGE", str(binary)):
            backup_crypto.export_backup(source, encrypted, recipient)
            self.assertTrue(encrypted.read_bytes().startswith(b"age-encryption.org/v1\n"))
            self.assertNotIn(b"a" * 43, encrypted.read_bytes())
            self.assertEqual(0o600, encrypted.stat().st_mode & 0o777)
            with backup_crypto.open_encrypted(encrypted, identity) as imported:
                self.assertEqual("desktop", backups.verify(imported)["mode"])
                self.assertEqual("a" * 43, (imported / "state/token").read_text())
            damaged = encrypted.read_bytes()
            encrypted.write_bytes(damaged[:-1] + bytes([damaged[-1] ^ 1]))
            with self.assertRaisesRegex(ValueError, "Could not decrypt"):
                with backup_crypto.open_encrypted(encrypted, identity):
                    self.fail("Tampered backup was accepted")

    def test_inventory_and_verification_detect_tampering(self):
        managed = self.directory / "inventory"
        current = managed / "backup-current"
        (current / "state").mkdir(mode=0o700, parents=True)
        managed.chmod(0o700)
        current.chmod(0o700)
        legacy = managed / "backup-legacy"
        legacy.mkdir(mode=0o700)
        state = current / "state"
        (state / "config.json").write_text("{}")
        (state / "token").write_text("a" * 43)
        store.initialize(state / "monitor.sqlite3")
        backups.seal(current, desktop=True)
        self.assertEqual("desktop", backups.verify(current)["mode"])
        self.assertEqual({str(current): "manifest-present", str(legacy): "unverified"},
                         {entry["path"]: entry["status"] for entry in backups.inventory(managed)})
        (state / "config.json").write_text('{"port":9001}')
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            backups.verify(current)
        (state / "monitor.sqlite3").write_bytes(b"not a database")
        backups.seal(current, desktop=True)
        with self.assertRaises(sqlite3.DatabaseError):
            backups.verify(current)

    def test_verified_restore_recovers_destination_if_startup_fails(self):
        deployment = rollback.Deployment(desktop=True)
        deployment.root = self.directory / "checkout"
        deployment.state = deployment.root / ".watchdog"
        deployment.config = deployment.state / "config.json"
        deployment.backups = deployment.state / "rollbacks"
        deployment.backups.mkdir(parents=True)
        package = deployment.root / "watchdog"
        (package / "static").mkdir(parents=True)
        for name in ("__init__.py", "__main__.py", "common.py", "monitor.py", "server.py"):
            (package / name).write_text(name)
        for name in rollback.ASSETS:
            (package / "static" / name).write_text(name)
        source = self.directory / "backup-donor"
        source.mkdir(mode=0o700)
        (source / "state").mkdir(mode=0o700)
        for state, marker, token, config in (
            (deployment.state, "destination", "a" * 43, "{}"),
            (source / "state", "donor", "b" * 43, '{"port": 9001}'),
        ):
            (state / "token").write_text(token)
            (state / "config.json").write_text(config)
            store.initialize(state / "monitor.sqlite3")
            with store.connect(state / "monitor.sqlite3") as db:
                store.property_set(db, "marker", marker)
        backups.seal(source, desktop=True)
        (source / "state/token").write_text("c" * 43)
        with patch.object(deployment, "stop") as stop:
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                deployment.restore(source)
            stop.assert_not_called()
        (source / "state/token").write_text("b" * 43)

        started = []
        def healthy(port, token, supervise):
            with store.connect(deployment.state / "monitor.sqlite3") as db:
                marker = store.property_get(db, "marker")
            started.append((port, token, marker))
            if marker == "donor":
                raise rollback.RollbackError("failed restored health check")

        with patch.object(deployment, "preflight", return_value=8765), patch.object(deployment, "active", return_value=True), \
             patch.object(deployment, "stop") as stop, patch.object(deployment, "start_healthy", side_effect=healthy), \
             redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(rollback.RollbackError, "original installation was restored"):
                deployment.restore(source)
        self.assertEqual(2, stop.call_count)
        self.assertEqual([(9001, "b" * 43, "donor"), (8765, "a" * 43, "destination")], started)
        self.assertEqual("{}", deployment.config.read_text())
        fallback, = deployment.backups.glob("backup-*")
        self.assertEqual("desktop", backups.verify(fallback)["mode"])
