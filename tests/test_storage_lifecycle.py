import tempfile
import unittest
from pathlib import Path

from watchdog import store


class StorageLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / "watchdog.sqlite3"
        store.initialize(self.database)

    def test_reopening_an_older_database_preserves_existing_samples_and_events(self):
        with store.connect(self.database) as db:
            db.execute("DROP TABLE interface_spikes")
            db.execute("DROP TABLE traffic_attribution")
            store.event(db, 100, "medium", "anomaly", "Legacy traffic spike", subject="rx")
            db.execute(
                "INSERT INTO samples(at,rx,tx,connections,failures,risk,training) VALUES (?,?,?,?,?,?,?)",
                (100, 1850, 1200, 3, 0, 0, 1),
            )

        store.initialize(self.database)
        with store.connect(self.database) as db:
            snapshot = store.snapshot(db, 110)
        self.assertEqual(1850, snapshot["samples"][0]["rx"])
        self.assertEqual("Legacy traffic spike", snapshot["events"][0]["title"])
        self.assertIsNone(snapshot["events"][0]["attribution"])
        self.assertEqual([], snapshot["interface_spikes"])

    def test_retention_prunes_old_spikes_and_attribution_with_their_events(self):
        with store.connect(self.database) as db:
            for when in (100, 90_000):
                event_id = store.event(db, when, "high", "anomaly", "Connection spike")
                db.execute("INSERT INTO traffic_attribution VALUES (?,?,?)", (event_id, when, "{}"))
                db.execute("INSERT INTO interface_spikes(at,snapshot) VALUES (?,?)", (when, "{}"))
                db.execute(
                    "INSERT INTO samples(at,rx,tx,connections,failures,risk,training) VALUES (?,?,?,?,?,?,?)",
                    (when, 1850, 1200, 3, 0, 0, 1),
                )
            store.expire(db, 100_000, 1)
            for table in ("samples", "events", "traffic_attribution", "interface_spikes"):
                with self.subTest(table=table):
                    self.assertEqual([90_000], [row[0] for row in db.execute(f"SELECT at FROM {table}")])
