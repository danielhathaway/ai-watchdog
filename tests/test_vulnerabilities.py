import io
import json
import os
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import store, vulnerabilities as vuln
from watchdog.__main__ import main

CVE = "CVE-2026-10001"
WATCHDOG_ID = "WD-2026-001"
ECOSYSTEM = "Ubuntu:26.04:LTS"
RELEASE = {"ID": "ubuntu", "VERSION_ID": "26.04", "VERSION": "26.04 LTS"}


def archive(path, entries, advisory=CVE):
    data = json.dumps({"id": f"UBUNTU-{advisory}", "affected": entries,
                       "severity": [{"type": "Ubuntu", "score": "high"}]}).encode()
    with tarfile.open(path, "w:xz") as bundle:
        info = tarfile.TarInfo(f"osv/cve/2026/UBUNTU-{advisory}.json")
        info.size = len(data)
        bundle.addfile(info, io.BytesIO(data))


def affected(source, *, fixed=None, ecosystem=ECOSYSTEM):
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": fixed})
    return {"package": {"name": source, "ecosystem": ecosystem},
            "ranges": [{"type": "ECOSYSTEM", "events": events}]}


class VulnerabilitiesTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.db = self.directory / "monitor.sqlite3"
        store.initialize(self.db)
        self.archive = self.directory / "ubuntu.tar.xz"
        self.manifest = self.directory / "watchdog.json"
        self.manifest.write_text(json.dumps({"available_version": "0.1.1", "advisories": [
            {"id": WATCHDOG_ID, "events": [{"introduced": "0.1.0"}, {"fixed": "0.1.1"}]},
        ]}))

    def refresh(self, inventory, *, watchdog=True):
        with patch.object(vuln, "os_release", return_value=RELEASE), \
             patch.object(vuln, "package_inventory", return_value=inventory):
            return vuln.refresh(self.db, archive=self.archive, manifest=self.manifest if watchdog else None)

    def test_cli_rejects_refresh_as_the_wrong_account_before_opening_sqlite(self):
        args = ["watchdog", "vulnerabilities", "--directory", str(self.directory), "refresh"]
        with patch("sys.argv", args), patch("sys.stderr", new_callable=io.StringIO) as stderr, \
             patch("watchdog.__main__.os.geteuid", return_value=os.geteuid() + 1), \
             patch("watchdog.store.initialize") as initialize, patch("watchdog.__main__.os.umask"):
            with self.assertRaises(SystemExit) as error:
                main()
        self.assertEqual(2, error.exception.code)
        self.assertIn("account that owns the monitor state", stderr.getvalue())
        initialize.assert_not_called()

    def test_source_package_backport_and_removal_reconcile_persisted_rows(self):
        archive(self.archive, [
            affected("iproute2", fixed="1:6.1-1ubuntu2"),
            affected("other", ecosystem="Ubuntu:24.04:LTS"),
            affected("system-source"),
        ])
        inventory = {
            "iproute2": [("iproute2", "1:6.1-1ubuntu2~preview", "1:6.1-1ubuntu2~preview+b1")],
            "system-source": [("system-binary", "2.0", "2.0")],
            "other": [("other", "1.0", "1.0")],
        }
        report = self.refresh(inventory)
        rows = {item["component"]: item for item in vuln.unresolved(report)}
        self.assertEqual({"iproute2", "system-binary", "ai-watchdog"}, rows.keys())
        self.assertEqual("dependency", rows["iproute2"]["scope"])
        self.assertEqual("1:6.1-1ubuntu2", rows["iproute2"]["fixed"])
        self.assertEqual("vendor-listed", rows["system-binary"]["status"])
        self.assertEqual("watchdog", rows["ai-watchdog"]["scope"])
        with store.connect(self.db) as db:
            self.assertEqual(3, vuln.summary(db)["unresolved"])
        inventory["iproute2"] = [("iproute2", "1:6.1-1ubuntu2", "1:6.1-1ubuntu2")]
        del inventory["system-source"]
        result = self.refresh(inventory)
        self.assertEqual([WATCHDOG_ID], [item["advisory"] for item in vuln.unresolved(result)])
        updated = {item["component"]: item for item in result["findings"].values()}
        self.assertEqual("outside-affected-range", updated["iproute2"]["status"])
        self.assertEqual("installed-runtime-unverified", updated["iproute2"]["fix_verification"])
        self.assertEqual("removed", updated["system-binary"]["status"])
        self.assertEqual(rows["iproute2"]["first_seen"], updated["iproute2"]["first_seen"])

    def test_bad_feed_and_missing_manifest_retain_existing_findings(self):
        archive(self.archive, [affected("iproute2")])
        inventory = {"iproute2": [("iproute2", "1.0", "1.0")]}
        first = self.refresh(inventory)
        self.archive.write_bytes(b"bad archive")
        second = self.refresh({}, watchdog=False)
        self.assertEqual(first["findings"], second["findings"])
        self.assertEqual("failed", second["sources"][ECOSYSTEM]["status"])
        self.assertEqual(first["started_at"], second["sources"][ECOSYSTEM]["checked_at"])
        self.assertEqual("unconfigured", second["sources"]["watchdog"]["status"])

    def test_updates_distinguish_available_candidates_and_fix_threshold(self):
        archive(self.archive, [affected("iproute2", fixed="3.0"), affected("other", fixed="2.0")])
        result = self.refresh({"iproute2": [("iproute2", "1.0", "1.0")],
                               "other": [("other:arm64", "1.0", "1.0+b1")]})
        apt = "iproute2:\n  Installed: 1.0\n  Candidate: 2.0\nother:arm64:\n  Installed: 2.0+b1\n  Candidate: 2.0+b1\n"
        with patch.object(vuln, "command", return_value=apt) as command:
            updates = {item["component"]: item for item in vuln.updates(result)}
        self.assertEqual(("/usr/bin/apt-cache", "policy", "iproute2", "other:arm64"), command.call_args.args)
        self.assertTrue(updates["iproute2"]["update_available"])
        self.assertFalse(updates["iproute2"]["candidate_meets_fix_threshold"])
        self.assertFalse(updates["other:arm64"]["update_available"])
        self.assertIsNone(updates["other:arm64"]["candidate_meets_fix_threshold"])
        self.assertTrue(updates["ai-watchdog"]["candidate_meets_fix_threshold"])

    def test_kev_prioritizes_applicable_findings_and_survives_failed_refresh(self):
        archive(self.archive, [affected("iproute2")])
        catalog = self.directory / "kev.json"
        catalog.write_text(json.dumps({"count": 2, "vulnerabilities": [
            {"cveID": CVE}, {"cveID": "CVE-2026-10002"},
        ]}))
        inventory = {"iproute2": [("iproute2", "1.0", "1.0")]}
        with patch.object(vuln, "os_release", return_value=RELEASE), \
             patch.object(vuln, "package_inventory", return_value=inventory):
            first = vuln.refresh(self.db, archive=self.archive, manifest=self.manifest, kev_path=catalog)
            catalog.write_text('{"count": 2, "vulnerabilities": []}')
            second = vuln.refresh(self.db, archive=self.archive, manifest=self.manifest, kev_path=catalog)
        self.assertEqual("failed", second["sources"]["kev"]["status"])
        self.assertEqual(first["sources"]["kev"]["checked_at"], second["sources"]["kev"]["checked_at"])
        self.assertEqual([CVE, WATCHDOG_ID], [row["advisory"] for row in vuln.select_findings(second)])
        with store.connect(self.db) as db:
            summary = vuln.summary(db)
        self.assertEqual(1, summary["known_exploited"])
        self.assertEqual(CVE, summary["priority_findings"][0]["advisory"])

    def test_stale_feed_alert_fires_without_a_refresh_and_recovers_once(self):
        now = time.time()
        expected = [ECOSYSTEM, "kev"]
        vuln.check_feed_health(self.db, expected, now)
        with store.connect(self.db) as db:
            self.assertEqual("pending", vuln.summary(db, now)["sources"]["kev"]["freshness"])
        deadline = now + vuln.STALE_AFTER
        vuln.check_feed_health(self.db, expected, deadline)
        vuln.check_feed_health(self.db, expected, deadline + 1)
        with store.connect(self.db) as db:
            self.assertEqual("stale", vuln.summary(db, deadline)["sources"]["kev"]["freshness"])
            saved = {"sources": {"kev": vuln.source_result({}, "kev", deadline + 2, vuln.KEV_FEED, local=True)}}
            store.property_set(db, "vulnerability_summary", saved)
        vuln.check_feed_health(self.db, expected, deadline + 2)
        with store.connect(self.db) as db:
            self.assertEqual("stale", vuln.summary(db, deadline + 2)["sources"]["kev"]["freshness"])
            saved["sources"]["kev"] = vuln.source_result({}, "kev", deadline + 3, vuln.KEV_FEED, local=False)
            store.property_set(db, "vulnerability_summary", saved)
        vuln.check_feed_health(self.db, expected, deadline + 3)
        vuln.check_feed_health(self.db, expected, deadline + 4)
        with store.connect(self.db) as db:
            self.assertEqual("fresh", vuln.summary(db, deadline + 4)["sources"]["kev"]["freshness"])
            self.assertEqual([("Vulnerability feed stale", ECOSYSTEM), ("Vulnerability feed stale", "kev"),
                              ("Vulnerability feed refreshed", "kev")],
                             [tuple(row) for row in db.execute(
                                 "SELECT title, subject FROM events WHERE kind='vulnerability-feed' ORDER BY id")])

    def test_kernel_verification_distinguishes_installed_and_running_builds(self):
        archive(self.archive, [affected("linux", fixed="6.8.0-50.51")])
        release = "6.8.0-50-generic"
        binary = "linux-image-" + release
        inventory = {"linux": [(binary, "6.8.0-50.51", "6.8.0-50.51")]}
        with patch.object(vuln.platform, "release", return_value=release), \
             patch.object(vuln, "running_kernel", return_value="6.8.0-50.50"):
            before = self.refresh(inventory, watchdog=False)
        self.assertEqual("reboot-required", vuln.unresolved(before)[0]["fix_verification"])
        with patch.object(vuln.platform, "release", return_value=release), \
             patch.object(vuln, "running_kernel", return_value="6.8.0-50.51"):
            after = self.refresh(inventory, watchdog=False)
        self.assertEqual([], vuln.unresolved(after))
        self.assertEqual("active", next(iter(after["findings"].values()))["fix_verification"])
        self.archive.write_bytes(b"bad archive")
        with patch.object(vuln, "BOOT_ID", "new-boot"):
            self.refresh(inventory, watchdog=False)
            with store.connect(self.db) as db:
                self.assertTrue(vuln.summary(db)["previous_boot"])

    def test_kernel_verification_tracks_a_removed_image_still_running(self):
        archive(self.archive, [affected("linux", fixed="6.8.0-51.51")])
        old_release = "6.8.0-50-generic"
        new_release = "6.8.0-51-generic"
        old_image = ("linux-image-" + old_release, "6.8.0-50.50", "6.8.0-50.50")
        new_image = ("linux-image-" + new_release, "6.8.0-51.51", "6.8.0-51.51")
        with patch.object(vuln.platform, "release", return_value=old_release), \
             patch.object(vuln, "running_kernel", return_value=old_image[1]):
            self.refresh({"linux": [old_image]}, watchdog=False)
            pending = self.refresh({"linux": [new_image]}, watchdog=False)
        row, = vuln.unresolved(pending)
        self.assertEqual("removed", row["status"])
        self.assertEqual("reboot-required", row["fix_verification"])
        with patch.object(vuln.platform, "release", return_value=new_release), \
             patch.object(vuln, "running_kernel", return_value=new_image[1]):
            active = self.refresh({"linux": [new_image]}, watchdog=False)
        self.assertEqual("active", next(iter(active["findings"].values()))["fix_verification"])

    def test_patched_kernel_modules_do_not_imply_the_bootable_image_is_patched(self):
        archive(self.archive, [affected("linux", fixed="6.8.0-50.51")])
        release = "6.8.0-50-generic"
        inventory = {
            "linux": [("linux-modules-" + release, "6.8.0-50.51", "6.8.0-50.51")],
            "linux-signed": [("linux-image-" + release, "6.8.0-50.50", "6.8.0-50.50")],
        }
        with patch.object(vuln.platform, "release", return_value=release), \
             patch.object(vuln, "running_kernel", return_value="6.8.0-50.50"):
            before = self.refresh(inventory, watchdog=False)
        row, = vuln.unresolved(before)
        self.assertEqual("running-affected", row["fix_verification"])

    def test_passive_evidence_matches_reviewed_rules_only(self):
        archive(self.archive, [affected("iproute2")])
        report = self.refresh({"iproute2": [("iproute2", "1.0", "1.0")]})
        path = self.directory / "rules.json"
        reference = "https://example.test/vendor-bulletin"
        path.write_text(json.dumps({"rules": [
            {"advisory": CVE, "event_kind": "integrity", "subject": "/test/example",
             "detail_contains": "expected marker", "reference": reference},
            {"advisory": CVE, "journal_unit": "example.service",
             "detail_contains": "vendor diagnostic", "reference": reference},
        ]}))
        now = time.time()
        with store.connect(self.db) as db:
            matching_id = store.event(db, now, "high", "integrity", "Changed", "expected marker", "/test/example")
            store.event(db, now, "high", "integrity", "Changed", "different marker", "/test/example")
            store.event(db, now, "high", "integrity", "Changed", "expected marker", "/test/other")
            store.event(db, now - 7200, "high", "integrity", "Changed", "expected marker", "/test/example")
            with patch.object(vuln, "journal_events", return_value=([{
                "MESSAGE": "vendor diagnostic", "__CURSOR": "journal-cursor",
                "__REALTIME_TIMESTAMP": str(int(now * 1_000_000)),
            }], False)):
                result = vuln.evidence(db, report, path, 1)
            with patch.object(vuln, "journal_events", side_effect=PermissionError):
                partial = vuln.evidence(db, report, path, 1)
        rows = {item["advisory"]: item for item in result["advisories"]}
        self.assertEqual("no-rule", rows[WATCHDOG_ID]["status"])
        self.assertEqual("signals-found", rows[CVE]["status"])
        self.assertEqual({matching_id, "journal-cursor"}, {row["id"] for row in rows[CVE]["events"]})
        self.assertTrue(partial["advisories"][0]["partial_log_coverage"])
