import io
import json
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import store, vulnerabilities as vuln

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
