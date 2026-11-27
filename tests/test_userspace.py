import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import runtime_processes, store, userspace, vulnerabilities

UNIT = "/system.slice/example.service"
LIBRARY = "/lib/libexample.so.1.2"
NEW_LIBRARY = "/lib/libexample.so.1.3"
COMPONENT = "libexample:amd64"
VERSION = ("2.0-1", "2.0-1")
TARGETS = {COMPONENT: {VERSION}}


def sample(files=(), *, partial=False):
    return {"at": time.time(), "boot_id": userspace.BOOT_ID, "limited": False, "unreadable": 0,
            "units": {UNIT: {"partial": partial, "files": files}}}


class UserspaceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def test_stale_library_requires_same_service_to_load_matching_replacement(self):
        previous = {"paths": {COMPONENT: [LIBRARY]}}
        stale = (LIBRARY, 7, 10, True)
        patched = (NEW_LIBRARY, 7, 11, False)
        owners = {NEW_LIBRARY: {COMPONENT: {(7, 11)}}}
        with patch.object(userspace, "file_owners", return_value=(owners, set())):
            observed = userspace.assess(sample([stale]), TARGETS, {COMPONENT: VERSION}, previous)
            row = observed["packages"][COMPONENT]["services"][UNIT]
            self.assertEqual("restart-required", row["status"])
            self.assertEqual([LIBRARY], row["replaced_paths"])
            for files, partial in (([], False), ([patched], True), ([(NEW_LIBRARY, 8, 11, False)], False)):
                with self.subTest(files=files, partial=partial):
                    result = userspace.assess(sample(files, partial=partial), TARGETS, {COMPONENT: VERSION}, observed)
                    service = result["packages"][COMPONENT]["services"][UNIT]
                    self.assertEqual("unverified", service["status"])
                    self.assertTrue(service["pending"])
            result = userspace.assess(sample([patched, stale]), TARGETS, {COMPONENT: VERSION}, observed)
            self.assertEqual("restart-required", result["packages"][COMPONENT]["services"][UNIT]["status"])
            restarted = userspace.assess(sample([patched]), TARGETS, {COMPONENT: VERSION}, observed)
            service = restarted["packages"][COMPONENT]["services"][UNIT]
            self.assertEqual("active", service["status"])
            self.assertFalse(service["pending"])

    def test_real_replaced_and_restarted_executable_mappings(self):
        binary = self.directory / "worker"
        replacement = self.directory / "replacement"
        shutil.copy2("/bin/sleep", binary)
        shutil.copy2("/bin/sleep", replacement)
        (self.directory / f"{COMPONENT}.list").write_text(str(binary) + "\n")
        canonical = runtime_processes.package_path

        def package_path(path):
            return "/bin/worker" if path == str(binary) else canonical(path)

        with patch.object(runtime_processes, "package_path", side_effect=package_path):
            with subprocess.Popen([binary, "30"]) as process:
                try:
                    maps = Path(f"/proc/{process.pid}/maps")
                    before = userspace.assess(sample(runtime_processes.mappings(maps)), TARGETS,
                                              {COMPONENT: VERSION}, {}, self.directory)
                    self.assertEqual("active", before["packages"][COMPONENT]["services"][UNIT]["status"])
                    os.replace(replacement, binary)
                    during = userspace.assess(sample(runtime_processes.mappings(maps)), TARGETS,
                                              {COMPONENT: VERSION}, before, self.directory)
                    self.assertEqual("restart-required", during["packages"][COMPONENT]["services"][UNIT]["status"])
                finally:
                    process.terminate()
            with subprocess.Popen([binary, "30"]) as restarted:
                try:
                    files = runtime_processes.mappings(Path(f"/proc/{restarted.pid}/maps"))
                    after = userspace.assess(sample(files), TARGETS, {COMPONENT: VERSION}, during, self.directory)
                    self.assertEqual("active", after["packages"][COMPONENT]["services"][UNIT]["status"])
                finally:
                    restarted.terminate()

    def test_verify_updates_saved_advisory_and_expires_runtime_evidence(self):
        database = self.directory / "monitor.sqlite3"
        store.initialize(database)
        row = {"advisory": "CVE-2026-10001", "component": COMPONENT, "scope": "os",
               "source": "Ubuntu:26.04:LTS", "status": "outside-affected-range", "fixed": "2.0-1",
               "comparison_version": VERSION[1], "installed": VERSION[0], "severity": "high",
               "known_exploited": True, "fix_verification": "installed-runtime-unverified"}
        report = {"started_at": time.time() - 1, "sources": {}, "kernel_check": {}, "findings": {"example": row}}
        with store.connect(database) as db:
            store.property_set(db, "vulnerabilities", report)
            store.property_set(db, "vulnerability_summary", vulnerabilities.report_summary(report))
        inventory = {"libexample": [(COMPONENT, VERSION[1], VERSION[0])]}
        owners = {LIBRARY: {COMPONENT: {(7, 11)}}}
        with patch.object(vulnerabilities, "package_inventory", return_value=inventory), \
             patch.object(userspace, "package_stamp", return_value=(1, 1, 1, 1000, 1000)), \
             patch.object(userspace, "file_owners", return_value=(owners, set())):
            with patch.object(userspace, "snapshot", return_value=sample([(LIBRARY, 7, 10, True)])):
                pending = userspace.check(database, host=True)
            with store.connect(database) as db:
                summary = vulnerabilities.summary(db)
                saved = store.property_get(db, userspace.PROPERTY)
            self.assertEqual("restart-required", pending["service_findings"][0]["status"])
            self.assertEqual(1, summary["unresolved"])
            self.assertEqual("service-restart-required",
                             vulnerabilities.unresolved(userspace.overlay(report, saved))[0]["fix_verification"])
            with patch.object(userspace, "snapshot", return_value=sample()):
                stopped = userspace.check(database, host=True)
            self.assertEqual(1, stopped["findings"]["service-runtime-unverified"])
            with patch.object(userspace, "snapshot", return_value=sample([(LIBRARY, 7, 11, False)])):
                restored = userspace.check(database, host=True)
        with store.connect(database) as db:
            self.assertEqual(0, vulnerabilities.summary(db)["unresolved"])
            expired = vulnerabilities.summary(db, restored["at"] + userspace.MAX_AGE)
        self.assertEqual("active", restored["service_findings"][0]["status"])
        self.assertEqual("awaiting-recheck", expired["userspace"]["status"])
        self.assertEqual({"installed-runtime-unverified": 1}, expired["fixes"])

    def test_unrelated_mapping_and_scope_do_not_count_as_restarted_service(self):
        group = self.directory / "cgroup"
        group.write_text("0::/user.slice/user-1000.slice/user@1000.service/app.slice/demo.scope\n")
        self.assertIsNone(runtime_processes.service(group))
        group.write_text("0::/user.slice/user-1000.slice/user@1000.service/app.slice/demo.service/subgroup\n")
        self.assertTrue(runtime_processes.service(group).endswith("/demo.service"))
        prior = {"packages": {COMPONENT: {"services": {UNIT: {"required": ["/lib/libother.so.1"]}}}}}
        with patch.object(userspace, "file_owners", return_value=({LIBRARY: {COMPONENT: {(7, 11)}}}, set())):
            observed = userspace.assess(sample([(LIBRARY, 7, 11, False)]), TARGETS, {COMPONENT: VERSION}, prior)
        self.assertEqual("unverified", observed["packages"][COMPONENT]["services"][UNIT]["status"])
