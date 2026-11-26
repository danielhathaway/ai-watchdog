import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from deploy.wsdd import manage
from watchdog import wsdd_policy as policy

PACKAGE = "/usr/bin/wsdd {\n  /usr/bin/wsdd r,\n}\n"


class WsddPolicyTests(unittest.TestCase):
    def test_install_check_detects_upgrade_drift_and_rollback_preserves_vendor_changes(self):
        with tempfile.TemporaryDirectory() as work, ExitStack() as stack:
            root = Path(work)
            for name, name_on_disk in (("LAUNCHER", "wsdd"), ("VENDOR", "wsdd.distrib"),
                                       ("PROFILE", "profile"), ("STATE", "state/policy.json")):
                stack.enter_context(patch.object(policy, name, root / name_on_disk))
            policy.LAUNCHER.write_text("vendor-before-upgrade")
            policy.PROFILE.write_text(PACKAGE)
            installed = False

            def diversion():
                return ("LOCAL", str(policy.VENDOR)) if installed else ("", str(policy.LAUNCHER))

            def divert(operation):
                nonlocal installed
                if operation == "--add":
                    policy.LAUNCHER.rename(policy.VENDOR)
                    installed = True
                else:
                    policy.VENDOR.rename(policy.LAUNCHER)
                    installed = False

            def load_profile(text):
                policy.PROFILE.write_text(text)

            stack.enter_context(patch.object(policy, "diversion", diversion))
            stack.enter_context(patch.object(policy, "trusted_file", lambda path, **kwargs: path.is_file()))
            stack.enter_context(patch.object(manage, "divert", divert))
            stack.enter_context(patch.object(manage, "load_profile", load_profile))
            stack.enter_context(patch.object(manage, "enforce"))
            stack.enter_context(patch.object(manage, "run"))
            stack.enter_context(patch("pathlib.Path.is_dir", return_value=True))
            # Simulate a root-owned state directory without requiring root in the test.
            actual_lstat = Path.lstat

            def lstat(path, *args, **kwargs):
                info = actual_lstat(path, *args, **kwargs)
                if path == policy.STATE.parent:
                    return type("ExpectedOwner", (), {"st_uid": 0, "st_mode": info.st_mode})()
                return info

            stack.enter_context(patch.object(Path, "lstat", lstat))
            manage.install("wlp5s0")
            data = policy.manifest()
            policy.VENDOR.write_text("vendor-after-upgrade")
            self.assertEqual([], policy.check_files(data))
            self.assertIn(policy.BLOCK, policy.PROFILE.read_text())
            self.assertIn('WIFI = "wlp5s0"', policy.LAUNCHER.read_text())

            upgraded_profile = PACKAGE.replace("\n}", "\n  # Upstream addition\n}")
            policy.PROFILE.write_text(upgraded_profile)
            self.assertIn("The managed AppArmor read rule is missing or changed", policy.check_files(data))
            manage.install("wlp5s0")
            self.assertEqual([], policy.check_files(data))
            manage.rollback()
            self.assertEqual("vendor-after-upgrade", policy.LAUNCHER.read_text())
            self.assertEqual(upgraded_profile, policy.PROFILE.read_text())
            self.assertFalse(policy.STATE.exists())

    def test_profile_refuses_unrecognized_or_unmanaged_rules(self):
        for old in (PACKAGE.replace("  /usr/bin/wsdd r,\n", ""), PACKAGE.replace(
            "}", policy.RULE + "\n}"), PACKAGE + policy.BEGIN):
            with self.subTest(old=old), self.assertRaises(ValueError):
                manage.profile_content(old, True)
