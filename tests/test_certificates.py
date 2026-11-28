import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from watchdog import certificates
from watchdog.common import configuration


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        root = Path(directory.name)
        cls.packaged = cls.generate(root, "Packaged CA", bits=2048, ca=True)
        cls.extra = cls.generate(root, "Unapproved CA", bits=2048, ca=True)
        cls.weak = cls.generate(root, "Weak certificate", bits=1024, ca=False)

    @staticmethod
    def generate(root, subject, *, bits, ca):
        path = root / (subject + ".crt")
        subprocess.run(
            ["/usr/bin/openssl", "req", "-x509", "-newkey", f"rsa:{bits}", "-nodes", "-days", "2",
             "-subj", f"/CN={subject}", "-addext", f"basicConstraints=critical,CA:{str(ca).upper()}",
             "-keyout", str(root / "test.key"), "-out", str(path)],
            capture_output=True, check=True, timeout=15,
        )
        return path.read_bytes()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.directory = root / "certs"
        self.directory.mkdir()
        self.bundle = self.directory / "ca-certificates.crt"
        self.bundle.write_bytes(self.packaged)
        self.package_root = root / "package"
        self.package_root.mkdir()
        self.vendor = self.package_root / "test_=Gold=_Főtanúsítvány.crt"
        self.vendor.write_bytes(self.packaged)
        self.manifest = root / "ca-certificates.md5sums"
        digest = hashlib.md5(self.packaged, usedforsecurity=False).hexdigest()
        self.manifest.write_text(f"{digest}  usr/share/ca-certificates/{self.vendor.name}\n")
        self.config = root / "ca-certificates.conf"
        self.config.write_text(self.vendor.name + "\n")

    def audit(self, allowed=(), blocked=(), now=None):
        return certificates.audit(allowed, blocked, bundle=self.bundle, directory=self.directory,
                                  package_root=self.package_root, manifest=self.manifest,
                                  configuration=self.config, now=now)

    def test_fingerprints_are_deduplicated_and_direct_ca_path_additions_are_detected(self):
        (self.directory / "aabbccdd.0").write_bytes(self.packaged)
        self.assertEqual({"status": "pass", "anchors": 1, "findings": [], "coverage_errors": [],
                          "distribution_available": True, "package_errors": []}, self.audit())
        (self.directory / "ab123456.1").write_bytes(self.extra)
        digest, _ = certificates.decode(self.extra)[0]
        report = self.audit()
        self.assertEqual("fail", report["status"])
        self.assertEqual(["unapproved-fingerprint"], report["findings"][0]["issues"])
        self.assertEqual([str(self.directory / "ab123456.1")], report["findings"][0]["sources"])
        self.assertEqual("pass", self.audit([digest])["status"])
        self.assertEqual(["blocked-fingerprint"], self.audit([digest], [digest])["findings"][0]["issues"])

    def test_package_tampering_and_distrusted_roots_are_reported(self):
        self.config.write_text("!" + self.vendor.name + "\n")
        self.assertEqual(["distribution-ca-disabled"], self.audit()["findings"][0]["issues"])
        self.vendor.write_bytes(self.extra)
        report = self.audit()
        self.assertEqual([self.vendor.name], report["package_errors"])
        self.assertEqual("fail", report["status"])

    def test_allowlisting_does_not_suppress_weak_key_or_validity_checks(self):
        self.bundle.write_bytes(self.packaged + self.weak)
        weak, der = certificates.decode(self.weak)[0]
        _, _, expires, _ = certificates.certificate_details(der)
        report = self.audit([weak], now=expires + 1)
        finding = next(item for item in report["findings"] if item["sha256"] == weak)
        self.assertEqual("warn", report["status"])
        self.assertEqual({"weak-public-key", "not-a-ca", "outside-validity-period"}, set(finding["issues"]))

    def test_missing_vendor_metadata_and_invalid_certificates_report_incomplete_coverage(self):
        self.manifest.unlink()
        self.assertEqual("unknown", self.audit()["status"])
        (self.directory / "badca000.0").write_bytes(b"not a certificate")
        self.assertEqual([str(self.directory / "badca000.0")], self.audit()["coverage_errors"])

    def test_settings_accept_only_exact_sha256_fingerprints(self):
        digest, _ = certificates.decode(self.extra)[0]
        path = self.directory / "config.json"
        path.write_text(json.dumps({"trusted_ca_sha256": [digest.upper(), digest]}))
        self.assertEqual([digest], configuration(path)["trusted_ca_sha256"])
        path.write_text(json.dumps({"blocked_ca_sha256": ["sha256:" + digest]}))
        with self.assertRaisesRegex(ValueError, "blocked_ca_sha256"):
            configuration(path)
