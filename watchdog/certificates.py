"""Audit trust anchors in the Ubuntu/Debian system OpenSSL trust store."""
import functools
import hashlib
import os
import re
import ssl
import stat
import subprocess
import time
from pathlib import Path

BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
CA_DIRECTORY = BUNDLE.parent
PACKAGE_ROOT = Path("/usr/share/ca-certificates")
PACKAGE_MANIFEST = Path("/var/lib/dpkg/info/ca-certificates.md5sums")
CA_CONFIG = Path("/etc/ca-certificates.conf")
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\r\n]+)\s+-----END CERTIFICATE-----")
HASH_LINK = re.compile(r"[0-9a-fA-F]{8}\.\d{1,6}")
PACKAGE_PATH = re.compile(r"([0-9a-f]{32})  usr/share/ca-certificates/(.+\.crt)")
MAX_CERT_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_CERTIFICATES = 512


def read_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("Certificate input is not a bounded regular file")
        contents = stream.read(maximum + 1)
    if len(contents) > maximum:
        raise ValueError("Certificate input exceeds size limit")
    return contents


def decode(contents):
    matches = list(PEM.finditer(contents))
    if (not matches or len(matches) > MAX_CERTIFICATES
            or len(matches) != contents.count(b"-----BEGIN CERTIFICATE-----")
            or len(matches) != contents.count(b"-----END CERTIFICATE-----")
            or b"-----BEGIN TRUSTED CERTIFICATE-----" in contents):
        raise ValueError("Invalid or unsupported certificate format")
    result = []
    for match in matches:
        if len(match[0]) > MAX_CERT_BYTES:
            raise ValueError("Certificate exceeds size limit")
        der = ssl.PEM_cert_to_DER_cert(match[0].decode("ascii"))
        result.append((hashlib.sha256(der).hexdigest(), der))
    return result


def distribution_anchors(root, manifest, configuration):
    contents = read_file(manifest, MAX_BUNDLE_BYTES).decode("utf-8")
    config = read_file(configuration, MAX_BUNDLE_BYTES).decode("utf-8")
    enabled = {line for line in map(str.strip, config.splitlines()) if line and not line.startswith(("#", "!"))}
    approved, distrusted, errors = set(), set(), []
    entries = [match.groups() for line in contents.splitlines() if (match := PACKAGE_PATH.fullmatch(line))]
    if not entries or len(entries) > MAX_CERTIFICATES:
        raise ValueError("CA package metadata contains an invalid number of certificates")
    for checksum, filename in entries:
        if len(filename) > 512 or not filename.isprintable() or any(
            part in {"", ".", ".."} for part in filename.split("/")
        ):
            raise ValueError("Invalid certificate filename in package metadata")
        try:
            data = read_file(root / filename, MAX_CERT_BYTES)
            # Dpkg uses MD5 for this local consistency check. Trust decisions use SHA-256.
            if hashlib.md5(data, usedforsecurity=False).hexdigest() != checksum:
                raise ValueError("Certificate differs from package metadata")
            fingerprints = {fingerprint for fingerprint, _ in decode(data)}
        except (OSError, ValueError):
            errors.append(filename)
            continue
        if filename in enabled:
            approved.update(fingerprints)
        else:
            distrusted.update(fingerprints)
    return approved, distrusted - approved, errors


def active_anchors(bundle, directory):
    anchors = {}
    errors = []

    def add(path, maximum, source):
        try:
            entries = decode(read_file(path, maximum))
            if len(anchors.keys() | {fingerprint for fingerprint, _ in entries}) > MAX_CERTIFICATES:
                raise ValueError("Trust store exceeds the certificate limit")
            for fingerprint, der in entries:
                anchors.setdefault(fingerprint, {"der": der, "sources": []})["sources"].append(source)
        except (OSError, ValueError):
            errors.append(source)

    add(bundle, MAX_BUNDLE_BYTES, str(bundle))
    try:
        with os.scandir(directory) as entries:
            names = []
            for index, entry in enumerate(entries):
                if index >= 4096 or len(names) >= 1024:
                    raise ValueError("Trust directory exceeds the scan limit")
                if HASH_LINK.fullmatch(entry.name):
                    names.append(entry.name)
            for name in sorted(names):
                add(directory / name, MAX_CERT_BYTES, str(directory / name))
    except (OSError, ValueError):
        errors.append(str(directory))
    return anchors, errors


@functools.lru_cache(maxsize=MAX_CERTIFICATES)
def certificate_details(der):
    result = subprocess.run(
        ["/usr/bin/openssl", "x509", "-inform", "DER", "-noout", "-nameopt", "RFC2253",
         "-subject", "-issuer", "-startdate", "-enddate", "-text"],
        input=der, capture_output=True, check=True, timeout=3,
    ).stdout.decode(errors="replace")
    subject = re.search(r"^subject=([^\r\n]*)", result, re.MULTILINE)
    issuer = re.search(r"^issuer=([^\r\n]*)", result, re.MULTILINE)
    validity = [re.search(rf"^{name}=([^\r\n]+)", result, re.MULTILINE) for name in ("notBefore", "notAfter")]
    if not subject or not issuer or not all(validity):
        raise ValueError("Certificate metadata is incomplete")
    algorithm = re.search(r"Public Key Algorithm:\s*(\S+)", result)
    bits = re.search(r"Public-Key: \((\d+) bit\)", result)
    if not algorithm:
        raise ValueError("Certificate public key is unavailable")
    limitations = []
    if algorithm[1] in {"rsaEncryption", "rsassaPss", "dsaEncryption", "id-ecPublicKey"}:
        if not bits:
            raise ValueError("Certificate public key size is unavailable")
        if int(bits[1]) < (224 if algorithm[1] == "id-ecPublicKey" else 2048):
            limitations.append("weak-public-key")
    elif algorithm[1] not in {"ED25519", "ED448"}:
        limitations.append("unrecognized-public-key")
    signature = re.search(r"Signature Algorithm:\s*([^\r\n]+)", result)
    if signature:
        name = signature[1].lower()
        if re.search(r"md[245](?!\d)", name) or (re.search(r"sha1(?!\d)", name) and subject[1] != issuer[1]):
            limitations.append("weak-certificate-signature")
    constraints = re.search(r"X509v3 Basic Constraints:[^\r\n]*\n\s*([^\r\n]+)", result)
    usage = re.search(r"X509v3 Key Usage:[^\r\n]*\n\s*([^\r\n]+)", result)
    if (constraints and "CA:TRUE" not in constraints[1]) or (usage and "Certificate Sign" not in usage[1]):
        limitations.append("not-a-ca")
    return subject[1][:400], *(ssl.cert_time_to_seconds(field[1]) for field in validity), tuple(limitations)


def audit(allowed=(), blocked=(), *, bundle=BUNDLE, directory=CA_DIRECTORY, package_root=PACKAGE_ROOT,
          manifest=PACKAGE_MANIFEST, configuration=CA_CONFIG, now=None):
    now = time.time() if now is None else now
    anchors, coverage_errors = active_anchors(bundle, directory)
    distribution_available = True
    try:
        approved, disabled, package_errors = distribution_anchors(package_root, manifest, configuration)
    except (OSError, ValueError):
        approved, disabled, package_errors = set(), set(), []
        distribution_available = False
    local, blocked = set(allowed), set(blocked)
    trusted = approved | disabled | local
    deadline = time.monotonic() + 10
    findings = []
    for fingerprint, anchor in sorted(anchors.items()):
        issues = []
        if fingerprint in blocked:
            issues.append("blocked-fingerprint")
        if fingerprint in disabled:
            issues.append("distribution-ca-disabled")
        if distribution_available and fingerprint not in trusted:
            issues.append("unapproved-fingerprint")
        elif not distribution_available and fingerprint not in local:
            issues.append("provenance-unverified")
        try:
            if time.monotonic() >= deadline:
                raise TimeoutError("Certificate metadata scan exceeded its time budget")
            subject, begins, ends, limitations = certificate_details(anchor["der"])
            issues.extend(limitations)
            if now < begins or now > ends:
                issues.append("outside-validity-period")
        except (OSError, ValueError, subprocess.SubprocessError):
            subject = ""
            issues.append("metadata-unavailable")
        if issues:
            findings.append({"sha256": fingerprint, "subject": subject, "issues": issues,
                             "sources": anchor["sources"]})
    critical = {"blocked-fingerprint", "unapproved-fingerprint", "distribution-ca-disabled"}
    statuses = {issue for row in findings for issue in row["issues"]}
    if statuses & critical or package_errors:
        status = "fail"
    elif statuses - {"provenance-unverified", "metadata-unavailable"}:
        status = "warn"
    elif statuses or coverage_errors or not distribution_available or not anchors:
        status = "unknown"
    else:
        status = "pass"
    return {"status": status, "anchors": len(anchors), "findings": findings, "coverage_errors": coverage_errors,
            "distribution_available": distribution_available, "package_errors": package_errors}
