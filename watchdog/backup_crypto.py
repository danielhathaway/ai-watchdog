"""Authenticated age transport for sealed backups, with a narrow archive format."""
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from contextlib import contextmanager

from . import backups

AGE = "/usr/bin/age"
RECIPIENT = re.compile(r"age1[ac-hj-np-z02-9]{58}")


def export_backup(source, destination, recipient):
    if not RECIPIENT.fullmatch(recipient):
        raise ValueError("Supply a native age X25519 recipient beginning with age1")
    manifest = backups.verify(source)
    with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
        encrypted = Path(directory) / "ciphertext"
        with encrypted.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            with subprocess.Popen([AGE, "--encrypt", "--recipient", recipient], stdin=subprocess.PIPE,
                                  stdout=output, stderr=subprocess.DEVNULL) as age:
                try:
                    with age.stdin, tarfile.open(fileobj=age.stdin, mode="w|") as archive:
                        for name in [backups.MANIFEST, *manifest["files"]]:
                            with backups.open_regular(source / name) as stream:
                                header = tarfile.TarInfo(name)
                                header.size = os.fstat(stream.fileno()).st_size
                                header.mode = 0o600
                                archive.addfile(header, stream)
                    if age.wait():
                        raise ValueError("age could not encrypt the backup; check the recipient")
                except (OSError, tarfile.TarError):
                    age.kill()
                    raise ValueError("Could not stream the backup into age") from None
            output.flush()
            os.fsync(output.fileno())
        os.link(encrypted, destination)


@contextmanager
def open_encrypted(source, identity):
    with backups.open_regular(identity) as identity_file:
        info = os.fstat(identity_file.fileno())
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("The age identity file must be private and owned by this account")
        # Pass the validated file descriptor so age reads the same identity that was checked.
        with backups.open_regular(source) as ciphertext, tempfile.TemporaryFile() as plaintext:
            decrypted = subprocess.run(
                [AGE, "--decrypt", "--identity", f"/proc/self/fd/{identity_file.fileno()}"],
                stdin=ciphertext, stdout=plaintext, stderr=subprocess.DEVNULL, pass_fds=(identity_file.fileno(),),
            )
            if decrypted.returncode:
                raise ValueError("Could not decrypt the backup with this age identity")
            plaintext.seek(0)
            with tempfile.TemporaryDirectory(prefix="watchdog-restore-") as directory:
                root = Path(directory)
                try:
                    unpack(plaintext, root)
                except tarfile.TarError as error:
                    raise ValueError("The encrypted payload is not a Watchdog backup archive") from error
                manifest = backups.verify(root)
                actual = {str(file.relative_to(root)) for file in root.rglob("*") if file.is_file()}
                if actual != set(manifest["files"]) | {backups.MANIFEST}:
                    raise ValueError("The encrypted archive and backup manifest list different files")
                yield root


def unpack(plaintext, directory):
    seen = set()
    with tarfile.open(fileobj=plaintext, mode="r:") as archive:
        for member in archive:
            name = member.name
            if (not member.isreg() or name in seen
                    or (name != backups.MANIFEST and not backups.FILE_NAME.fullmatch(name))):
                raise ValueError("The backup archive contains an unsafe or duplicate file entry")
            if len(seen) >= 256 or (name == backups.MANIFEST and member.size > 262144):
                raise ValueError("The backup archive has too many entries or an oversized manifest")
            seen.add(name)
            target = directory / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.extractfile(member) as stream, target.open("xb") as output:
                os.fchmod(output.fileno(), 0o600)
                shutil.copyfileobj(stream, output)
