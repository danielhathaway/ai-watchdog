"""Install, check, repair or remove the optional wsdd Wi-Fi policy."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if HERE == Path("/var/lib/ai-watchdog-wsdd"):
    sys.path.insert(0, str(HERE))
    import wsdd_policy as policy
else:
    sys.path.insert(0, str(HERE.parents[1]))
    from watchdog import wsdd_policy as policy

PARSER = "/usr/sbin/apparmor_parser"
PROFILE_LIST = Path("/sys/kernel/security/apparmor/profiles")
LOCK = Path("/run/lock/ai-watchdog-wsdd.lock")
HOOK = Path("/etc/dpkg/dpkg.cfg.d/90-ai-watchdog-wsdd")
HOOK_HELPERS = ("manage.py", "wsdd_policy.py")
HOOK_CONFIG = (
    b"post-invoke /usr/bin/python3 -I -B /var/lib/ai-watchdog-wsdd/manage.py repair-after-upgrade "
    b"|| echo 'Watchdog could not restore the wsdd policy; run install-wsdd-wifi.sh check.' >&2\n"
)
ANCHOR = re.compile(r"(?m)^[ \t]*/usr/bin/wsdd[ \t]+r,[ \t]*$")


def run(*args):
    subprocess.run(args, check=True, timeout=20)


def enforce():
    if policy.LABEL not in PROFILE_LIST.read_text().splitlines():
        raise ValueError("The wsdd AppArmor profile must already be enforced")


def profile_content(current, enable):
    if current.count(policy.BLOCK) == 1:
        unmanaged = current.replace(policy.BLOCK, "", 1)
    elif policy.BEGIN in current or policy.END in current:
        raise ValueError("The managed AppArmor block was edited or duplicated")
    else:
        unmanaged = current
    if not enable:
        return unmanaged
    if re.search(r"(?m)^\s*/usr/bin/wsdd\.distrib\s+", unmanaged):
        raise ValueError("An unmanaged AppArmor rule for wsdd.distrib already exists")
    updated, count = ANCHOR.subn(lambda match: match[0] + "\n" + policy.BLOCK.rstrip("\n"), unmanaged)
    if count != 1:
        raise ValueError("The packaged AppArmor profile layout changed. Review it before installing the policy.")
    return updated


def atomic(path, data, mode):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def check_hook():
    if not HOOK.exists() or not policy.trusted_file(HOOK) or HOOK.read_bytes() != HOOK_CONFIG:
        raise ValueError("The managed dpkg hook is missing or changed")
    for name in HOOK_HELPERS:
        helper = policy.STATE.parent / name
        if not helper.exists() or not policy.trusted_file(helper):
            raise ValueError("The installed dpkg hook helper is missing or unsafe")


def install_hook():
    if (HOOK.exists() or HOOK.is_symlink()) and (
        not policy.trusted_file(HOOK) or HOOK.read_bytes() != HOOK_CONFIG
    ):
        raise ValueError("An unmanaged dpkg hook already exists")
    # Package transactions run as root, so the hook must use an installed copy.
    for source in (Path(__file__), Path(policy.__file__)):
        atomic(policy.STATE.parent / source.name, source.read_bytes(), 0o644)
    atomic(HOOK, HOOK_CONFIG, 0o644)


def load_profile(text):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as staged:
        staged.write(text)
        staged.flush()
        run(PARSER, "-Q", "-T", staged.name)
    mode = stat.S_IMODE(policy.PROFILE.stat().st_mode)
    atomic(policy.PROFILE, text.encode(), mode)
    run(PARSER, "-r", "-T", str(policy.PROFILE))
    enforce()


def divert(operation):
    run("/usr/bin/dpkg-divert", "--local", "--rename", operation, "--divert",
        str(policy.VENDOR), str(policy.LAUNCHER))


def check(data):
    issues = policy.check_files(data)
    if issues:
        raise ValueError(". ".join(issues))
    enforce()
    run(str(policy.LAUNCHER), "--version")
    print(f"Wi-Fi discovery policy for {data['interface']} passed its post-update checks.")


def repair_after_upgrade():
    if not policy.STATE.exists() or not policy.PROFILE.exists() or not policy.VENDOR.exists():
        return
    if not policy.trusted_file(policy.PROFILE):
        raise ValueError("Unsafe packaged AppArmor profile")
    original = policy.PROFILE.read_bytes()
    old = original.decode()
    if old.count(policy.BLOCK) == 1:
        return
    # Only patch a pristine wsdd package conffile. Leave other local edits for review.
    conffiles = subprocess.check_output(
        ["/usr/bin/dpkg-query", "-W", "-f=${Conffiles}", "wsdd"], text=True, timeout=5
    )
    digest = hashlib.md5(original, usedforsecurity=False).hexdigest()
    if [str(policy.PROFILE), digest] not in [line.split() for line in conffiles.splitlines()]:
        return
    enforce()
    data = policy.manifest()
    if (policy.diversion() != ("LOCAL", str(policy.VENDOR))
            or not policy.launcher_matches(data) or not policy.trusted_file(policy.VENDOR, executable=True)):
        raise ValueError("Existing wsdd launcher or diversion changed")
    new = profile_content(old, True)
    try:
        load_profile(new)
        check(data)
    except (OSError, ValueError, subprocess.SubprocessError):
        load_profile(old)
        raise
    print("Restored the managed wsdd AppArmor rule after the dpkg update.")


def install(interface):
    if not policy.INTERFACE.fullmatch(interface):
        raise ValueError("Use an exact Wi-Fi interface name, such as wlp5s0")
    device = Path("/sys/class/net") / interface
    if not ((device / "wireless").is_dir() or (device / "phy80211").exists()):
        raise ValueError(f"{interface} is not a visible Wi-Fi interface")
    enforce()
    if not policy.trusted_file(policy.PROFILE):
        raise ValueError("Unsafe packaged AppArmor profile")
    old = policy.PROFILE.read_text()
    new = profile_content(old, True)
    policy.STATE.parent.mkdir(mode=0o755, exist_ok=True)
    info = policy.STATE.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Unsafe wsdd policy state directory")
    if policy.STATE.exists():
        data = policy.manifest()
        if data["interface"] != interface or policy.diversion() != ("LOCAL", str(policy.VENDOR)) or (
            not policy.launcher_matches(data) or not policy.trusted_file(policy.VENDOR, executable=True)
        ):
            raise ValueError("Existing installation differs. Review it with check, then use rollback if needed.")
        try:
            load_profile(new)
            check(data)
            install_hook()
        except (OSError, ValueError, subprocess.SubprocessError):
            load_profile(old)
            raise
        return
    if (policy.diversion() != ("", str(policy.LAUNCHER)) or policy.VENDOR.exists()
            or policy.BEGIN in old or not policy.trusted_file(policy.LAUNCHER, executable=True)):
        raise ValueError("An unmanaged wsdd launcher, diversion, or policy already exists")
    code = Path(__file__).with_name("wsdd").read_bytes().replace(b"__WIFI_INTERFACE__", interface.encode())
    compile(code, str(policy.LAUNCHER), "exec")
    data = {"interface": interface, "launcher_sha256": hashlib.sha256(code).hexdigest()}
    divert("--add")
    try:
        atomic(policy.LAUNCHER, code, 0o755)
        load_profile(new)
        check(data)
        atomic(policy.STATE, json.dumps(data).encode(), 0o644)
        install_hook()
    except (OSError, ValueError, subprocess.SubprocessError):
        policy.STATE.unlink(missing_ok=True)
        policy.LAUNCHER.unlink(missing_ok=True)
        divert("--remove")
        load_profile(old)
        raise


def rollback():
    data = policy.manifest()
    if policy.diversion() != ("LOCAL", str(policy.VENDOR)) or not policy.trusted_file(policy.VENDOR, executable=True):
        raise ValueError("The expected diversion or original executable is missing")
    if not policy.launcher_matches(data):
        raise ValueError("The launcher has been changed. Review it before rollback.")
    enforce()
    if not policy.trusted_file(policy.PROFILE):
        raise ValueError("Unsafe packaged AppArmor profile")
    code = policy.LAUNCHER.read_bytes()
    old = policy.PROFILE.read_text()
    new = profile_content(old, False)
    if (HOOK.exists() or HOOK.is_symlink()) and (
        not policy.trusted_file(HOOK) or HOOK.read_bytes() != HOOK_CONFIG
    ):
        raise ValueError("An unmanaged dpkg hook already exists")
    try:
        load_profile(new)
        policy.LAUNCHER.unlink()
        try:
            divert("--remove")
        except (OSError, subprocess.SubprocessError):
            atomic(policy.LAUNCHER, code, 0o755)
            raise
    except (OSError, ValueError, subprocess.SubprocessError):
        load_profile(old)
        raise
    policy.STATE.unlink()
    HOOK.unlink(missing_ok=True)
    for name in HOOK_HELPERS:
        (policy.STATE.parent / name).unlink(missing_ok=True)
    print("Restored the packaged wsdd executable and removed the managed AppArmor rule.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("install").add_argument("interface")
    actions.add_parser("check")
    actions.add_parser("rollback")
    actions.add_parser("repair-after-upgrade")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run this command as root to manage or check the enforced AppArmor profile")
    if args.action == "repair-after-upgrade" and (
        os.environ.get("DPKG_ROOT") not in {None, "", "/"}
        or os.environ.get("DPKG_ADMINDIR") not in {None, "/var/lib/dpkg"}
    ):
        return
    try:
        fd = os.open(LOCK, os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_RDWR, 0o600)
        with os.fdopen(fd, "rb+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.action == "install":
                install(args.interface)
            elif args.action == "check":
                check_hook()
                check(policy.manifest())
            elif args.action == "repair-after-upgrade":
                repair_after_upgrade()
            else:
                rollback()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"wsdd Wi-Fi policy: {error}\n")


if __name__ == "__main__":
    main()
