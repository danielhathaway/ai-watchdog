import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog import responder

UNSHARE = shutil.which("unshare")
NAMESPACE_FLAGS = ["--user", "--map-root-user", "--net"]


class KernelIntegrationTests(unittest.TestCase):
    def test_firewall_leases_isolation_and_recovery_in_a_disposable_namespace(self):
        if not UNSHARE or not Path(responder.NFT).is_file() or not Path(responder.IP).is_file():
            self.skipTest("unshare, nftables, and iproute2 are needed")
        prefix = [UNSHARE, *NAMESPACE_FLAGS, "--"]
        probe = subprocess.run([*prefix, responder.NFT, "list", "tables"], capture_output=True, text=True, timeout=8)
        if probe.returncode:
            self.skipTest("An unprivileged network namespace with nftables is unavailable")
        with open("/proc/self/ns/net", "rb") as parent_namespace:
            run = subprocess.run([
                *prefix, sys.executable, str(Path(__file__).resolve()),
                "--disposable-network-test", str(parent_namespace.fileno()),
            ], pass_fds=(parent_namespace.fileno(),), capture_output=True, text=True, timeout=15,
                env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])})
        self.assertEqual(0, run.returncode, run.stdout + run.stderr)
        self.assertEqual("disposable firewall test passed", run.stdout.strip())


def check_disposable_network(parent_fd):
    # This file is also a subprocess entry point. Refuse to change the parent namespace.
    inherited = os.readlink(f"/proc/self/fd/{parent_fd}")
    current = os.readlink("/proc/self/ns/net")
    if not inherited.startswith("net:[") or inherited == current or os.geteuid() != 0:
        raise RuntimeError("Firewall smoke test requires its own root-mapped network namespace")

    with tempfile.TemporaryDirectory() as temporary:
        state_dir = Path(temporary)
        with (
            patch.object(responder, "RESPONSE_STATE", state_dir),
            patch.object(responder, "RESPONSE_RUNTIME", state_dir),
        ):
            responder.execute(responder.IP, "link", "set", "lo", "up")
            responder.execute(responder.IP, "link", "add", "wd-test", "type", "dummy")
            responder.execute(responder.IP, "link", "set", "wd-test", "up")
            responder.execute(responder.NFT, "add", "table", "inet", "wd_other")
            responder.apply_firewall({"8.8.8.8": 120, "2001:4860::1": 120}, False, ("00:11:22:33:44:55",))
            table = responder.execute(responder.NFT, "list", "table", "inet", responder.TABLE)
            for rule in ("8.8.8.8", "2001:4860::1", "00:11:22:33:44:55", "flags timeout"):
                assert rule in table, table

            responder.apply_firewall({}, True)
            state = {"reason": "isolated smoke test", "boot_id": responder.BOOT_ID, "links": {}}
            responder.persist_latch(state)
            assert responder.isolate_links(state) == []
            links = {link["ifname"]: link["flags"] for link in responder.links()}
            assert "UP" in links["lo"] and "UP" not in links["wd-test"], links
            table = responder.execute(responder.NFT, "list", "table", "inet", responder.TABLE)
            assert 'iifname != "lo"' in table and 'oifname != "lo"' in table, table

            responder.recover()
            links = {link["ifname"]: link["flags"] for link in responder.links()}
            tables = responder.execute(responder.NFT, "list", "tables")
            assert "UP" in links["lo"] and "UP" in links["wd-test"], links
            assert "table inet wd_other" in tables and responder.TABLE not in tables, tables
            assert not (state_dir / "isolation.json").exists()
    print("disposable firewall test passed")


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--disposable-network-test":
    check_disposable_network(int(sys.argv[2]))
