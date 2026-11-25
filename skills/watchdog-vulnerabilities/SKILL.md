---
name: watchdog-vulnerabilities
description: Report known vulnerabilities affecting the Linux host monitored by AI Watchdog, its packaged dependencies, and its own release. Use when asked about outstanding CVEs, scan coverage, or updates for affected components.
---

# Check known exposure

Run from the Watchdog checkout or installed package directory. Use the monitor's actual state directory, such as `.watchdog` for a default observe-only installation.

- Read saved findings with `python3 -m watchdog vulnerabilities --directory .watchdog list`. Filter with `--advisory` or `--scope` to keep results manageable. The `--all` option includes earlier findings that are now outside the affected range or whose packages were removed.
- When asked to update the scan, run `python3 -m watchdog vulnerabilities --directory .watchdog refresh`. Pass `--watchdog-advisories PATH` if the operator maintains a first-party manifest. The default is `watchdog-advisories.json` in the state directory. The Ubuntu lookup fetches a public archive and matches the installed package inventory locally.
- Check candidates with `python3 -m watchdog vulnerabilities --directory .watchdog updates`. Report both candidate availability and whether the version can be confirmed to meet the vendor fix threshold. APT results reflect the local cache.

Report the source checks and their timestamps with the findings. For kernel results, compare the package name with the reported running kernel before describing runtime exposure. Describe `vendor-listed` entries as vendor-tracked with uncertain applicability or no published fix. `unverified` means the latest usable data could not confirm a previous finding. Treat source states such as `failed` and `unconfigured` as coverage gaps. Use the separate passive evidence skill for signs of exploitation.
