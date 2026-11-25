---
name: watchdog-passive-evidence
description: Check AI Watchdog events and readable local systemd logs for reviewed signs associated with known vulnerabilities. Use when asked whether a tracked vulnerability has matching signs of exploitation on this host.
---

# Check recorded attack indicators

Run `python3 -m watchdog vulnerabilities --directory .watchdog evidence --hours 24` from the Watchdog checkout or installed package directory. Substitute the actual monitor state directory and requested time window. Use `--advisory CVE-…` to focus on a specific tracked issue, including one since resolved. Pass `--rules PATH` when the operator has a reviewed indicator file that cites the vendor or another authoritative source. The default is `vulnerability-rules.json` in the state directory.

Use recorded Watchdog events and local systemd journal entries. Report matching event times, the rule reference, and any partial coverage. A match is an indicator for investigation. `no-rule` means the advisory has no configured indicator. `no-matching-events` covers the selected rules and time window. `partial-log-coverage` means a journal source was empty, unavailable, or capped. Host version exposure and observed attack evidence are separate findings.
