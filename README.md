# AI Watchdog

AI Watchdog is a local Linux endpoint monitor with a browser dashboard, on-device anomaly detection, and an independent process that can quarantine traffic or disconnect the host. Live deployments start in observe-only mode.

## License

AI Watchdog is licensed under the [GNU General Public License version 3 only](LICENSE), except for the optional [UDP tracing script](deploy/udp/udp.bt), which is licensed under the [GNU General Public License version 2 only](deploy/udp/COPYING).

## Try the dashboard

Run from this directory with Python 3.10 or newer:

```sh
python3 -m watchdog demo
```

Open [127.0.0.1:8765](http://127.0.0.1:8765). The demo uses synthetic data in a temporary database. **Run AI check** refreshes the assessment and records it in Activity. Devices shows remembered neighbors. Sensors shows source availability and current firewall blocks.

## Install for your Linux user account

Use this option for live observation without administrator access. It requires an active systemd user manager and uses sensors available to the logged-in account.

```sh
./deploy/install-user.sh
cat .watchdog/token
```

Open [127.0.0.1:8765](http://127.0.0.1:8765) and enter the token. The installer enables the monitor and a separate heartbeat supervisor in the user service manager. Both run as your account. This installation always runs in observe-only mode and records events and local configuration in the checkout's private `.watchdog` directory. Keep the checkout at its installed path. The initial integrity baseline reflects the local files at first start.

```sh
systemctl --user status ai-watchdog-observe.service ai-watchdog-observe-supervisor.service
```

Use the system-wide installation below for enforcement or monitoring independently of the user session.

## Install on a Linux host

Use a Linux host with systemd, journald, iproute2, nftables with `destroy table` and timed set-element support, and a local management console. The installer copies the service code and configuration with root ownership. It does not start the services. Review the configuration in `/etc/ai-watchdog/config.json` before starting.

```sh
sudo ./deploy/install.sh
cd /opt/ai-watchdog
sudo python3 -B -m watchdog baseline
sudo systemctl enable --now ai-watchdog-response.service
sudo cat /var/lib/ai-watchdog/token
```

The response service starts the monitor. Open [127.0.0.1:8765](http://127.0.0.1:8765) from the monitored machine and enter the token. Use the numeric loopback address shown. The API requires that token and accepts active checks from the dashboard's exact origin. SQLite is stored in the monitor's private state directory. Sample, event, and neighbor records expire after 30 days by default. Supervisor transitions are also written to journald.

### What it monitors

| Signal | What it measures |
| --- | --- |
| Traffic | Inbound and outbound interface counters, excluding loopback |
| TCP | Established connections, pending outbound handshakes, and distinct pending inbound peers |
| SSH | Failed authentication from the systemd units `ssh.service` and `sshd.service` with OpenSSH journal messages |
| Devices | IPv4 and IPv6 neighbor-cache entries, remembered by hardware address and interface |
| File integrity | Content hash, target, ownership, and permissions against a root-managed baseline |

The statistical detector learns a robust baseline for traffic and established TCP connections from up to 720 recent normal samples per metric. It needs 30 valid samples per metric to begin reporting deviations. An active check refreshes local evidence and uses the latest completed traffic window to evaluate bandwidth against that history. Traffic inspection covers rates and connection metadata. Device observations cover entries visible in the local cache and do not establish a device's identity or presence independently.

For an optional natural-language summary, configure a downloaded local Ollama model in `ollama_model`. Run Ollama in local-only mode at `127.0.0.1:11434` with cloud features disabled. Restart the monitor after editing the model setting. The optional model sees numeric evidence, coverage, and event category counts. The statistical assessment continues if the model is unavailable. The model output has no command or rule execution privileges. [Ollama local-only configuration](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)

### Network interface totals and spike history

Watchdog totals traffic at the hardware-backed interface layer. This counts Wi-Fi or Ethernet traffic at the point it leaves the host and keeps VPN, bridge, and other virtual interface readings separate. If no hardware-backed interface is visible in the namespace, Watchdog uses a single interface when there is only one, or selects one main-table default-route interface. The dashboard identifies which interfaces contributed to the total. [Linux network interface statistics](https://docs.kernel.org/networking/statistics.html)

In Overview, expand **Interface breakdown** under Network traffic for the latest rates. In Activity, expand a timestamp under **Traffic spikes by interface** for the recorded interface rates, counted interfaces, process rates, and shared start and end times. Flagged windows are saved once, with process attribution, even during the Activity event cooldown. The dashboard lists the latest 20 breakdowns, and the database retains them for the configured retention period.

New spike records include Linux interface packet counts and TCP/UDP payload totals for all observed processes, including rows outside the displayed ranking. Where socket counters provide TCP segment counts, Watchdog saves a minimum IP + TCP header estimate (40 bytes per IPv4 segment, 60 per IPv6 segment). TCP options, IPv6 extension headers, link headers, and VPN encapsulation are outside that estimate. The updated UDP collector also counts successful send/receive calls and estimates 8 bytes of UDP header per counted datagram call. UDP segmentation/coalescing can make call counts differ from wire packet counts. Older collectors remain compatible and supply UDP byte rates. Rerun the [UDP installer](#enable-udp-and-quic-attribution) to add UDP datagram counts.

Changing the measurement basis starts fresh inbound and outbound baselines. The traffic chart uses samples from the current basis. The TCP connection baseline and existing event history are retained.

### Process traffic

Overview lists the processes with the most observed TCP and UDP traffic in the latest completed window. In Activity, expand an inbound or outbound traffic anomaly to see the processes observed in that direction when Watchdog logged the event. Events recorded before this feature have no process sample.

Watchdog uses Linux `ss` to sample TCP socket byte counters and visible process owners. It retains names, PIDs, and rates for logged spikes. It does not record endpoints or content for this feature. Traffic from shared TCP sockets or sockets with inaccessible owners is shown separately when measurable. Very short TCP connections can disappear between samples. A VPN or locally routed traffic can cause interface counters and socket totals to differ. Treat these entries as contributors seen at the time, without using them to account for every byte in a spike. [iproute2 socket statistics manual](https://github.com/iproute2/iproute2/blob/main/man/man8/ss.8)

#### Enable UDP and QUIC attribution

Linux TCP monitoring works on its own. For UDP, run the optional collector on a host with bpftrace 0.25 or later, kernel BTF, and IPv4/IPv6 fexit support. The installer checks that the probes can attach and waits for the service's first usable sample.

```sh
sudo ./deploy/install-udp.sh "$(id -un)"
```

For a system-wide Watchdog service using the `ai-watchdog` account, pass `ai-watchdog` as the argument to monitor that account instead. The collector accounts for successful UDP socket operations by the selected account, including QUIC and other UDP traffic. It writes an owner-readable snapshot every five seconds. Watchdog shows separate TCP and UDP rates, with UDP blank when no recent collector sample is available. This does not inspect payloads or identify which UDP flows use QUIC. Kernel-only or forwarded UDP is outside the account's process view, and UDP loopback traffic can be included. Interfaces, TCP, and UDP share fixed windows aligned to the UDP collector’s five-second boundaries. The default window is ten seconds. Other sampling intervals round up to a multiple of five seconds. Watchdog combines the complete UDP buckets for each window and leaves a protocol’s rates blank if its data for that window is missing. The rates share a time window, while interface byte counters include network overhead that socket counters can omit. [bpftrace kernel function probes](https://bpftrace.org/docs/release_025/language#fentry-and-fexit)

### Recurring AI checks

Open **Settings → Recurring AI check** and enter a cadence in minutes. The first check is due one interval after saving. Use 0 to turn the schedule off. The service saves the schedule across restarts and performs one catch-up check after downtime, then resumes the saved cadence. The dashboard may be closed. Scheduled checks use the same local analysis and run one at a time with manual checks. Their results appear in Overview and Activity.

### Scheduled system checks

The **Sensors** page shows the latest Watchdog health and host hardening results. These checks run independently of the AI schedule. New warnings and failures, and findings that return to normal, appear in Activity. The checks report findings without changing host settings.

| Schedule | Defaults and coverage |
| --- | --- |
| Watchdog health | Every 5 minutes. Checks the heartbeat, independent supervisor, sensor status, private state permissions, and Watchdog files against a trusted baseline. |
| Host hardening | Every 60 minutes. Inventories TCP and UDP listeners on non-loopback addresses, reviews effective default OpenSSH authentication settings, checks visible nftables input policy, and reads kernel settings for ASLR, ptrace restrictions, and link protections. |

Override the cadence with `health_check_minutes` and `hardening_check_minutes` in the active configuration. Use `allowed_listeners` to list expected non-loopback ports, for example `["tcp/22", "udp/5353"]` if you intend to expose those services. The default empty allowlist surfaces every non-loopback listener for review. A listening socket can still be blocked by a firewall. SSH connection-specific `Match` rules and firewall rules outside the monitor's permissions require separate review.

Record the Watchdog file baseline from trusted files. For the observe-only installation, run this from the checkout as the monitor user.

```sh
python3 -m watchdog baseline --directory .watchdog
```

The system installation records a root-owned Watchdog baseline with the existing `sudo python3 -B -m watchdog baseline` command. The baseline covers application code, dashboard assets, active configuration, service unit files and their local overrides, and installed UDP probe files when present. After an intentional update, review the files and use `sudo python3 -B -m watchdog baseline --watchdog-only` to refresh just the application baseline on system installations. The observe-only account owns its baseline, so a compromise of that account can affect what the checks report. Host-local checks also depend on the integrity of the running kernel.

### Email alerts

Add an `email_alerts` object to the active configuration file. For the user installation this is `.watchdog/config.json`. For the system installation it is `/etc/ai-watchdog/config.json`. The default value `null` keeps delivery off.

```json
"email_alerts": {
  "host": "smtp.example.com",
  "port": 587,
  "security": "starttls",
  "sender": "watchdog@example.com",
  "recipient": "security@example.com",
  "minimum_severity": "high",
  "username": "watchdog@example.com",
  "password_file": "smtp-password"
}
```

Use the host, port, sender, and authentication settings from your relay. Use `"tls"` for implicit TLS. Keep the SMTP password or app password in a separate file. The path may be absolute or relative to the configuration directory. Use mode `0600` for a user installation or mode `0640` with ownership `root:ai-watchdog` for the system installation. Omit both authentication fields for a trusted relay that accepts unauthenticated submissions over TLS. [Python SMTP documentation](https://docs.python.org/3/library/smtplib.html)

Restart the monitor after changing the configuration:

```sh
systemctl --user restart ai-watchdog-observe.service
```

For a system-wide installation, use a local TLS relay allowed by the service's loopback network policy. Apply configuration changes with the maintenance sequence below. Check relay connectivity and delivery while in observe mode before relying on alerts.

New high and critical events enter a local queue. Set `minimum_severity` to `critical` for critical-only alerts. Each email includes event titles, severity, and timestamps. IP addresses, device identities, file paths, and raw logs stay in Watchdog. Delivery is batched, retried on failure, and expires after 24 hours. The Settings page shows pending alerts, the next retry, and the last time SMTP accepted a batch. If the computer is disconnected, alerts can only be delivered once the relay becomes reachable again.

### Enable and verify containment

First verify the sensors and independent supervisor in observe mode. From a local console on a disposable test host, stop the monitor, verify **would-isolate** through `journalctl -u ai-watchdog-response`, and restart the monitor. A missing heartbeat may be acted on immediately once the supervisor has previously verified a healthy monitor. A stale heartbeat or unresponsive console triggers a response after the configured deadlines.

Set `"enforce": true` to enable the following policies:

- **Temporary IP block.** Twelve SSH failures from an eligible public source within two minutes request a 15-minute IPv4 or IPv6 block. The supervisor validates the address again, excludes host and default gateway addresses, and installs a kernel-expiring lease. Include public management, VPN, DNS, and proxy addresses or subnets that must be protected in `protected_networks`. Observe mode records block recommendations.
- **Device block.** The administrator can add hardware addresses such as `00:11:22:33:44:55` to `blocked_macs`. The firewall drops incoming and forwarded IP packets bearing those source MACs at the endpoint. This is useful for directly attached peers. A MAC address can change or be spoofed, and the rule does not control the router or other hosts.
- **Host isolation.** The supervisor latches isolation after monitor unresponsiveness, confirmed drift on a path explicitly listed in `isolate_on_integrity`, or three consecutive failures applying a qualifying temporary block. It filters non-loopback IPv4/IPv6 traffic and takes non-loopback links down in the host network namespace. Systemd restarts the supervisor if it hangs. The supervisor reasserts isolation after service restart and reboot. [nftables manual](https://netfilter.org/projects/nftables/manpage.html) · [systemd service watchdog](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)

Apply policy changes from the local console. Stop the responder first, restart the monitor, then wait for a healthy monitor before starting the responder. Substitute your configured dashboard port if it differs.

```sh
sudo systemctl stop ai-watchdog-response.service
sudo systemctl restart ai-watchdog.service
curl --fail --silent --show-error --retry 12 --retry-delay 1 --retry-connrefused \
    http://127.0.0.1:8765/health &&
    sudo systemctl start ai-watchdog-response.service
```

Confirm actual IPv4/IPv6 connectivity loss, loopback dashboard access, and recovery on a disposable host before relying on enforcement. An expected shutdown of the monitor while the supervisor is active can trigger containment. Stop the response service first for planned maintenance. When switching from enforcement to observe-only, stop the responder and use the recovery command below to remove its existing rules.

### Recover locally

After investigating the incident, run from the physical or out-of-band console:

```sh
sudo systemctl stop ai-watchdog-response.service
cd /opt/ai-watchdog
sudo python3 -B -m watchdog recover
sudo systemctl start ai-watchdog.service
curl --fail --silent --show-error --retry 12 --retry-delay 1 --retry-connrefused \
    http://127.0.0.1:8765/health &&
    sudo systemctl start ai-watchdog-response.service
```

Recovery restores matching links the supervisor recorded in this boot, removes its nftables table, and clears the isolation latch. After reboot or if a link or network manager has changed, restore connectivity through the host's usual network manager as needed. Verify any changed integrity files before authorizing a new baseline. If the original trigger remains, the supervisor can isolate the host again.

### Coverage limits

This is a host-side detection and containment layer. It covers the host network namespace and the listed signals. Full-system hangs, a compromised kernel, and a sufficiently privileged attacker can defeat host-local enforcement. A separate switch, gateway, or management controller is required for containment when the host itself cannot execute. Payload inspection, malware scanning, and operating-system patch management are outside the implemented coverage.

## Run the test suite

From the checkout on Linux:

```sh
python3 -m unittest discover -s tests -v
```

The suite uses Python’s standard library. It checks traffic accounting, alert decisions, heartbeat validation, local-model responses, database upgrades and retention, and the real dashboard HTTP API. It also verifies that schedules and completed checks survive reopening the database.

The integration tests use temporary state. The SMTP test delivers to a localhost-only TLS sink and verifies that an untrusted certificate leaves the alert queued for retry. The firewall test uses a disposable network namespace to apply real IPv4/IPv6 leases and verify isolation and recovery. Local socket access is needed for HTTP and SMTP. SMTP also requires OpenSSL, and the firewall test requires iproute2, nftables, and unprivileged network namespaces. A test skips when its environment prerequisite is unavailable. The suite does not use the live Watchdog database, install services, or send external email.

The suite checks frontend asset delivery and traffic telemetry parsers, including the UDP collector’s output format. Run the real Firefox smoke test with Firefox and GeckoDriver installed.

```sh
WATCHDOG_BROWSER_SMOKE=1 python3 -m unittest discover -s tests -p test_browser_smoke.py -v
```

The browser uses a temporary profile and a token-protected, synthetic dashboard on a random loopback port. The test exercises unlocking, running a check, navigation, saving a recurring check, and locking. Set `WATCHDOG_FIREFOX` and `WATCHDOG_GECKODRIVER` to absolute executable paths for standalone binaries, for example when Snap confinement prevents driver cleanup. You can run the command in a disposable network namespace with its loopback device enabled.

Run the UDP smoke test on an x86-64 Linux host with QEMU, static BusyBox, cpio, gzip, bpftrace, Python, and a readable bootable kernel image with BTF, tracefs, IPv6, and BPF tracing enabled.

```sh
bash tests/smoke/udp_vm.sh /path/to/vmlinuz-VERSION
```

The runner builds an initramfs from local tools and boots a QEMU guest with no network adapter, disk, or host filesystem mount. The collector must reach readiness and publish the exact IPv4 and IPv6 UDP byte and datagram counts for the guest test process. Guest root loads the probes. The host runner uses no elevated privileges.

For additional source and deployment validation:

```sh
python3 -m compileall -q watchdog deploy/udp
for script in deploy/*.sh; do sh -n "$script" || exit; done
systemd-analyze verify --man=no deploy/*.service deploy/udp/*.service
```


## Vulnerability tracking

Run these commands from the checkout. Use the service's state directory if it differs from the default observe-only checkout.

```sh
python3 -m watchdog vulnerabilities --directory .watchdog refresh
python3 -m watchdog vulnerabilities --directory .watchdog list
python3 -m watchdog vulnerabilities --directory .watchdog updates
python3 -m watchdog vulnerabilities --directory .watchdog evidence --hours 24
```

For the system-wide installation, run vulnerability commands as the service account so SQLite and the monitor have the same file ownership. From the installed application directory, the default state path is `/var/lib/ai-watchdog`.

```sh
cd /opt/ai-watchdog
sudo -u ai-watchdog -- python3 -B -m watchdog vulnerabilities refresh
sudo -u ai-watchdog -- python3 -B -m watchdog vulnerabilities list
```

`refresh` matches Canonical's [Ubuntu OSV feed](https://documentation.ubuntu.com/security/security-updates/osv/) against local dpkg source versions, including packaged Watchdog runtime dependencies. It also accepts `--ubuntu-archive PATH` for offline refreshes. Ubuntu archive packages are covered. Snap, manually installed programs, external package feeds, and Ubuntu Pro-only ecosystems are outside current coverage. The download does not send the inventory. The archive is expanded incrementally and can take a few minutes.

Watchdog records findings, source status and scan time in the monitor database. The Sensors page and active AI check include the saved summary. A failed refresh preserves prior findings. `list --all` includes entries outside the affected range and removed packages. A `vendor-listed` finding has no known fix threshold and may still be awaiting vendor evaluation. APT update candidates reflect locally cached indexes. A missing or incomparable candidate is reported as unknown. Add `--advisory` to focus on one advisory, `--scope dependency` to filter package findings, or `--limit 0` to return all matching rows.

To scan Watchdog's own release, place a trusted first-party manifest in `watchdog-advisories.json` in the state directory or pass `--watchdog-advisories PATH`. The optional `available_version` is the current release offered by that manifest. This example uses a fictional advisory.

```json
{
  "available_version": "0.1.1",
  "advisories": [
    {
      "id": "WD-2026-001",
      "severity": "high",
      "events": [{"introduced": "0.1.0"}, {"fixed": "0.1.1"}]
    }
  ]
}
```

For an evidence check, place reviewed rules in the state directory's `vulnerability-rules.json` or pass `--rules PATH`. Each rule must include an authoritative HTTPS reference. Each rule matches a Watchdog event kind with an exact subject, a literal detail substring, or both. A rule can instead match a literal message substring in a specific readable systemd service journal. This example uses fictional indicators.

```json
{
  "rules": [
    {
      "advisory": "WD-2026-001",
      "event_kind": "integrity",
      "subject": "/path/covered/by/the/vendor/notice",
      "reference": "https://example.invalid/vendor/advisory"
    },
    {
      "advisory": "WD-2026-001",
      "journal_unit": "example.service",
      "detail_contains": "vendor-documented diagnostic",
      "reference": "https://example.invalid/vendor/advisory"
    }
  ]
}
```

The evidence check reads existing records. It reports matching indicators, missing rules, and any journal coverage gap. No indicator rules ship enabled. The two [agent skills](skills/) can be installed by copying their directories into an agent's skills directory.
