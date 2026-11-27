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

Use this option for live observation under your own account. It requires an active systemd user manager and uses sensors available to the logged-in account. On APT-based hosts the installer may prompt for administrator access to set up ClamAV. Use `./deploy/install-user.sh --without-clamav` for an installation without administrator access.

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

Expand **Listener owners** in Host hardening to see each local endpoint, its visible process and service, and its allowlist status. Watchdog saves successful inventories in SQLite according to the configured retention period. The observe-only account may see a service name even when the owning process is hidden by OS permissions.

Use `allowed_listener_rules` to allow an exact service and interface without approving a port across the host. Rules can also require an app name and protocol. For example, this allows GNOME Files discovery only on the named Wi-Fi interface.

```json
"allowed_listener_rules": [
  {"service": "gvfs-daemon.service", "interface": "wlp5s0", "app": "wsdd", "protocol": "udp"}
]
```

Watchdog displays the interface from a reported socket scope or a uniquely assigned local address. A service-and-interface rule requires a verified receive scope for every socket at that endpoint. A reported socket scope or a device binding can establish receive scope. A local address association or configured multicast send interface alone leaves the endpoint marked **Review**. A global port entry in `allowed_listeners` applies across interfaces. This allowlist changes Watchdog's reporting. Network access is governed by the host and firewall.

UDP inventories record multicast send and receive-scope evidence per socket. On supported Linux architectures, Watchdog reads multicast send options when the kernel permits access to the owning process. The dashboard shows **Unavailable** when that access is restricted. Watchdog leaves the host's ptrace policy in effect.

An optional read-only helper uses the Linux BPF UDP iterator to read multicast send interfaces and group membership interfaces for the monitor's UID. It needs a kernel with BTF and UDP iterator support and a compatible bpftrace installation. Install it locally as follows.

```sh
sudo ./deploy/install-multicast.sh "$(id -un)"
```

The helper refreshes a root-owned runtime snapshot approximately every minute. Watchdog matches recent evidence to the live socket's inode and kernel cookie. The helper does not require ptrace access or change host security settings. Reported send interfaces and multicast memberships do not establish exclusive receive scope.

Record the Watchdog file baseline from trusted files. For the observe-only installation, run this from the checkout as the monitor user.

```sh
python3 -m watchdog baseline --directory .watchdog
```

The system installation records a root-owned Watchdog baseline with the existing `sudo python3 -B -m watchdog baseline` command. The baseline covers application code, dashboard assets, active configuration, service unit files and their local overrides, and installed UDP probe files when present. After an intentional update, review the files and use `sudo python3 -B -m watchdog baseline --watchdog-only` to refresh just the application baseline on system installations. The observe-only account owns its baseline, so a compromise of that account can affect what the checks report. Host-local checks also depend on the integrity of the running kernel.

### Optional ClamAV antivirus

On Ubuntu and Debian, both Watchdog installers install ClamAV and FreshClam when needed and start the signature updater for this boot and future boots. Rerunning an installer reuses the packages and any enabled FreshClam update timer. Use `--without-clamav` to skip package and updater setup. On systems without APT, install and update ClamAV using the distribution's package manager. [ClamAV package documentation](https://docs.clamav.net/manual/Installing/Packages.html)

Add the following keys to `.watchdog/config.json` for the user installation or `/etc/ai-watchdog/config.json` for the system installation. Replace the example with files or directories readable by the monitor. The system unit hides home directories, so use the user installation for a Downloads folder.

```json
{
  "antivirus_paths": ["/home/alex/Downloads"],
  "antivirus_check_minutes": 1440
}
```

Restart the monitor to apply the settings. The first scan runs shortly after the monitor is ready. Subsequent scans default to every 24 hours, with a configurable interval of 5 to 10,080 minutes. An empty path list disables scanning. After verifying the intentional configuration change, refresh the Watchdog file baseline as described above.

Open **Sensors → Antivirus** for readiness, daily signature age, scan paths, and the next and latest scan times. **Scan now** uses the same worker and paths as scheduled scans. Watchdog runs one scan at a time and schedules the next one from the latest result. Incomplete scans retry after five minutes. A clean rescan updates Sensors and keeps earlier detections in **Activity** under the usual retention policy. Detections are high-severity events and use the existing email settings.

Use **Open findings** to review malware detections across the retained history. Filter by review status and use **Older** and **Newer** to page through results. **Acknowledge** records that you reviewed a finding. After a newer scan of the same configured paths finishes clean and scans at least one file, use **Resolve with clean scan** to link that result to the finding. The original alert remains in **Activity** under the usual retention policy, and the resolved findings filter shows the linked scan timestamp and summary. Older findings recorded before Watchdog saved the scan paths can be acknowledged.

Scans run locally under the monitor account with a shared 15-minute limit. **Coverage by scan path** shows ClamAV's file counts, access errors, file or archive limit hits, and elapsed time for each attempted path. Elapsed time includes loading the scanner. A reported limit hit makes coverage incomplete. Counts for overlapping paths can include the same file twice. Directory scans skip symlinks and nested mounts. ClamAV uses official signatures, and Watchdog reports an incomplete scan if the signatures are missing or older than seven days. Watchdog reports findings and leaves the files in place. [ClamAV scanning documentation](https://docs.clamav.net/manual/Usage/Scanning.html)

Open **Sensors → Antivirus coverage history** to see previous path results under the configured retention period. Filter by path or load older results. Retained results remain available after paths are removed from the configuration. History starts with scans run after this feature is installed.

Activity records a medium-severity coverage alert after three successive scans report a path access error, scan error, or file or archive limit. Further failures for that path leave the incident open without repeating the alert. An information event records recovery when ClamAV scans files on that path without reporting an error or limit. Empty paths and scanner-wide failures provide no evidence of recovery.

To opt into the warm backend, install the matching `clamav-daemon` package and set `"antivirus_clamd": true`, then restart Watchdog. It starts its own unprivileged ClamD process on a private Unix socket and passes files opened by the monitor account. The private process loads official signatures and reports scanner limit hits. Watchdog compares the loaded signature version with the current on-disk database before scanning. Startup failures, version mismatches, and ambiguous scan replies fall back to ClamScan within the same scan time limit. The per-path coverage view records which backend ran and the reason for a fallback. [ClamD protocol documentation](https://docs.clamav.net/manual/Usage/ClamdProtocol.html)

### Optional Wi-Fi-only GNOME discovery

On Ubuntu systems with the `wsdd` package, an enforced `/usr/bin/wsdd` AppArmor profile, and GNOME’s `wsdd` backend, find your Wi-Fi interface with `ip -brief link`. From a trusted checkout run the following, replacing `wlp5s0` with that interface.

```sh
sudo ./deploy/install-wsdd-wifi.sh install wlp5s0
```

The installer registers a local dpkg diversion so package updates install the vendor executable at `/usr/bin/wsdd.distrib`. It installs a launcher at `/usr/bin/wsdd` and adds one marked rule granting read access to that vendor file. The launcher binds discovery sockets to the Wi-Fi device and preserves the packaged behavior for other invocations. It refuses an unmanaged diversion or rule. Existing discovery processes pick up the launcher at their next start. Sign out and back in to restart the GNOME discovery session, then reopen **Network** in Files.

The installer registers a dpkg post-update hook. If dpkg installs a fresh copy of the packaged AppArmor profile, the hook restores the read rule and reloads the enforced profile before dpkg returns. The hook checks the package's conffile checksum and preserves the rest of the updated profile. Rerun `install` with the same interface to add the hook to an existing managed setup.

After a `wsdd` or AppArmor update, run the check below. It verifies the hook, diversion, launcher hash, vendor file, exact read rule, enforced profile, and packaged program startup. Watchdog also checks the launcher and rule on its scheduled health cadence and reports drift in **Sensors**. Its file integrity baseline tracks the hook and both installed helper files. Refresh the baseline after verifying an intentional installation or update of these files. If the hook warns that it could not restore the rule, review the profile and run the check before restarting discovery.

```sh
sudo ./deploy/install-wsdd-wifi.sh check
```

To roll back, run the command below, then sign out and back in before reopening Network in Files. Rollback restores the current package executable from its diverted path and removes the installer’s marked AppArmor rule. This restores the package’s default discovery scope, which can include VPN and Docker interfaces.

```sh
sudo ./deploy/install-wsdd-wifi.sh rollback
```

Rollback also removes the dpkg hook and its installed helper files.

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

Set `"coverage_notify_minutes": 60` inside `email_alerts` to opt into one email per path incident that stays unresolved for 60 minutes after Watchdog records degradation. This policy applies independently of `minimum_severity`. Use 0 to disable it. Recovery cancels queued mail for that incident. The email omits scan paths, so use Activity to identify the affected path.

In **Settings → Coverage email delivery**, Watchdog shows the coverage queue, any retry time, the last coverage message accepted by the SMTP relay, and the last coverage message that expired before delivery. Ordinary alert mail does not update these coverage timestamps.

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

### Roll back the Watchdog application

Run the desktop command from the installed checkout as the monitor user. For the system installation, run from `/opt/ai-watchdog` with a trusted older checkout in a root-controlled directory.

```sh
# Desktop
python3 -B -m watchdog rollback --desktop /path/to/trusted-older-checkout

# System-wide
cd /opt/ai-watchdog
sudo python3 -B -m watchdog rollback /opt/trusted-older-checkout
```

The command stops the installed services, backs up the running application, configuration, SQLite database, dashboard token, and standard baseline files, then replaces the Python package and dashboard assets. It preserves the live configuration, database, service units, and installed dependencies. System-wide rollback checks for an isolation latch before making changes. Use a version compatible with the current configuration and database. Schedule a local maintenance window and stop any independent tools that write to the database before running the command.

The backup path is printed before the change. Desktop backups are under `.watchdog/rollbacks` and system backups under `/var/lib/ai-watchdog-rollbacks`. Backups are private and contain the dashboard token. Keep them protected according to your local backup policy. After restarting the target, the command checks the authenticated dashboard and any previously running supervisor. If startup fails, it attempts to restore the original application and database and reports the backup path.

### Create, verify, and restore backups

Run from the installed desktop checkout as the monitor user. For the system installation, run from `/opt/ai-watchdog` as root and omit `--desktop`.

```sh
python3 -B -m watchdog backups --desktop create
python3 -B -m watchdog backups --desktop list
python3 -B -m watchdog backups --desktop verify /path/to/backup-directory
python3 -B -m watchdog backups --desktop restore /path/to/backup-directory
```

Create briefly stops Watchdog so it can back up a consistent SQLite database. List inventories backups in the local backup directory. Verify checks the SHA-256 manifest and SQLite integrity. Use backups from a trusted source. Backups made before manifests were introduced are listed as unverified.

To restore onto a fresh host, first install and start Watchdog in the same installation mode. Copy the backup directory over a trusted channel and keep it private and owned by the account running restore. Restore verifies the backup before stopping the services, backs up the destination, and restores the configuration, database, token, and recorded baseline files. It uses the destination's installed application and leaves its local containment latch in place. If the restored dashboard fails its authenticated health check, the command attempts to recover the destination's prior state. Review scan paths, the integrity baseline, and any separately stored SMTP credential on the destination.

For off-host storage, install `age` and export a sealed backup to a native age X25519 public recipient. Generate and store the corresponding private identity separately. The export writes an encrypted archive and refuses to overwrite an existing destination. The machine creating the export needs only the public recipient.

```sh
python3 -B -m watchdog backups --desktop export /path/to/backup-directory watchdog.age --recipient age1...
python3 -B -m watchdog backups --desktop verify watchdog.age --identity /private/age-identity
python3 -B -m watchdog backups --desktop restore watchdog.age --identity /private/age-identity
```

Omit `--desktop` and run as root for a system-wide backup. Verification and restore use private local temporary storage to decrypt the archive, check its layout, and verify its manifest and SQLite database. Restore requires the identity and the encrypted archive. Neither command reinstalls the application from the archive.

### Schedule off-host backups and restore drills

The system installer installs two opt-in systemd timers. Install `age` and `rclone` on the uploader and verifier, configure authenticated remote storage, and reserve one remote subdirectory per Watchdog installation. The uploader needs list, read, write, and delete access to that subdirectory. Give the verifier list and read access and keep the private age identity on the verifier and in your recovery storage. Use mode `0600` for the job files, credentials, and identity. [rclone configuration](https://rclone.org/docs/)

On the Watchdog host, create `/etc/ai-watchdog/backup-upload.json` and point it to the uploader's rclone config. Set `keep` to the number of encrypted archives to retain, between 2 and 365.

```json
{
  "remote": "offsite:watchdog-backups/endpoint01",
  "rclone_config": "backup-upload-rclone.conf",
  "recipient": "age1...",
  "keep": 30
}
```

```sh
sudo systemctl start ai-watchdog-backup-upload.service
sudo systemctl enable --now ai-watchdog-backup-upload.timer
journalctl -u ai-watchdog-backup-upload.service
```

The daily job briefly stops Watchdog while it captures consistent state. It encrypts the backup locally, uploads only ciphertext, and reads the uploaded archive back to verify its SHA-256 digest before deleting older managed archives. It preserves unrelated files. Use a single uploader per subdirectory.

For immutable storage, set `keep` to `0` and configure retention with your storage provider. Watchdog still verifies its uploads and leaves expiration to the provider, so the uploader only needs list, read, and create access. Verify the provider's immutability policy before relying on it. [Amazon S3 Object Lock documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)

On a separate verifier with the system Watchdog package installed, create `/etc/ai-watchdog/backup-drill.json` with the same remote and the credential names below. Place the verifier's rclone config at `/etc/ai-watchdog/backup-drill-rclone.conf` and its private age identity at `/etc/ai-watchdog/backup-drill-identity`. The service uses private temporary copies, so choose a remote credential that works without persisting a refreshed config file.

```json
{
  "remote": "offsite:watchdog-backups/endpoint01",
  "rclone_config": "rclone.conf",
  "identity": "identity"
}
```

```sh
sudo systemctl start ai-watchdog-backup-drill.service
sudo systemctl enable --now ai-watchdog-backup-drill.timer
journalctl -u ai-watchdog-backup-drill.service
```

The weekly drill downloads the newest archive, checks the digest, verifies the decrypted manifest and SQLite database, and starts an isolated authenticated dashboard using scratch state, with enforcement and email disabled. Check the timer and service journal for the result. If the system must be recovered, download the desired encrypted archive and run `backups verify` and `backups restore` with the private identity on the destination.

**Sensors → Off-host backups** shows job deadlines, the last successful runs, and recorded failures. Activity records uploads overdue by default after 26 hours and drills overdue after 170 hours without success. It also records drill failures and recoveries. Set `backup_upload_max_hours` or `backup_drill_max_hours` in the Watchdog monitor configuration if you change a schedule.

To see a separate verifier's results on the primary dashboard, reserve a dedicated writable status subdirectory outside the immutable archives. Generate a shared reporting key with `openssl rand -hex 32` and securely install the same key file on both hosts. Keep the reporting key separate from the age identity. Use mode `0600` for the job files, key, and rclone credentials. Put side-specific rclone credentials under `/etc/ai-watchdog`, granting the verifier write access to the status object and the primary read access. Use this configuration on both hosts with their respective local credential filenames.

```json
{
  "verifier": "recovery-host",
  "remote": "offsite:watchdog-status/endpoint01",
  "rclone_config": "backup-verifier-rclone.conf",
  "key_file": "backup-verifier.key"
}
```

On the verifier, save it as `/etc/ai-watchdog/backup-verifier-report.json` and enable `ai-watchdog-backup-verifier@report.timer`. On the primary, save it as `/etc/ai-watchdog/backup-verifier-import.json` and enable `ai-watchdog-backup-verifier@import.timer`. Use `sudo systemctl enable --now` for each timer. To test immediately, start the verifier's `ai-watchdog-backup-verifier@report.service` and then the primary's `ai-watchdog-backup-verifier@import.service`. The timers sync about every five minutes. Keep both clocks synchronized.

The verifier sends authenticated outcome timestamps. The primary rejects tampered reports and keeps the last accepted result when a sync fails or replays an older report. **Sensors → Off-host backups** displays the latest report time alongside **Remote verifier**, and **Activity** records its failed, overdue, and recovered drills.

To rotate the age key, generate a new identity on the verifier, replace the uploader's public `recipient`, publish a new archive, and update the verifier's drill identity. Keep the retired identity in recovery storage for as long as any archive encrypted to it is retained. Older immutable archives stay encrypted to their original recipients. To rehearse an older recovery point, run `backups drill --job /path/to/private-job.json --archive ARCHIVE_NAME` with a job file pointing to the retired identity, or download the archive and verify it directly.

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

Run the antivirus smoke test on an x86-64 Linux host with QEMU, OVMF, xorriso, OpenSSH, Python, Firefox, and GeckoDriver. Use the official Ubuntu 24.04 amd64 cloud image and allow the guest to reach the Ubuntu package mirrors and ClamAV signature servers. [Ubuntu cloud images](https://cloud-images.ubuntu.com/releases/noble/release/)

```sh
bash tests/smoke/eicar_vm.sh /path/to/ubuntu-24.04-server-cloudimg-amd64.img
bash tests/smoke/eicar_vm.sh /path/to/ubuntu-24.04-server-cloudimg-amd64.img desktop-upgrade
bash tests/smoke/eicar_vm.sh /path/to/ubuntu-24.04-server-cloudimg-amd64.img system-upgrade
bash tests/smoke/eicar_vm.sh /path/to/ubuntu-24.04-server-cloudimg-amd64.img backup-restore
bash tests/smoke/eicar_vm.sh /path/to/ubuntu-24.04-server-cloudimg-amd64.img system-backup-restore
```

Each run creates a disposable disk overlay and verifies that FreshClam is enabled and downloads signatures. The Firefox test acknowledges an EICAR alert in **Open findings**, runs a clean scan after the sample is removed, checks retained coverage and timing for both results, and resolves the original finding. The upgrade modes install the pre-review commit `ae1fe37`, upgrade, use the operator rollback command and verify its state backup and dashboard health check, then reinstall the latest version to confirm the review and coverage history survived. The system-wide mode also checks per-path coverage under home-directory restrictions, reports scan limits and unreadable files, and exercises stale signature recovery using the disposable guest clock.

The runner uses a loopback-only SSH tunnel for dashboard access and discards the guest and its test data afterward. A successful run prints `WATCHDOG_EICAR_VM_PASS`. The Firefox executable overrides above also apply to this test. Set `WATCHDOG_OVMF_CODE` and `WATCHDOG_OVMF_VARS` if OVMF is installed outside `/usr/share/OVMF`.

GitHub Actions runs the EICAR smoke test on pull requests and pushes to `main` that touch the installers, antivirus integration, or smoke test. The workflow also supports manual runs from the Actions tab.

The backup-restore scenario creates a real backup on one VM and verifies it on a separately installed VM with a different machine ID. It checks that configuration, dashboard access, acknowledged EICAR evidence, and timed antivirus history survive the restore.

The system-backup-restore scenario requires `age-keygen` and `rclone` on the host. It verifies EICAR detection under Ubuntu's unchanged ClamD AppArmor profile and exercises ClamScan fallback. The storage fixture tests normal retention and enforces write-once rules on a separate archive directory. The test checks missed uploads, overdue drills and their recoveries, confirms overwrites and deletes are refused, then restores pre-rotation and post-rotation archives on a fresh Ubuntu VM using their respective keys. A separate primary VM imports the verifier's signed report and shows the alerts in its dashboard. The temporary private age identities are supplied only to the restore VM.

### Benchmark multi-path antivirus scans

With matching ClamAV and ClamD binaries and the packaged signature database at `/var/lib/clamav`, run the comparison from the checkout. The benchmark starts a temporary daemon under the current account on a private Unix socket.

```sh
PYTHONPATH="$PWD" python3 -B tests/smoke/benchmark_clamav.py --clamd /path/to/clamd
```

One ClamAV 1.5.4 run used three trials with 24 benign 16 KiB files per path. The batch times below are medians, with each batch taken from the corresponding prefix of a four-path trial. Ubuntu VM tests were active on the same host, so these numbers describe the small-file startup cost on that host.

| Paths | Watchdog with `clamscan` | Warm private `clamd` |
| --- | ---: | ---: |
| 1 | 19.737 s | 0.328 s |
| 2 | 38.069 s | 0.454 s |
| 4 | 82.064 s | 0.610 s |

ClamD took 12.813 s to start and used 100.6 MiB of resident memory after the trials. These results support an opt-in daemon for frequent multi-path scans. Keep the existing backend until a daemon integration can reproduce per-path permission and limit reporting, verify signature freshness, and recover safely if the socket is unavailable. [ClamD protocol documentation](https://docs.clamav.net/manual/Usage/ClamdProtocol.html)

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
