"use strict";

const get = (id) => document.getElementById(id);
const text = (id, value) => {
  if (get(id).textContent !== String(value)) get(id).textContent = value;
};
const date = (stamp) => new Date(stamp * 1000);
const time = (stamp) => date(stamp).toLocaleTimeString([], {hour: "numeric", minute: "2-digit"});
const fullDate = (stamp) => date(stamp).toLocaleString([], {month: "short", day: "numeric", hour: "numeric", minute: "2-digit"});
const number = new Intl.NumberFormat();
const pages = {overview: "Overview", activity: "Activity", findings: "Open findings", devices: "Devices", sensors: "Sensors", settings: "Settings"};
let token = sessionStorage.getItem("watchdog-token") || "";
let snapshot = null;
let pending = false;
let antivirusPending = false;
let generation = 0;
let accessFailed = false;
let scheduleEdited = false;
let findingCursors = [null];
let nextFindingCursor = null;
let findingRequest = 0;
let historyRequest = 0;
let historyCursor = null;
let historyLatest = null;

function announce(message) {
  get("error").hidden = !message;
  text("error", message || "");
}

async function api(path, method = "GET", payload) {
  const headers = token ? {Authorization: "Bearer " + token} : {};
  if (payload !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method, headers, body: payload === undefined ? undefined : JSON.stringify(payload),
    cache: "no-store", signal: AbortSignal.timeout(5000)
  });
  if (response.status === 401) {
    const error = new Error("Access token required");
    error.unauthorized = true;
    throw error;
  }
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result;
}

function route() {
  const requested = location.hash.slice(1);
  const id = Object.hasOwn(pages, requested) ? requested : "overview";
  for (const section of Object.keys(pages)) {
    get(section).hidden = id !== section;
    const link = document.querySelector(`[data-page="${section}"]`);
    if (id === section) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  text("page-name", pages[id]);
  if (id === "findings" && snapshot) loadFindings();
  drawTraffic();
}

function formatRate(value) {
  if (value == null) return "—";
  if (value >= 1e6) return (value / 1e6).toFixed(1) + " MB/s";
  if (value >= 1000) return Math.round(value / 1000) + " kB/s";
  return Math.round(value) + " B/s";
}

function drawTraffic() {
  const canvas = get("traffic-chart");
  if (!snapshot || !canvas.clientWidth) return;
  const {samples, now, interval} = snapshot;
  const usable = samples.filter((sample) => sample.rx != null || sample.tx != null);
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  const scale = window.devicePixelRatio || 1;
  canvas.width = width * scale;
  canvas.height = height * scale;
  const ctx = canvas.getContext("2d");
  ctx.scale(scale, scale);
  ctx.font = "12px system-ui";
  const step = Math.max(100, ...usable.flatMap((sample) => [sample.rx || 0, sample.tx || 0])) / 4;
  const unit = 10 ** Math.floor(Math.log10(step));
  const top = 4 * Math.ceil(step / unit) * unit;
  const left = 72;
  const right = width - 13;
  const upper = 12;
  const floor = height - 28;
  const x = (at) => left + (right - left) * (at - now + 3600) / 3600;
  const y = (value) => floor - (floor - upper) * value / top;
  ctx.fillStyle = "#9eafc5";
  ctx.strokeStyle = "#273648";
  ctx.textAlign = "right";
  for (let index = 0; index <= 4; index++) {
    const value = top * index / 4;
    ctx.fillText(formatRate(value), left - 8, y(value) + 4);
    ctx.beginPath();
    ctx.moveTo(left, y(value));
    ctx.lineTo(right, y(value));
    ctx.stroke();
  }
  for (const minutes of [60, 45, 30, 15, 0]) {
    if (width < 375 && ![60, 30, 0].includes(minutes)) continue;
    ctx.textAlign = minutes === 60 ? "left" : minutes === 0 ? "right" : "center";
    ctx.fillText(minutes ? `−${minutes}m` : "Now", x(now - minutes * 60), floor + 21);
  }
  for (const [metric, color] of [["rx", "#65e0b4"], ["tx", "#8daaff"]]) {
    ctx.save();
    ctx.beginPath();
    ctx.rect(left, upper - 3, right - left, floor - upper + 6);
    ctx.clip();
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    let previous = null;
    for (const sample of usable) {
      if (sample[metric] == null) continue;
      const px = x(sample.at);
      const py = y(sample[metric]);
      if (previous != null && sample.at - previous <= Math.max(75, interval * 3)) ctx.lineTo(px, py);
      else ctx.moveTo(px, py);
      previous = sample.at;
    }
    ctx.stroke();
    const latest = usable.at(-1);
    if (latest?.[metric] != null) {
      ctx.beginPath();
      ctx.arc(x(latest.at), y(latest[metric]), 3, 0, 2 * Math.PI);
      ctx.fill();
    }
    ctx.restore();
  }
  const latest = snapshot.interface_traffic || usable.at(-1);
  text("traffic-detail", latest?.rx != null || latest?.tx != null
    ? `Current inbound ${formatRate(latest.rx)} · outbound ${formatRate(latest.tx)}`
    : "Waiting for traffic samples");
}

function element(tag, content, className) {
  const node = document.createElement(tag);
  if (content != null) node.textContent = content;
  if (className) node.className = className;
  return node;
}

function rateTable(columns, rows) {
  const wrapper = element("div", null, "table-wrap");
  const table = element("table");
  const heading = element("tr");
  for (const label of columns) {
    const column = element("th", label);
    column.scope = "col";
    heading.append(column);
  }
  const head = element("thead");
  head.append(heading);
  const body = element("tbody");
  body.append(...rows);
  table.append(head, body);
  wrapper.append(table);
  return wrapper;
}

function cells(values) {
  const row = element("tr");
  for (const value of values) row.append(element("td", value));
  return row;
}

function formatCount(value) {
  return value == null ? "—" : number.format(value);
}

function sampleAccounting(attribution) {
  if (!attribution.payload_rates) return null;
  const labels = {tcp: ["TCP payload", "TCP segments", "Estimated IP + TCP headers (B)"],
                  udp: ["UDP payload", attribution.framing_sources?.udp === "test_client"
                    ? "UDP datagrams (test client)" : "UDP datagram calls", "Estimated UDP headers (B)"]};
  const rows = [];
  for (const protocol of ["tcp", "udp"]) {
    const payload = attribution.payload_rates[protocol];
    if (!payload) continue;
    const framing = attribution.framing[protocol] || {};
    rows.push(cells([labels[protocol][0], formatRate(payload.rx), formatRate(payload.tx)]));
    if (framing.rx || framing.tx) {
      rows.push(cells([labels[protocol][1], formatCount(framing.rx?.packets), formatCount(framing.tx?.packets)]));
      rows.push(cells([labels[protocol][2], formatCount(framing.rx?.header_bytes), formatCount(framing.tx?.header_bytes)]));
    }
  }
  return rateTable(["Process traffic total", "Inbound", "Outbound"], rows);
}

function interfaceTable(interfaces) {
  const ordered = interfaces.toSorted((a, b) => Number(b.counted) - Number(a.counted));
  const hasPackets = ordered.some((row) => row.rx_packets != null || row.tx_packets != null);
  const columns = ["Interface", "In total", "Inbound", "Outbound"];
  if (hasPackets) columns.push("Packets in", "Packets out");
  return rateTable(columns, ordered.map(({name, counted, rx, tx, rx_packets, tx_packets}) => {
    const values = [name, counted ? "Yes" : "No", formatRate(rx), formatRate(tx)];
    if (hasPackets) values.push(formatCount(rx_packets), formatCount(tx_packets));
    return cells(values);
  }));
}

function processRows(processes, protocols) {
  return processes.map((process) => {
    const hasUDP = protocols?.udp === "ready";
    const tcpRx = hasUDP ? process.tcp_rx : process.rx;
    const tcpTx = hasUDP ? process.tcp_tx : process.tx;
    return cells([process.name, process.pid, formatRate(tcpRx), formatRate(tcpTx),
                  formatRate(process.udp_rx), formatRate(process.udp_tx)]);
  });
}

function windowLabel(sample) {
  const times = (at) => date(at).toLocaleTimeString([], {
    hour: "numeric", minute: "2-digit", second: "2-digit",
  });
  return `${times(sample.window_start)}–${times(sample.at)} · ${number.format(sample.window_seconds)} s shared window`;
}

function renderInterfaces(current, spikes = []) {
  const labels = {physical: "Physical uplinks", default: "Default-route interface", single: "Single interface"};
  const scope = current ? labels[current.method] || "Uplink unavailable" : null;
  text("traffic-scope", scope ? `Last hour · ${scope}` : "Last hour · bytes per second");
  get("live-interfaces").hidden = !current?.interfaces.length;
  if (current?.interfaces.length && get("live-interface-table").dataset.sample !== String(current.at)) {
    get("live-interface-table").dataset.sample = current.at;
    get("live-interface-table").replaceChildren(interfaceTable(current.interfaces));
  }

  const container = get("interface-spikes");
  const key = spikes.map(({id, at}) => `${id}:${at}`).join(",");
  if (container.dataset.spikes === key) return;
  container.dataset.spikes = key;
  const opened = new Set(Array.from(container.querySelectorAll("details[open]"), (item) => item.dataset.spike));
  const entries = spikes.map((spike) => {
    const detail = element("details", null, "interface-detail");
    detail.dataset.spike = spike.id;
    detail.open = opened.has(String(spike.id));
    const rates = spike.deviations.map(({metric, observed}) =>
      `${metric === "rx" ? "Inbound" : "Outbound"} ${formatRate(observed)}`);
    const stamp = date(spike.at).toLocaleString([], {
      month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit"
    });
    detail.append(element("summary", `${stamp} · ${rates.join(" · ")}`));
    if (spike.window_seconds) {
      const label = spike.window_start != null ? windowLabel(spike) : `${number.format(spike.window_seconds)} s interface sample`;
      detail.append(element("p", label, "interface-window"));
    }
    detail.append(interfaceTable(spike.interfaces));
    if (spike.attribution) {
      const {top = [], protocols} = spike.attribution;
      const missing = (["tcp", "udp"]).filter((key) => protocols[key] !== "ready").map((key) => key.toUpperCase());
      const label = missing.length ? `${missing.join(" and ")} data unavailable for this window.` : "";
      if (top.length) {
        detail.append(element("p", "Process traffic", "interface-window spike-process-title"),
          rateTable(["Process", "PID", "TCP in", "TCP out", "UDP in", "UDP out"], processRows(top, protocols)));
      } else if (!label) {
        detail.append(element("p", "No attributed process traffic in this window.", "interface-window spike-process-title"));
      }
      const accounting = sampleAccounting(spike.attribution);
      if (accounting) detail.append(accounting);
      if (spike.attribution.payload_rates?.udp && !Object.keys(spike.attribution.framing?.udp || {}).length) {
        detail.append(element("p", "UDP packet counts require the updated collector.", "interface-window spike-process-title"));
      }
      if (label) detail.append(element("p", label, "interface-window spike-process-title"));
    }
    return detail;
  });
  container.replaceChildren(...(entries.length ? entries : [element("p", "No interface breakdowns recorded yet.", "empty")]));
}

function spikeAttribution(record, open) {
  const details = element("details", null, "spike-details");
  details.dataset.event = record.id;
  details.open = open;
  const direction = record.subject === "rx" ? "inbound" : "outbound";
  const attribution = record.attribution;
  const hasUDP = attribution?.protocols?.udp === "ready";
  details.append(element("summary", `Processes with ${direction} ${hasUDP ? "TCP / UDP" : "TCP"} traffic`));
  if (attribution?.state !== "ready") {
    details.append(element("p", "No process sample is available for this event."));
    return details;
  }
  const metric = record.subject;
  const rows = attribution.processes.map((process) => {
    const rates = hasUDP
      ? [process[`tcp_${metric}`] == null ? null : `TCP ${formatRate(process[`tcp_${metric}`])}`,
        `UDP ${formatRate(process[`udp_${metric}`])}`].filter(Boolean).join(" · ")
      : formatRate(process[metric]);
    return element("li", `${process.name} (PID ${process.pid}) · ${rates}`);
  });
  if (attribution.unattributed > 0) {
    rows.push(element("li", `TCP without a visible owner · ${formatRate(attribution.unattributed)}`));
  }
  if (rows.length) {
    const list = element("ul", null, "spike-processes");
    list.append(...rows);
    details.append(list);
  } else {
    details.append(element("p", "No matching traffic was captured in this sample."));
  }
  return details;
}

function renderProcessTraffic(traffic) {
  const processes = traffic?.top || [];
  const unknown = traffic?.unattributed;
  const udp = traffic?.protocols?.udp;
  const tcp = traffic?.protocols?.tcp;
  text("process-scope", udp === "ready" ? "TCP / UDP"
    : udp === "stale" || udp === "unavailable" ? "UDP data unavailable" : "UDP collector off");
  text("process-timestamp", traffic?.window_start != null ? windowLabel(traffic)
    : traffic?.at ? `Sample at ${time(traffic.at)}` : "Latest sample");
  get("process-table").hidden = !processes.length;
  get("process-empty").hidden = Boolean(processes.length);
  text("process-empty", traffic?.state === "ready" ? "No traffic from a visible process in this sample."
    : tcp === "warming" ? "Waiting for a second TCP sample." : "Process traffic data is unavailable.");
  get("process-rows").replaceChildren(...processRows(processes, traffic?.protocols));
  get("process-unknown").hidden = !(unknown?.rx || unknown?.tx);
  if (unknown) text("process-unknown",
    `TCP without a visible owner · inbound ${formatRate(unknown.rx)} · outbound ${formatRate(unknown.tx)}`);
}

function eventList(id, records) {
  const container = get(id);
  const eventKey = records.map(({id, at, review}) =>
    JSON.stringify([id, at, review?.acknowledged_at, review?.resolved_at, review?.can_resolve])).join(",");
  if (container.dataset.eventKey === eventKey) return;
  container.dataset.eventKey = eventKey;
  const openItems = new Set(Array.from(container.querySelectorAll("details[open]"), (item) => item.dataset.event));
  const items = records.map((record) => {
    const item = element("li");
    item.dataset.eventId = record.id;
    const label = record.severity[0].toUpperCase() + record.severity.slice(1);
    const status = element("span", null, "dot " + ({critical: "bad", high: "bad", medium: "warning", info: "good"}[record.severity] || ""));
    status.title = label;
    status.setAttribute("aria-label", label + " severity");
    status.setAttribute("role", "img");
    const description = element("div");
    description.append(element("strong", record.title));
    const details = [record.subject, record.detail].filter(Boolean).join(" · ");
    if (details) description.append(element("small", details));
    if (id !== "recent-events" && record.review) description.append(findingReview(record));
    if (record.kind === "anomaly" && ["rx", "tx"].includes(record.subject)) {
      description.append(spikeAttribution(record, openItems.has(String(record.id))));
    }
    const when = element("time", fullDate(record.at));
    when.dateTime = date(record.at).toISOString();
    item.append(status, description, when);
    return item;
  });
  const empty = id === "finding-events" ? "No matching findings." : "No matching events.";
  container.replaceChildren(...(items.length ? items : [element("li", empty, "empty")]));
}

async function loadFindings() {
  const current = ++findingRequest;
  const before = generation;
  const query = new URLSearchParams({status: get("finding-status").value});
  const cursor = findingCursors.at(-1);
  if (cursor != null) query.set("before", cursor);
  try {
    const page = await api("/api/findings?" + query);
    if (before !== generation || current !== findingRequest) return;
    if (!page.events.length && findingCursors.length > 1) {
      findingCursors.pop();
      await loadFindings();
      return;
    }
    nextFindingCursor = page.next_before;
    eventList("finding-events", page.events);
    text("finding-page", `Page ${findingCursors.length}`);
    get("finding-newer").disabled = findingCursors.length === 1;
    get("finding-older").disabled = nextFindingCursor == null;
  } catch (error) {
    if (before === generation && current === findingRequest && location.hash === "#findings") announce(error.message);
  }
}

function changeFindingsPage() {
  nextFindingCursor = null;
  get("finding-newer").disabled = true;
  get("finding-older").disabled = true;
  loadFindings();
}

function findingReview({id, review}) {
  const panel = element("div", null, "finding-review");
  if (review.resolved_at) {
    panel.append(element("small", `Resolved ${fullDate(review.resolved_at)} · Clean scan ${fullDate(review.evidence_at)} · ${review.evidence_detail}`));
    return panel;
  }
  if (review.acknowledged_at) {
    panel.append(element("small", `Acknowledged ${fullDate(review.acknowledged_at)}`));
    if (!review.can_resolve) {
      panel.append(element("small", review.scope_recorded
        ? "A clean rescan of the same paths is required to resolve this finding."
        : "Scan paths were unavailable when this finding was recorded."));
      return panel;
    }
  }
  const action = review.acknowledged_at ? "resolve" : "acknowledge";
  const button = element("button", action === "resolve" ? "Resolve with clean scan" : "Acknowledge", "text-button");
  button.type = "button";
  button.addEventListener("click", async () => {
    const before = generation;
    button.disabled = true;
    announce("");
    try {
      await api(`/api/alerts/${id}/${action}`, "POST");
    } catch (error) {
      if (before === generation) announce(error.message);
    } finally {
      button.disabled = false;
      if (before === generation) await refresh();
    }
  });
  panel.append(button);
  return panel;
}

function filterEvents() {
  if (!snapshot) return;
  const severity = get("severity").value;
  eventList("all-events", snapshot.events.filter((event) => (
    severity === "all" || event.severity === severity || (severity === "high" && event.severity === "critical")
  )));
}

function render() {
  const {response, sensors, assessment, ready, assessing, samples, now, interval} = snapshot;
  const recent = samples.length && now - samples.at(-1).at < 3 * interval;
  const active = ready && recent;
  const working = Object.values(sensors).filter((state) => state === "ready").length;
  const all = Object.keys(sensors).length;
  text("mode", {demo: "Demo data", observe: "Observe only", enforce: "Enforcement on"}[response.mode]);
  get("mode-dot").className = "dot " + (response.mode === "enforce" ? "good" : "");
  text("last-updated", `Updated ${time(now)}`);
  text("monitoring", active ? (working === all ? "Active" : "Degraded") : ready ? "Stalled" : "Starting");
  get("monitoring").className = active && working === all ? "good-text" : "warning-text";
  text("monitoring-detail", all ? `${working} of ${all} sensors ready` : "Waiting for first sample");
  const status = response.watchdog_alive ? response.status : "unavailable";
  const labels = {isolated: "Isolated", failed: "Response failed", "would-isolate": "Would isolate",
    observing: response.mode === "demo" ? "Simulated" : response.mode === "observe" ? "Observe only" : "Armed",
    unavailable: "Unavailable", starting: "Starting"};
  text("containment", labels[status] || "Unavailable");
  get("containment").className = ["failed", "isolated", "unavailable"].includes(status) ? "bad-text"
    : status === "would-isolate" ? "warning-text" : "good-text";
  text("containment-detail", response.reason || `${number.format(response.blocked.length)} active blocks`);
  text("alerts", number.format(snapshot.alert_count));
  text("device-count", number.format(snapshot.device_count));
  text("assessment-model", assessment?.model || "Statistical baseline");
  text("assessment-title", assessing ? "Checking this host" : assessment?.error ? "Check failed" : assessment ? "Check complete" : "Ready to run");
  text("assessment-description", assessing ? "Reviewing local evidence and recent activity."
    : assessment?.summary || "Run an AI check for a fresh assessment of this host.");
  text("assessment-at", assessment
    ? `${assessment.trigger === "scheduled" ? "Scheduled check · " : ""}${fullDate(assessment.at)}`
    : "");
  get("run").disabled = !active || assessing || pending;
  renderProcessTraffic(snapshot.process_traffic);
  renderInterfaces(snapshot.interface_traffic, snapshot.interface_spikes);
  eventList("recent-events", snapshot.events.slice(0, 5));
  filterEvents();
  const devices = snapshot.devices.map((device) => {
    const row = element("tr");
    for (const cell of [device.address, device.mac, device.interface, fullDate(device.first_seen), fullDate(device.last_seen)]) {
      row.append(element("td", cell));
    }
    return row;
  });
  get("device-rows").replaceChildren(...devices);
  get("no-devices").hidden = devices.length > 0;
  get("sensor-rows").replaceChildren(...Object.entries(sensors).map(([name, state]) => {
    const row = element("div");
    row.append(element("dt", name), element("dd", state, state === "ready" ? "good-text" : "warning-text"));
    return row;
  }));
  renderSystemChecks();
  const vulnerability = snapshot.vulnerabilities;
  const coverage = Object.entries(vulnerability?.sources || {});
  const vulnerabilityRows = [["Unresolved findings",
    vulnerability?.status === "recorded" ? number.format(vulnerability.unresolved) : "No scan recorded"]];
  for (const [source, detail] of coverage) {
    const name = {watchdog: "Watchdog advisories", os: "OS advisories", kev: "CISA KEV"}[source] || source;
    const publicCheck = detail.online_at ?? (detail.local === undefined ? detail.checked_at : null);
    const last = publicCheck ? `Last public refresh ${fullDate(publicCheck)}` : "No public refresh recorded";
    const warnings = [detail.freshness === "stale" ? "Stale" : "",
      detail.status === "failed" ? "Refresh failed" : ""].filter(Boolean);
    const value = detail.freshness
      ? [...warnings, last, detail.local && detail.checked_at ? `Offline import ${fullDate(detail.checked_at)}` : ""]
        .filter(Boolean).join(" · ")
      : detail.status === "ready" ? fullDate(detail.checked_at) : detail.status.replaceAll("-", " ");
    vulnerabilityRows.push([name, value, warnings.length ? "warning-text" : ""]);
  }
  if (vulnerability?.known_exploited !== undefined) {
    const fixLabels = {
      "reboot-required": "Fixed kernel installed, reboot required",
      "running-affected": "Running kernel still affected",
      "active": "Kernel fix active",
      "service-restart-required": "Service restart required",
      "service-runtime-unverified": "Service fix still unverified",
      "userspace-active": "Fix active in observed services",
      "installed-runtime-unverified": "Fix installed, service runtime unverified",
      "runtime-unverified": "Kernel runtime unverified",
      "fix-not-installed": "Fix not installed",
    };
    vulnerabilityRows.push(["Known exploited findings", number.format(vulnerability.known_exploited)]);
    if (vulnerability.kernel_check?.release) {
      const build = vulnerability.kernel_check.build ? ` · build ${vulnerability.kernel_check.build}` : "";
      vulnerabilityRows.push(["Kernel at last check", vulnerability.kernel_check.release + build]);
    }
    if (vulnerability.previous_boot) {
      vulnerabilityRows.push(["Fix verification", "Results from a previous boot", "warning-text"]);
    }
    for (const [state, count] of Object.entries(vulnerability.fixes)) {
      vulnerabilityRows.push([fixLabels[state] || state, number.format(count),
        ["reboot-required", "running-affected", "service-restart-required", "service-runtime-unverified"].includes(state)
          ? "warning-text" : ""]);
    }
    for (const finding of vulnerability.priority_findings) {
      const status = [finding.status.replaceAll("-", " "), fixLabels[finding.fix_verification]].filter(Boolean).join(" · ");
      const fixed = finding.fixed ? ` · fixed version ${finding.fixed}` : "";
      vulnerabilityRows.push([finding.advisory, `${finding.component} · ${status}${fixed}`, "warning-text"]);
    }
    const runtime = vulnerability.userspace;
    if (runtime?.status === "recorded") {
      const partial = runtime.scope === "user" || runtime.limited || runtime.unreadable
        || runtime.partial_units || runtime.unreadable_packages;
      const scope = runtime.scope === "user" ? "Visible user services" : "Host services";
      vulnerabilityRows.push(["Userspace runtime check", `${fullDate(runtime.at)} · ${scope}${
        partial ? " · Partial coverage" : ""}`, partial ? "warning-text" : ""]);
      const serviceLabels = {"restart-required": "Restart required", active: "Patched files loaded",
        unverified: "Unverified"};
      for (const service of vulnerability.service_findings) {
        const unit = service.unit.split("/").at(-1);
        const user = service.unit.match(/\/user-(\d+)\.slice\//)?.[1];
        vulnerabilityRows.push([user ? `${unit} (UID ${user})` : unit,
          `${service.component} · ${serviceLabels[service.status]}`,
          service.status === "active" ? "good-text" : "warning-text"]);
      }
      if (vulnerability.service_findings_total > vulnerability.service_findings.length) {
        vulnerabilityRows.push(["More service results", "See vulnerabilities list --all for details"]);
      }
    } else if (runtime) {
      vulnerabilityRows.push(["Userspace runtime check", "Awaiting a fresh check", "warning-text"]);
    }
  }
  get("vulnerability-status").replaceChildren(...vulnerabilityRows.map(([name, value, color]) => {
    const row = element("div");
    row.append(element("dt", name), element("dd", value, color));
    return row;
  }));
  get("blocks").replaceChildren(...(response.blocked.length
    ? response.blocked.map((address) => {
      const item = element("li");
      item.append(element("span", null, "dot warning"), element("strong", address));
      return item;
    })
    : [element("li", "No active blocks.", "empty")]));
  renderSettings();
  drawTraffic();
}

function renderSystemChecks() {
  const labels = {pass: "Passed", warn: "Review", fail: "Failed", unknown: "Unavailable", skipped: "Skipped"};
  const colors = {pass: "good-text", warn: "warning-text", fail: "bad-text"};
  const antivirus = snapshot.system_checks?.antivirus;
  get("antivirus-panel").hidden = !antivirus;
  if (antivirus) renderAntivirus(antivirus);
  renderBackupHealth();
  for (const group of ["health", "hardening"]) {
    const report = snapshot.system_checks?.[group];
    const target = get(`${group}-checks`);
    const listenersOpen = target.querySelector(".listener-inventory")?.open ?? false;
    const certificatesOpen = target.querySelector(".certificate-inventory")?.open ?? false;
    const cadence = report ? `Every ${number.format(report.interval_minutes)} min · ` : "";
    text(`${group}-check-time`, cadence + (report?.at ? `Last run ${fullDate(report.at)}` : "No check recorded"));
    const rows = (report?.checks ?? []).map((entry) => {
      const row = element("div");
      const detail = element("dd");
      detail.append(element("strong", labels[entry.status], colors[entry.status]), element("span", entry.detail));
      if (entry.listeners?.length) {
        const inventory = element("details", null, "listener-inventory");
        inventory.open = listenersOpen;
        const list = element("ul");
        for (const listener of entry.listeners) {
          const host = listener.address.includes(":") ? `[${listener.address}]` : listener.address;
          const owners = [
            ...listener.processes.map(({app, pid}) => `${app} (PID ${pid})`),
            ...listener.services,
          ];
          const item = element("li", `${host}:${listener.port} ${listener.protocol.toUpperCase()} · `
            + (owners.join(", ") || "Owner unavailable")
            + ` · ${listener.interface || "Interface unavailable"}`
            + (listener.allowed ? " · Allowed" : " · Review")
            + (listener.socket_count > 1 ? ` · ${listener.socket_count} sockets` : ""));
          if (listener.sockets?.length) {
            const sockets = element("ul");
            for (const socket of listener.sockets) {
              const outbound = Object.entries(socket.multicast_send).map(([family, value]) =>
                `${family === "ipv4" ? "IPv4" : "IPv6"} ${value.interface || value.address || `ifindex ${value.index}`}`);
              const send = outbound.join(", ") || (socket.socket_options_available ? "No interface reported" : "Unavailable");
              const memberships = (socket.multicast_memberships ?? []).map(({family, interface: name, index}) =>
                `IPv${family} ${name || `ifindex ${index}`}`);
              sockets.append(element("li", `Receive scope: ${socket.receive_interface || "Unverified"} · Multicast send: ${send}`
                + (memberships.length ? ` · Multicast memberships: ${memberships.join(", ")}` : "")));
            }
            item.append(sockets);
          }
          list.append(item);
        }
        inventory.append(element("summary", `Listener owners (${entry.listeners.length})`), list);
        detail.append(inventory);
      }
      if (entry.certificate_findings?.length) {
        const inventory = element("details", null, "certificate-inventory");
        inventory.open = certificatesOpen;
        const list = element("ul");
        for (const certificate of entry.certificate_findings) {
          const row = element("li", certificate.subject || "Unknown subject");
          row.append(element("span", `SHA-256 ${certificate.sha256}`),
            element("span", certificate.issues.map(issue => issue.replaceAll("-", " ")).join(", ")));
          list.append(row);
        }
        inventory.append(element("summary", `Certificates to review (${entry.certificate_finding_count})`), list);
        detail.append(inventory);
      }
      row.append(element("dt", entry.name), detail);
      return row;
    });
    target.replaceChildren(...rows);
  }
}

function renderBackupHealth() {
  const names = {upload: "Encrypted backup uploads", drill: "Restore drills", verifier: "Remote verifier"};
  const labels = {healthy: "Healthy", overdue: "Overdue", failed: "Last run failed", waiting: "Waiting for first run"};
  const colors = {healthy: "good-text", overdue: "bad-text", failed: "bad-text", waiting: "warning-text"};
  const rows = Object.entries(snapshot.backup_health ?? {}).map(([job, report]) => {
    const row = element("div");
    const detail = element("dd");
    detail.append(element("strong", labels[report.status], colors[report.status]));
    if (job === "verifier") {
      const reporting = {current: "Reporting current", waiting: "Waiting for first report", overdue: "Reports overdue"};
      if (report.report_status) {
        const channel = element("span");
        channel.append(element("strong", reporting[report.report_status],
          report.report_status === "overdue" ? "bad-text" : report.report_status === "current" ? "good-text" : "warning-text"));
        detail.append(channel);
      }
      detail.append(element("span", report.reported_at
        ? `${report.verifier} · Last report ${fullDate(report.reported_at)}` : "No verifier report received"));
      if (report.report_deadline) detail.append(element("span", `Report deadline ${fullDate(report.report_deadline)}`));
    }
    if (report.success_at) detail.append(element("span", `Last successful run ${fullDate(report.success_at)}`));
    if (report.failure_at) detail.append(element("span", `Last failed run ${fullDate(report.failure_at)}`));
    if (report.deadline) detail.append(element("span", `${job === "upload" ? "Upload" : "Drill"} deadline ${fullDate(report.deadline)}`));
    row.append(element("dt", names[job]), detail);
    return row;
  });
  get("backup-health-panel").hidden = !rows.length;
  get("backup-health").replaceChildren(...rows);
}

function renderAntivirus(report) {
  const {readiness, running, next_at: next, paths, checks} = report;
  const labels = {
    checking: "Checking", ready: "Ready", "missing-scanner": "ClamAV is unavailable",
    "missing-signatures": "Waiting for signatures", "stale-signatures": "Signatures are stale",
    unavailable: "Unable to check signatures",
  };
  const activity = running ? "Scan in progress" : next <= snapshot.now ? "Scan due now" : `Next scan ${fullDate(next)}`;
  text("antivirus-check-time", activity + (report.at ? ` · Last run ${fullDate(report.at)}` : ""));
  get("scan-antivirus").disabled = antivirusPending || running || !snapshot.ready;
  const hours = Math.max(0, Math.floor((snapshot.now - readiness.signatures_at) / 3600));
  const signatureAge = readiness.signatures_at == null ? "Unavailable" : hours < 24 ? `${hours} h` : `${Math.floor(hours / 24)} d`;
  const values = [
    ["Readiness", labels[readiness.state], readiness.state === "ready" ? "good-text" : "warning-text"],
    ["Signature age", signatureAge, readiness.state === "stale-signatures" ? "warning-text" : ""],
    ["Scan paths", paths.join("\n"), "scan-paths"],
    ["Coverage", "ClamAV skips symlinks and nested mounts and applies file and archive limits."],
  ];
  get("antivirus-readiness").replaceChildren(...values.map(([name, value, style]) => {
    const row = element("div");
    row.append(element("dt", name), element("dd", value, style));
    return row;
  }));
  const scan = checks?.[0];
  const outcomes = {pass: "Clean", fail: "Detection", warn: "Incomplete scan", skipped: "No files scanned"};
  const style = {pass: "good-text", fail: "bad-text", warn: "warning-text"};
  const result = element("div");
  const detail = element("dd");
  detail.append(element("strong", scan ? outcomes[scan.status] : "No scan recorded", style[scan?.status]));
  if (scan) {
    detail.append(element("span", scan.detail));
    if (scan.scan_errors) detail.append(element("span", `Scan errors: ${number.format(scan.scan_errors)}`));
    if (scan.status !== "pass" && scan.files_scanned != null) {
      detail.append(element("span", `Files scanned: ${number.format(scan.files_scanned)}`));
    }
  }
  result.append(element("dt", "Last result"), detail);
  get("antivirus-checks").replaceChildren(result);
  const coverage = scan?.coverage ?? [];
  get("antivirus-coverage").hidden = !coverage.length;
  get("antivirus-path-results").replaceChildren(...coverage.map(coverageRow));
  if (get("antivirus-history").open && report.at !== historyLatest) {
    historyLatest = report.at;
    loadAntivirusHistory();
  }
}

function coverageRow(path) {
  const outcomes = {pass: "Clean", fail: "Detection", warn: "Incomplete scan", skipped: "No files scanned"};
  const style = {pass: "good-text", fail: "bad-text", warn: "warning-text"};
  const row = element("div");
  const detail = element("dd");
  const counts = [];
  if (path.files_scanned != null) counts.push(`Files counted by ClamAV: ${number.format(path.files_scanned)}`);
  if (path.access_errors) counts.push(`Access errors: ${number.format(path.access_errors)}`);
  if (path.scan_errors) counts.push(`Scan errors: ${number.format(path.scan_errors)}`);
  if (path.limit_hits) counts.push(`File or archive limit hits: ${number.format(path.limit_hits)}`);
  if (path.backend) counts.push(path.fallback ? "ClamScan fallback" : path.backend === "clamd" ? "ClamD" : "ClamScan");
  if (path.duration_seconds != null) {
    counts.push(`Elapsed: ${path.duration_seconds.toLocaleString([], {maximumFractionDigits: 3})} s`);
  }
  detail.append(element("strong", outcomes[path.status], style[path.status]), element("span", path.detail));
  if (path.fallback) detail.append(element("span", path.fallback));
  if (counts.length) detail.append(element("span", counts.join(" · ")));
  const label = element("dt", path.path);
  if (path.at != null) label.append(element("small", ` · ${fullDate(path.at)}`));
  row.append(label, detail);
  return row;
}

async function loadAntivirusHistory(older = false) {
  const before = generation;
  const request = ++historyRequest;
  const select = get("history-path");
  const path = select.value;
  const query = new URLSearchParams();
  if (path) query.set("path", path);
  if (older && historyCursor != null) query.set("before", historyCursor);
  get("history-older").disabled = true;
  try {
    const history = await api("/api/antivirus/history?" + query);
    if (before !== generation || request !== historyRequest) return;
    historyCursor = history.next_before;
    const allPaths = new Set([...history.paths, ...(path ? [path] : [])]);
    select.replaceChildren(new Option("All paths", ""), ...[...allPaths].map((value) => new Option(value, value)));
    select.value = path;
    const rows = history.results.map(coverageRow);
    if (older) get("history-results").append(...rows);
    else get("history-results").replaceChildren(...rows);
    text("history-status", get("history-results").children.length ? "" : "No coverage history for this selection.");
    get("history-older").hidden = historyCursor == null;
  } catch (error) {
    if (before === generation && request === historyRequest) text("history-status", error.message);
  } finally {
    if (before === generation && request === historyRequest) get("history-older").disabled = false;
  }
}

function renderSettings() {
  const {schedule, email} = snapshot;
  if (!scheduleEdited) get("schedule-minutes").value = schedule.interval_minutes;
  text("next-check", schedule.next_at
    ? `Every ${number.format(schedule.interval_minutes)} min · Next ${fullDate(schedule.next_at)}`
    : "Off");
  const values = email.enabled ? [
    ["Delivery", email.retry_at ? "Retrying" : "Enabled"],
    ["Severity", email.minimum_severity === "critical" ? "Critical only" : "High and critical"],
    ["Pending alerts", number.format(email.pending)],
    ["Last accepted by SMTP", email.last_sent_at ? fullDate(email.last_sent_at) : "None yet"],
  ] : [["Delivery", "Off"]];
  if (email.retry_at) values.push(["Next retry", fullDate(email.retry_at)]);
  const rows = (entries) => entries.map(([name, value]) => {
    const row = element("div");
    row.append(element("dt", name), element("dd", value));
    return row;
  });
  get("email-status").replaceChildren(...rows(values));
  get("email-help").hidden = email.enabled;
  const coverage = email.coverage;
  const delivery = email.enabled && email.coverage_notify_minutes ? [
    ["Delivery", coverage.retry_at ? "Retrying" : coverage.pending ? "Queued" : "Enabled"],
    ["Unresolved coverage", `Email after ${email.coverage_notify_minutes} min`],
    ["Pending alerts", number.format(coverage.pending)],
    ["Last accepted by SMTP", coverage.last_accepted_at ? fullDate(coverage.last_accepted_at) : "None yet"],
  ] : [["Delivery", "Off"]];
  if (coverage?.retry_at) delivery.push(["Next retry", fullDate(coverage.retry_at)]);
  if (coverage?.last_expired_at) delivery.push(["Last expired before delivery", fullDate(coverage.last_expired_at)]);
  get("coverage-email-status").replaceChildren(...rows(delivery));
}

function feedback(message, failed = false) {
  text("schedule-feedback", message);
  get("schedule-feedback").classList.toggle("bad-text", failed);
  get("schedule-feedback").hidden = !message;
}

function lock(showError = false) {
  generation++;
  scheduleEdited = false;
  feedback("");
  token = "";
  snapshot = null;
  get("antivirus-history").open = false;
  get("history-results").replaceChildren();
  get("history-path").replaceChildren(new Option("All paths", ""));
  get("history-older").hidden = true;
  text("history-status", "");
  historyCursor = null;
  historyLatest = null;
  findingCursors = [null];
  nextFindingCursor = null;
  get("finding-status").value = "open";
  get("finding-events").replaceChildren();
  delete get("finding-events").dataset.eventKey;
  text("finding-page", "");
  get("finding-newer").disabled = true;
  get("finding-older").disabled = true;
  sessionStorage.removeItem("watchdog-token");
  get("dashboard").hidden = true;
  get("unlock").hidden = false;
  get("lock").hidden = true;
  get("run").disabled = true;
  text("last-updated", "Local access required");
  announce(showError ? "The access token was rejected." : "");
}

async function refresh() {
  const before = generation;
  try {
    const status = await api("/api/status");
    if (generation !== before) return;
    const initial = !snapshot;
    snapshot = status;
    get("unlock").hidden = true;
    get("dashboard").hidden = false;
    get("lock").hidden = !token;
    if (accessFailed || initial) announce("");
    accessFailed = false;
    render();
    if (location.hash === "#findings") loadFindings();
  } catch (error) {
    if (generation !== before) return;
    if (error.unauthorized) lock(Boolean(token));
    else {
      get("run").disabled = true;
      if (snapshot) {
        text("monitoring", "Unreachable");
        get("monitoring").className = "bad-text";
      }
      accessFailed = true;
      announce("The local monitor is unreachable.");
    }
  }
}

get("unlock").addEventListener("submit", (event) => {
  event.preventDefault();
  generation++;
  token = get("token").value.trim();
  get("token").value = "";
  sessionStorage.setItem("watchdog-token", token);
  refresh();
});
get("lock").addEventListener("click", () => lock());
get("scan-antivirus").addEventListener("click", async () => {
  antivirusPending = true;
  get("scan-antivirus").disabled = true;
  const before = generation;
  announce("");
  try {
    await api("/api/antivirus/scan", "POST");
  } catch (error) {
    if (before === generation) announce(error.message);
  } finally {
    antivirusPending = false;
    if (before === generation) await refresh();
  }
});
get("run").addEventListener("click", async () => {
  pending = true;
  get("run").disabled = true;
  announce("");
  try {
    await api("/api/check", "POST");
    if (location.hash !== "#overview") location.hash = "overview";
  } catch (error) {
    announce(error.message);
  } finally {
    pending = false;
    await refresh();
  }
});
get("schedule-minutes").addEventListener("input", () => {
  scheduleEdited = true;
  feedback("");
});
get("schedule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const before = generation;
  const input = get("schedule-minutes");
  const button = event.submitter;
  button.disabled = true;
  input.disabled = true;
  try {
    const saved = await api("/api/schedule", "PUT", {interval_minutes: input.valueAsNumber});
    if (before !== generation) return;
    scheduleEdited = false;
    snapshot.schedule = saved;
    renderSettings();
    feedback(saved.interval_minutes ? "Schedule saved." : "Recurring checks turned off.");
    await refresh();
  } catch (error) {
    if (before === generation) feedback(error.message, true);
  } finally {
    button.disabled = false;
    input.disabled = false;
  }
});
get("severity").addEventListener("change", filterEvents);
get("antivirus-history").addEventListener("toggle", () => {
  if (get("antivirus-history").open && snapshot) {
    historyLatest = snapshot.system_checks?.antivirus?.at;
    loadAntivirusHistory();
  }
});
get("history-path").addEventListener("change", () => loadAntivirusHistory());
get("history-older").addEventListener("click", () => loadAntivirusHistory(true));
get("finding-status").addEventListener("change", () => {
  findingCursors = [null];
  changeFindingsPage();
});
get("finding-newer").addEventListener("click", () => {
  findingCursors.pop();
  changeFindingsPage();
});
get("finding-older").addEventListener("click", () => {
  if (nextFindingCursor == null) return;
  findingCursors.push(nextFindingCursor);
  changeFindingsPage();
});
window.addEventListener("hashchange", route);
window.addEventListener("resize", drawTraffic);
route();
refresh();
setInterval(refresh, 3000);
