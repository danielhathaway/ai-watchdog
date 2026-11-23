"use strict";

const get = (id) => document.getElementById(id);
const text = (id, value) => {
  if (get(id).textContent !== String(value)) get(id).textContent = value;
};
const date = (stamp) => new Date(stamp * 1000);
const time = (stamp) => date(stamp).toLocaleTimeString([], {hour: "numeric", minute: "2-digit"});
const fullDate = (stamp) => date(stamp).toLocaleString([], {month: "short", day: "numeric", hour: "numeric", minute: "2-digit"});
const number = new Intl.NumberFormat();
const pages = {overview: "Overview", activity: "Activity", devices: "Devices", sensors: "Sensors", settings: "Settings"};
let token = sessionStorage.getItem("watchdog-token") || "";
let snapshot = null;
let pending = false;
let generation = 0;
let accessFailed = false;
let scheduleEdited = false;

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
    for (const sample of samples) {
      if (sample[metric] == null) {
        previous = null;
        continue;
      }
      const px = x(sample.at);
      const py = y(sample[metric]);
      if (previous != null && sample.at - previous <= Math.max(75, interval * 3)) ctx.lineTo(px, py);
      else ctx.moveTo(px, py);
      previous = sample.at;
    }
    ctx.stroke();
    const latest = samples.at(-1);
    if (latest?.[metric] != null) {
      ctx.beginPath();
      ctx.arc(x(latest.at), y(latest[metric]), 3, 0, 2 * Math.PI);
      ctx.fill();
    }
    ctx.restore();
  }
  const latest = samples.at(-1);
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

function eventList(id, records) {
  const items = records.map((record) => {
    const item = element("li");
    const label = record.severity[0].toUpperCase() + record.severity.slice(1);
    const status = element("span", null, "dot " + ({critical: "bad", high: "bad", medium: "warning", info: "good"}[record.severity] || ""));
    status.title = label;
    status.setAttribute("aria-label", label + " severity");
    status.setAttribute("role", "img");
    const description = element("div");
    description.append(element("strong", record.title));
    const details = [record.subject, record.detail].filter(Boolean).join(" · ");
    if (details) description.append(element("small", details));
    const when = element("time", fullDate(record.at));
    when.dateTime = date(record.at).toISOString();
    item.append(status, description, when);
    return item;
  });
  get(id).replaceChildren(...(items.length ? items : [element("li", "No matching events.", "empty")]));
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
  get("email-status").replaceChildren(...values.map(([name, value]) => {
    const row = element("div");
    row.append(element("dt", name), element("dd", value));
    return row;
  }));
  get("email-help").hidden = email.enabled;
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
window.addEventListener("hashchange", route);
window.addEventListener("resize", drawTraffic);
route();
refresh();
setInterval(refresh, 3000);
