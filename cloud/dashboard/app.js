// Vorynex dashboard (M8).
// Reads the control-plane API and renders hosts, protection mode, and a
// containment event timeline. All user/agent data is inserted via textContent.

const $ = (sel) => document.querySelector(sel);

const params = new URLSearchParams(location.search);
const tokenParam = params.get("token");
if (tokenParam) sessionStorage.setItem("vorynex-token", tokenParam);

const state = {
  token: sessionStorage.getItem("vorynex-token") || "",
  hosts: [],
  events: [],
  selectedHost: null,
  onlyContained: false,
  busy: false,
};

const MODES = ["observe", "protect", "lockdown"];

function authHeaders() {
  return state.token ? { Authorization: "Bearer " + state.token } : {};
}

async function getJSON(path) {
  const res = await fetch(path, { headers: authHeaders() });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

function setStatus(kind, label) {
  const s = $("#cloud-status");
  s.dataset.state = kind;
  s.querySelector("span:last-child").textContent = label;
}

function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d)) return "—";
  return d.toLocaleTimeString([], { hour12: false });
}

function ago(ts) {
  const d = new Date(ts);
  if (isNaN(d)) return "—";
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

// An event is "contained" when the kernel refused the access. strace records
// any failed syscall as allowed:false, including harmless ENOENT misses, so we
// only count permission denials (EACCES/EPERM) as containment.
function isContained(e) {
  const ev = eventOf(e);
  if (!ev || ev.allowed !== false) return false;
  const reason = String(ev.reason || "");
  return reason.includes("EACCES") || reason.includes("EPERM");
}

function eventOf(e) {
  return (e && e.record && e.record.event) || {};
}

function hostStats(hostId) {
  let events = 0, contained = 0, last = null, gaps = 0;
  for (const e of state.events) {
    if (hostId && e.host_id !== hostId) continue;
    if (e.record && e.record.gap) { gaps++; continue; }
    events++;
    if (isContained(e)) contained++;
    const ts = eventOf(e).timestamp;
    if (ts && (!last || ts > last)) last = ts;
  }
  return { events, contained, last, gaps };
}

function selectedHostObj() {
  return state.hosts.find((h) => h.host_id === state.selectedHost) || null;
}

async function load() {
  setStatus("loading", "Loading");
  try {
    const [hosts, events] = await Promise.all([
      getJSON("/v1/hosts"),
      getJSON("/v1/events?limit=300"),
    ]);
    state.hosts = hosts.hosts || [];
    state.events = events.events || [];
    render();
    setStatus("ok", "Connected");
  } catch (err) {
    renderError(err);
    setStatus("error", "Unreachable");
  }
}

function render() {
  const contained = state.events.filter(isContained).length;
  const host = selectedHostObj();

  $("#stat-workloads").textContent = String(state.hosts.length);
  $("#stat-events").textContent = String(state.events.filter((e) => !(e.record && e.record.gap)).length);
  $("#stat-contained").textContent = String(contained);
  $("#stat-mode").textContent = host ? host.mode : state.hosts.length ? "mixed" : "—";
  $("#nav-events-count").textContent = String(state.events.length);
  $("#rail-host").textContent = host ? host.host_id : state.hosts.length ? state.hosts.length + " hosts" : "no hosts";
  $("#subline").textContent = state.hosts.length
    ? `${state.hosts.length} host${state.hosts.length === 1 ? "" : "s"} · ${state.events.length} events · Tier 0 spawn-time containment`
    : "No hosts enrolled yet";
  $("#wl-hint").textContent = host ? `Filtered to ${host.host_id}` : "";
  $("#clear-filter").hidden = !host;

  renderWorkloads();
  renderEvents();
}

function renderWorkloads() {
  const body = $("#wl-body");
  body.textContent = "";

  if (state.hosts.length === 0) {
    const cmd = el("code", { class: "code", text: "vorynex telemetry export --endpoint http://127.0.0.1:8787 --once" });
    body.append(
      el("div", { class: "empty" }, [
        el("h3", { text: "No workloads enrolled yet" }),
        el("p", { text: "Enroll this host and export telemetry. The dashboard reads from the local control plane." }),
        cmd,
      ])
    );
    return;
  }

  const table = el("table", { class: "table" });
  const thead = el("thead", {}, [
    el("tr", {}, [
      el("th", { scope: "col", text: "Workload" }),
      el("th", { scope: "col", text: "Mode" }),
      el("th", { scope: "col", text: "Events" }),
      el("th", { scope: "col", text: "Contained" }),
      el("th", { scope: "col", text: "Last event" }),
      el("th", { scope: "col", text: "Status" }),
    ]),
  ]);
  const tbody = el("tbody");

  for (const h of state.hosts) {
    const s = hostStats(h.host_id);
    const tr = el("tr", { "aria-selected": String(state.selectedHost === h.host_id) });

    const nameBtn = el("button", {
      class: "row-btn mono",
      type: "button",
      "aria-pressed": String(state.selectedHost === h.host_id),
      text: h.host_id,
      title: "Filter events to this workload",
    });
    nameBtn.addEventListener("click", () => {
      state.selectedHost = state.selectedHost === h.host_id ? null : h.host_id;
      render();
    });

    tr.append(el("td", { "data-label": "Workload" }, [nameBtn]));
    tr.append(el("td", { "data-label": "Mode" }, [modeControl(h)]));
    tr.append(el("td", { class: "num", "data-label": "Events", text: String(s.events) }));
    tr.append(
      el("td", { class: "num", "data-label": "Contained" }, [
        s.contained > 0 ? el("span", { class: "badge badge-contained", text: String(s.contained) }) : el("span", { class: "muted", text: "0" }),
      ])
    );
    tr.append(el("td", { class: "muted", "data-label": "Last event", text: s.last ? ago(s.last) : "—" }));
    tr.append(el("td", { "data-label": "Status" }, [statusBadge(s)]));
    tbody.append(tr);
  }

  table.append(thead, tbody);
  body.append(table);
}

function statusBadge(s) {
  if (s.events === 0) return el("span", { class: "badge badge-allowed", text: "no data" });
  if (s.last && Date.now() - new Date(s.last).getTime() < 10 * 60 * 1000) {
    return el("span", { class: "badge badge-contained", text: "reporting" });
  }
  return el("span", { class: "badge badge-gap", text: "stale" });
}

function modeControl(host) {
  const group = el("div", { class: "modes", role: "group", "aria-label": "Protection mode for " + host.host_id });
  for (const m of MODES) {
    const b = el("button", {
      type: "button",
      "aria-pressed": String(host.mode === m),
      text: m,
    });
    if (state.busy) b.disabled = true;
    b.addEventListener("click", () => setMode(host, m));
    group.append(b);
  }
  return group;
}

async function setMode(host, mode) {
  if (state.busy || host.mode === mode) return;
  state.busy = true;
  render();
  try {
    const res = await fetch("/v1/hosts/" + encodeURIComponent(host.host_id) + "/mode", {
      method: "POST",
      headers: Object.assign({ "Content-Type": "application/json" }, authHeaders()),
      body: JSON.stringify({ mode }),
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    host.mode = mode;
    setStatus("ok", "Mode saved");
  } catch (err) {
    setStatus("error", "Mode not saved");
  } finally {
    state.busy = false;
    render();
  }
}

function renderEvents() {
  const body = $("#ev-body");
  body.textContent = "";

  let rows = state.events.filter((e) => !(e.record && e.record.gap));
  if (state.selectedHost) rows = rows.filter((e) => e.host_id === state.selectedHost);
  if (state.onlyContained) rows = rows.filter(isContained);
  rows = rows.slice(0, 60);

  if (rows.length === 0) {
    body.append(
      el("div", { class: "empty" }, [
        el("h3", { text: state.onlyContained ? "No contained events" : "No events yet" }),
        el("p", {
          text: state.onlyContained
            ? "Nothing has been denied in the current view. Run a workload under Vorynex and export telemetry."
            : "Enrolled hosts have not exported events yet. Run observe or protect, then export.",
        }),
      ])
    );
    return;
  }

  const list = el("ul", { class: "events" });
  for (const e of rows) {
    const ev = eventOf(e);
    const contained = isContained(e);
    const li = el("li", { class: "event" + (contained ? " is-contained" : "") });

    li.append(el("span", { class: "event-time", text: fmtTime(ev.timestamp) }));

    const what = el("div", { class: "event-what" });
    const head = el("div", {}, [
      el("span", { class: "event-act", text: (ev.action || "access") + " " }),
      el("span", { class: "event-target", text: ev.resource || "(unknown)" }),
    ]);
    what.append(head);
    what.append(el("div", { class: "event-host", text: e.host_id }));
    if (contained && ev.reason) what.append(el("div", { class: "event-why", text: ev.reason }));
    li.append(what);

    li.append(
      el("span", {}, [
        el("span", {
          class: "badge " + (contained ? "badge-contained" : "badge-allowed"),
          text: contained ? "contained" : "allowed",
        }),
      ])
    );

    list.append(li);
  }
  body.append(list);
}

function renderError(err) {
  const body = $("#wl-body");
  body.textContent = "";
  const unauthorized = String(err && err.message) === "HTTP 401";
  body.append(
    el("div", { class: "error" }, [
      el("h3", { text: unauthorized ? "Authentication required" : "Cannot reach the control plane" }),
      el("p", {
        text: unauthorized
          ? "This control plane requires a token. Open the dashboard with ?token=<your-token> or run the server with --token \"\" for local use."
          : "The dashboard could not load hosts or events. Check that vorynex-cloud is running and refresh.",
      }),
      el("button", { class: "btn", type: "button", text: "Retry" , id: "retry" }),
    ])
  );
  const retry = body.querySelector("#retry");
  if (retry) retry.addEventListener("click", load);

  $("#ev-body").textContent = "";
  $("#ev-body").append(el("div", { class: "empty" }, [el("p", { text: "Event timeline unavailable while disconnected." })]));
}

// ---- wiring ----
$("#refresh").addEventListener("click", load);
$("#only-contained").addEventListener("change", (e) => {
  state.onlyContained = e.target.checked;
  renderEvents();
});
$("#clear-filter").addEventListener("click", () => {
  state.selectedHost = null;
  render();
});

load();
