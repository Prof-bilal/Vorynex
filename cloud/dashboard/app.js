// Vorynex dashboard (M8).
// Reads the control-plane API and renders hosts, protection mode, a workload
// detail panel, and a containment event timeline. All agent data is inserted
// via textContent, never innerHTML.

const $ = (sel) => document.querySelector(sel);

const params = new URLSearchParams(location.search);
if (params.get("token")) sessionStorage.setItem("vorynex-token", params.get("token"));

const MODES = ["observe", "protect", "lockdown"];
const POLL_MS = 15000;

const state = {
  token: sessionStorage.getItem("vorynex-token") || "",
  hosts: [],
  events: [],
  selectedHost: null,
  onlyContained: false,
  busy: false,
  paused: false,
  needsAuth: false,
  lastLoad: 0,
  policy: null,
  policyHost: null,
  sbom: null,
};

let pollTimer = null;

class AuthError extends Error {}

function authHeaders() {
  return state.token ? { Authorization: "Bearer " + state.token } : {};
}

async function getJSON(path) {
  const res = await fetch(path, { headers: authHeaders() });
  if (res.status === 401) throw new AuthError("unauthorized");
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

function eventOf(e) {
  return (e && e.record && e.record.event) || {};
}

// "Contained" means the kernel refused the access. strace records every failed
// syscall as allowed:false, including harmless ENOENT misses, so count only
// permission denials.
function isContained(e) {
  const ev = eventOf(e);
  if (!ev || ev.allowed !== false) return false;
  const reason = String(ev.reason || "");
  return reason.includes("EACCES") || reason.includes("EPERM");
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

function hostLabel(id) {
  const h = state.hosts.find((x) => x.host_id === id);
  return h ? (h.hostname || h.host_id) : id;
}

function isInteracting() {
  const a = document.activeElement;
  if (!a) return false;
  return ["#wl-body", "#ev-body", "#detail-body"].some((sel) => {
    const root = $(sel);
    return root && root.contains(a);
  });
}

async function load(opts = {}) {
  if (!opts.silent) setStatus("loading", "Loading");
  try {
    let hosts, events;
    if (window.__VORYNEX_DEMO__) {
      hosts = window.__VORYNEX_DEMO__.hosts || [];
      events = window.__VORYNEX_DEMO__.events || [];
      // In the static preview, open the first workload so the detail panel is
      // visible without interaction.
      if (!state.selectedHost && hosts.length) state.selectedHost = hosts[0].host_id;
    } else {
      const [h, e] = await Promise.all([
        getJSON("/v1/hosts"),
        getJSON("/v1/events?limit=300"),
      ]);
      hosts = h.hosts || [];
      events = e.events || [];
    }
    state.hosts = hosts;
    state.events = events;
    state.lastLoad = Date.now();
    hideLogin();
    const hostId = state.selectedHost || (state.hosts[0] && state.hosts[0].host_id) || null;
    await loadHostExtras(hostId);
    // Don't steal focus or rebuild the DOM under the operator's hands during a
    // silent poll; the state is updated and the next render will pick it up.
    if (!(opts.silent && isInteracting())) render();
    setStatus("ok", window.__VORYNEX_DEMO__ ? "Preview" : "Connected");
  } catch (err) {
    if (err instanceof AuthError) {
      showLogin();
      setStatus("error", "Sign in required");
      return;
    }
    if (opts.silent) {
      setStatus("error", "Refresh failed");
    } else {
      renderError(err);
      setStatus("error", "Unreachable");
    }
  }
}

// loadHostExtras fetches the effective policy and the correlated SBOM a host
// uploaded. It never throws: a missing artifact is an empty state, not an error.
async function loadHostExtras(hostId) {
  if (window.__VORYNEX_DEMO__) {
    state.policy = window.__VORYNEX_DEMO__.policy || null;
    state.sbom = window.__VORYNEX_DEMO__.sbom || null;
    state.policyHost = hostId || null;
    renderPolicies();
    renderCves();
    return;
  }
  state.policyHost = hostId || null;
  state.policy = null;
  state.sbom = null;
  if (hostId) {
    const base = "/v1/hosts/" + encodeURIComponent(hostId);
    try {
      const [pol, sb] = await Promise.all([
        fetch(base + "/policy", { headers: authHeaders() }).catch(() => null),
        fetch(base + "/sbom", { headers: authHeaders() }).catch(() => null),
      ]);
      if (pol && pol.ok) state.policy = await pol.json();
      if (sb && sb.ok) state.sbom = await sb.json();
    } catch (_) {
      state.policy = null;
      state.sbom = null;
    }
  }
  renderPolicies();
  renderCves();
}

function showLogin(msg) {
  state.needsAuth = true;
  $("#login").hidden = false;
  $(".stats").hidden = true;
  $("#workloads").hidden = true;
  $("#detail").hidden = true;
  $("#events").hidden = true;
  $("#blast").hidden = true;
  $("#policies").hidden = true;
  $("#cves").hidden = true;
  $("#signout").hidden = !state.token;
  if (msg) {
    const e = $("#login-error");
    e.textContent = msg;
    e.hidden = false;
  }
  $("#token-input").focus();
}

function hideLogin() {
  state.needsAuth = false;
  $("#login").hidden = true;
  $(".stats").hidden = false;
  $("#workloads").hidden = false;
  $("#events").hidden = false;
  $("#blast").hidden = false;
  $("#policies").hidden = false;
  $("#cves").hidden = false;
  $("#signout").hidden = !state.token || !!window.__VORYNEX_DEMO__;
}

function render() {
  const contained = state.events.filter(isContained).length;
  const host = selectedHostObj();

  $("#stat-workloads").textContent = String(state.hosts.length);
  $("#stat-events").textContent = String(state.events.filter((e) => !(e.record && e.record.gap)).length);
  $("#stat-contained").textContent = String(contained);
  $("#stat-mode").textContent = host ? host.mode : state.hosts.length ? "mixed" : "—";
  $("#nav-events-count").textContent = String(state.events.length);
  $("#rail-host").textContent = host
    ? host.hostname || host.host_id
    : state.hosts.length
      ? state.hosts.length + " hosts"
      : "no hosts";
  $("#subline").textContent = state.hosts.length
    ? `${state.hosts.length} host${state.hosts.length === 1 ? "" : "s"} · ${state.events.length} events · Tier 0 spawn-time containment`
    : "No hosts enrolled yet";
  $("#wl-hint").textContent = host ? `Filtered to ${host.hostname || host.host_id}` : "";
  $("#clear-filter").hidden = !host;

  renderWorkloads();
  renderDetail();
  renderBlast();
  renderPolicies();
  renderCves();
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
        el("p", { text: "Enroll a host and export telemetry. The dashboard reads from the local control plane." }),
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

    const nameBtn = el(
      "button",
      {
        class: "row-btn",
        type: "button",
        "aria-pressed": String(state.selectedHost === h.host_id),
        title: "Open this workload",
      },
      [
        el("span", { class: "mono", text: h.hostname || h.host_id }),
        h.hostname ? el("span", { class: "wl-id muted mono", text: h.host_id }) : null,
      ]
    );
    nameBtn.addEventListener("click", () => {
      state.selectedHost = state.selectedHost === h.host_id ? null : h.host_id;
      loadHostExtras(state.selectedHost || (state.hosts[0] && state.hosts[0].host_id) || null);
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
    const b = el("button", { type: "button", "aria-pressed": String(host.mode === m), text: m });
    if (state.busy) b.disabled = true;
    b.addEventListener("click", () => setMode(host, m));
    group.append(b);
  }
  return group;
}

async function setMode(host, mode) {
  if (state.busy || host.mode === mode) return;
  if (window.__VORYNEX_DEMO__) {
    host.mode = mode;
    setStatus("ok", "Mode saved (preview)");
    render();
    return;
  }
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

function renderDetail() {
  const host = selectedHostObj();
  const panel = $("#detail");
  if (!host) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  $("#detail-title").textContent = host.hostname || host.host_id;
  $("#detail-sub").textContent = host.host_id;

  const s = hostStats(host.host_id);
  const body = $("#detail-body");
  body.textContent = "";

  const grid = el("div", { class: "detail-grid" });
  grid.append(detailStat("Protection mode", modeControl(host)));
  grid.append(detailStat("Events", el("span", { class: "detail-v num", text: String(s.events) })));
  grid.append(detailStat("Contained", el("span", { class: "detail-v num detail-ok", text: String(s.contained) })));
  grid.append(detailStat("Last event", el("span", { class: "detail-v", text: s.last ? ago(s.last) : "—" })));

  const recent = state.events.filter((e) => e.host_id === host.host_id && isContained(e)).slice(0, 4);
  if (recent.length) {
    grid.append(
      el("div", { class: "detail-recent" }, [
        el("span", { class: "detail-k", text: "Contained recently" }),
        el("ul", { class: "detail-list" }, recent.map((e) => {
          const ev = eventOf(e);
          return el("li", {}, [
            el("span", { class: "mono", text: (ev.action || "access") + " " + (ev.resource || "") }),
            el("span", { class: "muted", text: ev.reason || "" }),
          ]);
        })),
      ])
    );
  }
  body.append(grid);
  body.append(
    el("div", { class: "detail-foot" }, [
      el("span", { class: "muted", text: "Mode applies on the next agent sync." }),
      (() => {
        const b = el("button", { class: "btn btn-quiet", type: "button", text: "Clear selection" });
        b.addEventListener("click", () => { state.selectedHost = null; render(); });
        return b;
      })(),
    ])
  );
}

function detailStat(label, node) {
  return el("div", { class: "detail-stat" }, [
    el("span", { class: "detail-k", text: label }),
    node,
  ]);
}

function isWriteAction(a) {
  return ["creat", "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "chmod", "fchmodat", "chown", "fchownat"].includes(a);
}

function isSecretPath(base, p) {
  if ([".env", "id_rsa", "id_ed25519", "credentials", ".npmrc", ".pypirc", ".dockercfg", ".netrc", ".pgpass", ".htpasswd"].includes(base)) return true;
  if (base.startsWith(".env.")) return true;
  if ([".pem", ".key", ".p12", ".pfx"].some((s) => base.endsWith(s))) return true;
  return ["/.ssh/", "/.aws/", "/.kube/", "/.docker/", "/.gnupg/"].some((f) => p.includes(f));
}

function behaviorOf(ev) {
  const action = String(ev.action || "");
  const resource = String(ev.resource || "");
  const base = resource.split("/").pop();
  if (action === "execve" || action === "execveat") {
    const shells = ["sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "ash", "busybox"];
    return shells.includes(base) ? "shell execution" : "unexpected process execution";
  }
  if (ev.type === "network") {
    const host = resource.replace(/:\d+$/, "");
    if (host === "169.254.169.254" || host === "169.254.170.2") return "cloud metadata access";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return "arbitrary egress";
    return "network access";
  }
  if (isSecretPath(base, resource)) return "credential access";
  return isWriteAction(action) ? "filesystem write" : "filesystem access";
}

function policyOf(ev) {
  const action = String(ev.action || "");
  if (action === "execve" || action === "execveat") return "process.exec";
  if (ev.type === "network") return "network.connect";
  if (isWriteAction(action)) return "filesystem.write";
  return "filesystem.read";
}

function nextActionsFor(behavior) {
  switch (behavior) {
    case "shell execution":
      return ["Review the request that reached this workload", "Fix the command-injection sink", "Keep the rule"];
    case "credential access":
      return ["Rotate any credentials this workload can reach", "Move secrets to a secret manager", "Keep the rule"];
    case "cloud metadata access":
      return ["Require IMDSv2 with a hop limit where possible", "Keep the rule"];
    case "arbitrary egress":
      return ["Add the legitimate destination to network.allow", "Keep the rule"];
    default:
      return ["Review the access", "Keep the rule"];
  }
}

function traceField(k, v) {
  return el("div", { class: "trace-f" }, [el("dt", { text: k }), el("dd", { text: v })]);
}

function traceDetails(ev) {
  const behavior = behaviorOf(ev);
  const policy = policyOf(ev);
  return el("details", { class: "trace" }, [
    el("summary", {}, [
      el("span", { class: "trace-sum", text: "Trace · " + behavior }),
      el("span", { class: "trace-pol mono", text: policy }),
    ]),
    el("div", { class: "trace-body" }, [
      el("dl", { class: "trace-fields" }, [
        traceField("Result", "DENIED"),
        traceField("Policy", policy),
        traceField("Behavior", behavior),
        traceField("Confidence", "inferred"),
      ]),
      el("div", { class: "trace-next" }, [
        el("span", { class: "trace-k", text: "Next" }),
        el("ul", {}, nextActionsFor(behavior).map((a) => el("li", { text: a }))),
      ]),
    ]),
  ]);
}

function renderBlast() {
  if (state.policy && state.policy.blast_radius) {
    renderPolicyBlast(state.policy.blast_radius);
    return;
  }
  const host = selectedHostObj();
  const hostId = host ? host.host_id : null;
  const reach = new Map();
  const hold = new Map();

  for (const e of state.events) {
    if (hostId && e.host_id !== hostId) continue;
    const ev = eventOf(e);
    if (!ev || !ev.resource) continue;
    if (isContained(e)) {
      const b = behaviorOf(ev);
      hold.set(b, (hold.get(b) || 0) + 1);
      continue;
    }
    if (!ev.allowed) continue;
    if (ev.type === "network") reach.set("connect " + ev.resource, "network");
    else if (isWriteAction(ev.action)) reach.set("write " + ev.resource, "filesystem");
  }

  $("#blast-sub").textContent = host ? host.hostname || host.host_id : "all workloads · observed reach";
  const body = $("#blast-body");
  body.textContent = "";

  const grid = el("div", { class: "blast" });

  const reachCol = el("div", { class: "col reach" }, [el("h4", { text: "Reachable" })]);
  const reachItems = [...reach.entries()].slice(0, 10);
  if (reachItems.length === 0) {
    reachCol.append(el("p", { class: "muted", text: "No successful access observed" }));
  } else {
    reachCol.append(
      el("ul", {}, reachItems.map(([t, kind]) => el("li", {}, [el("span", { class: "ico", text: "!" }), t + "  ·  " + kind])))
    );
  }

  const holdCol = el("div", { class: "col hold" }, [el("h4", { text: "Contained" })]);
  const holdItems = [...hold.entries()];
  if (holdItems.length === 0) {
    holdCol.append(el("p", { class: "muted", text: "No containment events observed" }));
  } else {
    holdCol.append(
      el("ul", {}, holdItems.map(([b, n]) => el("li", {}, [el("span", { class: "ico", text: "✓" }), b + " (" + n + ")"])))
    );
  }

  grid.append(reachCol, holdCol);
  body.append(grid);
  body.append(
    el("div", { class: "blast-foot" }, [
      el("span", { class: "muted", text: "Observed reach from telemetry. The policy-based view arrives with policy upload." }),
    ])
  );
}

// renderPolicyBlast shows the blast radius derived from the uploaded policy:
// every line is a rule, never a score.
function renderPolicyBlast(report) {
  $("#blast-sub").textContent = (report.workload || "workload") + " · from the effective policy";
  const body = $("#blast-body");
  body.textContent = "";

  const grid = el("div", { class: "blast" });

  const reachCol = el("div", { class: "col reach" }, [el("h4", { text: "Reachable" })]);
  const reach = report.reachable || [];
  if (reach.length === 0) {
    reachCol.append(el("p", { class: "muted", text: "Nothing reachable within the policy" }));
  } else {
    reachCol.append(
      el("ul", {}, reach.slice(0, 12).map((r) => el("li", {}, [
        el("span", { class: "ico", text: "!" }),
        `${r.kind} ${r.target}${r.via ? "  ·  " + r.via : ""}`,
      ])))
    );
  }

  const holdCol = el("div", { class: "col hold" }, [el("h4", { text: "Contained" })]);
  const hold = report.contained || [];
  if (hold.length === 0) {
    holdCol.append(el("p", { class: "muted", text: "No danger classes are contained by this policy" }));
  } else {
    holdCol.append(
      el("ul", {}, hold.map((c) => el("li", {}, [
        el("span", { class: "ico", text: "✓" }),
        `${c.class}${c.reason ? "  ·  " + c.reason : ""}`,
      ])))
    );
  }

  grid.append(reachCol, holdCol);
  body.append(grid);
  body.append(
    el("div", { class: "blast-foot" }, [
      el("span", { class: "muted", text: "Derived from the policy this host uploaded. Enforcement stays local; the cloud is not in the request path." }),
    ])
  );
}

// renderPolicies shows the effective policy: the reviewable rule set and whether
// high-confidence secret protection is on.
function renderPolicies() {
  const body = $("#pol-body");
  const host = selectedHostObj();
  $("#pol-sub").textContent = host ? (host.hostname || host.host_id) : "no host selected";
  body.textContent = "";

  if (!state.policy) {
    body.append(
      el("div", { class: "empty" }, [
        el("h3", { text: "No policy uploaded" }),
        el("p", { text: "The agent uploads its effective policy with:" }),
        el("p", { class: "mono muted", text: "vorynex telemetry export --policy <file> --endpoint <url>" }),
      ])
    );
    return;
  }

  const s = state.policy.summary || {};
  body.append(
    el("div", { class: "pol-head" }, [
      el("span", { class: "badge", text: "schema v" + (s.version || "—") }),
      el("span", { class: "badge " + (s.protect_secrets ? "badge-contained" : ""), text: s.protect_secrets ? "secret protection on" : "secret protection off" }),
    ])
  );

  const groups = [
    ["Read (ro)", s.read],
    ["Write (rw)", s.write],
    ["Denied paths", s.deny],
    ["Exec allow", s.exec_allow],
    ["Exec deny", s.exec_deny],
    ["Network allow", s.network_allow],
  ];
  const grid = el("div", { class: "pol-grid" });
  for (const [label, items] of groups) {
    const col = el("div", { class: "pol-col" }, [el("h4", { text: label })]);
    if (!items || items.length === 0) {
      col.append(el("p", { class: "muted", text: "—" }));
    } else {
      col.append(el("ul", {}, items.slice(0, 12).map((x) => el("li", { text: x }))));
      if (items.length > 12) col.append(el("p", { class: "muted", text: `+${items.length - 12} more` }));
    }
    grid.append(col);
  }
  body.append(grid);
  body.append(
    el("p", { class: "muted pol-foot", text: "Deny always wins over allow. This policy was validated by the control plane before it was stored." })
  );
}

// renderCves shows the correlated SBOM a host uploaded: which dependency
// versions are affected, whether a fix exists, and whether it is known-exploited.
function renderCves() {
  const body = $("#cve-body");
  const host = selectedHostObj();
  $("#cve-sub").textContent = host ? (host.hostname || host.host_id) : "no host selected";
  body.textContent = "";

  const sbom = state.sbom && state.sbom.sbom;
  if (!sbom || !sbom.entries || sbom.entries.length === 0) {
    body.append(
      el("div", { class: "empty" }, [
        el("h3", { text: "No CVEs reported" }),
        el("p", { text: "The agent uploads a correlated SBOM with:" }),
        el("p", { class: "mono muted", text: "vorynex cve scan --lockfile package-lock.json --live --nvd --upload --endpoint <url>" }),
      ])
    );
    return;
  }

  const table = el("table", { class: "table" });
  table.append(
    el("thead", {}, [
      el("tr", {}, [
        el("th", { text: "Severity" }),
        el("th", { text: "Advisory" }),
        el("th", { text: "Package" }),
        el("th", { text: "Installed" }),
        el("th", { text: "Fixed" }),
        el("th", { text: "Exploited" }),
      ]),
    ])
  );
  const tbody = el("tbody");
  for (const e of sbom.entries) {
    const sev = e.cvss ? `${e.cvss.score.toFixed(1)} ${e.cvss.severity || ""}`.trim() : "—";
    const sevClass = e.cvss && (e.cvss.severity === "CRITICAL" || e.cvss.severity === "HIGH") ? "badge-contained" : "badge-allowed";
    tbody.append(
      el("tr", {}, [
        el("td", {}, [el("span", { class: "badge " + sevClass, text: sev })]),
        el("td", { class: "mono" }, [e.advisory_id + (e.aliases && e.aliases.length ? " (" + e.aliases.join(", ") + ")" : "")]),
        el("td", { class: "mono", text: e.name }),
        el("td", { class: "mono", text: e.version }),
        el("td", { class: "mono", text: e.fixed || "unknown" }),
        el("td", {}, [e.known_exploited ? el("span", { class: "badge badge-contained", text: "KEV" }) : el("span", { class: "muted", text: "no" })]),
      ])
    );
  }
  table.append(tbody);
  body.append(table);
  body.append(
    el("p", { class: "muted pol-foot", text: `${sbom.entries.length} affected package(s) across ${sbom.packages} dependencies. Scan: ${sbom.scanned_at || "—"}.` })
  );
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
    what.append(
      el("div", {}, [
        el("span", { class: "event-act", text: (ev.action || "access") + " " }),
        el("span", { class: "event-target", text: ev.resource || "(unknown)" }),
      ])
    );
    what.append(el("div", { class: "event-host", text: hostLabel(e.host_id) }));
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

    if (contained) li.append(traceDetails(ev));

    list.append(li);
  }
  body.append(list);
}

function renderError(err) {
  const body = $("#wl-body");
  body.textContent = "";
  body.append(
    el("div", { class: "error" }, [
      el("h3", { text: "Cannot reach the control plane" }),
      el("p", { text: "The dashboard could not load hosts or events. Check that vorynex-cloud is running, then retry." }),
      (() => {
        const b = el("button", { class: "btn", type: "button", text: "Retry" });
        b.addEventListener("click", () => load());
        return b;
      })(),
    ])
  );
  $("#ev-body").textContent = "";
  $("#ev-body").append(el("div", { class: "empty" }, [el("p", { text: "Event timeline unavailable while disconnected." })]));
}

function startLive() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    if (document.hidden || state.paused || state.needsAuth) return;
    load({ silent: true });
  }, POLL_MS);
}

// ---- wiring ----
$("#refresh").addEventListener("click", () => load());
$("#only-contained").addEventListener("change", (e) => {
  state.onlyContained = e.target.checked;
  renderEvents();
});
$("#clear-filter").addEventListener("click", () => {
  state.selectedHost = null;
  loadHostExtras(state.hosts[0] && state.hosts[0].host_id);
  render();
});
$("#live").addEventListener("click", () => {
  state.paused = !state.paused;
  $("#live").textContent = state.paused ? "Paused" : "Live";
  $("#live").setAttribute("aria-pressed", String(!state.paused));
  if (!state.paused) load({ silent: true });
});
$("#login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const value = $("#token-input").value.trim();
  state.token = value;
  if (value) sessionStorage.setItem("vorynex-token", value);
  else sessionStorage.removeItem("vorynex-token");
  $("#login-error").hidden = true;
  await load();
  if (state.needsAuth) {
    const e = $("#login-error");
    e.textContent = "That token was rejected.";
    e.hidden = false;
  }
});
$("#signout").addEventListener("click", () => {
  state.token = "";
  sessionStorage.removeItem("vorynex-token");
  state.hosts = [];
  state.events = [];
  state.selectedHost = null;
  showLogin("Signed out. Enter a token to reconnect.");
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && !state.paused && !state.needsAuth) load({ silent: true });
});

load();
startLive();
