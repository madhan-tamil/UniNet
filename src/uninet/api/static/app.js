"use strict";
const $ = (s) => document.querySelector(s);
const SVGNS = "http://www.w3.org/2000/svg";
const SEV = ["critical", "high", "medium", "low"];
const SEV_COLOR = { critical: "#ff3b3b", high: "#ff9500", medium: "#ffcc00", low: "#34c759" };
const NODE_COLOR = { host: "#4f8dff", burst: "#ffcc00", domain: "#ffb77a", alert: "#ff3b3b" };
const VIEW_TITLE = { overview: "Overview", alerts: "Alerts", hosts: "Clients" };

const state = {
  view: "overview",          // "overview" | "alerts" | "hosts"
  filter: {},                // { severity?, threat?, host? }
  alerts: [],
  hosts: [],
  activeAlert: null,
  prevAlertIds: new Set(),   // for the "fresh alert" flash
  lastUpdate: 0,             // ms epoch of the last successful tick
  version: -1,               // detection version from /api/stats
};

async function j(url, opts) {
  const r = await fetch(url, opts);
  if (r.status === 401) { window.location = "/login"; throw new Error("unauth"); }
  return r.json();
}

/* ---------------- header / config ---------------- */
async function loadConfig() {
  try {
    const c = await j("/api/config");
    const link = $("#port-link");
    link.textContent = `:${c.port}`;
    link.href = c.base_url + "/";
    link.title = `dashboard @ ${c.base_url}  ·  bind ${c.bind_host}  ·  bus ${c.bus}  ·  window ${c.window_seconds}s`;
    const dot = $("#live-dot");
    if (dot) dot.title = c.live
      ? `live mode — detections refresh every few seconds`
      : `real-time stream connected (static detection set)`;
  } catch (_) {}
}

/* ---------------- stats (clickable filters) ---------------- */
async function loadStats() {
  const s = await j("/api/stats");
  $("#s-flows").textContent = s.flows.toLocaleString();
  $("#s-windows").textContent = s.windows;
  $("#s-hosts").textContent = s.hosts;
  $("#s-graph").textContent = `${s.graph.nodes} / ${s.graph.edges}`;
  $("#s-alerts").textContent = s.alerts;

  const mini = $("#s-sevmini");
  mini.innerHTML = "";
  SEV.forEach((k) => {
    const n = s.by_severity[k] || 0;
    if (!n) return;
    const bar = document.createElement("span");
    bar.style.background = SEV_COLOR[k];
    bar.style.flex = String(n);
    bar.title = `filter: ${n} ${k}`;
    bar.onclick = (e) => { e.stopPropagation(); toggleFilter("severity", k); };
    mini.appendChild(bar);
  });

  const chips = $("#s-threats");
  chips.innerHTML = "";
  Object.entries(s.by_threat || {}).sort((a, b) => b[1] - a[1]).forEach(([k, v]) => {
    const c = document.createElement("span");
    c.className = "chip" + (state.filter.threat === k ? " on" : "");
    c.textContent = `${k} · ${v}`;
    c.onclick = () => toggleFilter("threat", k);
    chips.appendChild(c);
  });

  if (typeof s.version === "number") state.version = s.version;
  return s;
}

/* ---------------- "updated Ns ago" ticker ---------------- */
function paintRefreshed() {
  const el = $("#refreshed");
  if (!el || !state.lastUpdate) return;
  const secs = Math.round((Date.now() - state.lastUpdate) / 1000);
  el.textContent = secs < 2 ? "updated just now"
    : secs < 60 ? `updated ${secs}s ago`
    : `updated ${Math.round(secs / 60)}m ago`;
}

function toggleFilter(key, val) {
  state.filter[key] = state.filter[key] === val ? undefined : val;
  if (key === "severity" || key === "threat") setView("alerts");
  render();
}
function clearFilter() { state.filter = {}; render(); }

/* ---------------- view switching ---------------- */
function setView(v) {
  state.view = v;
  const listMode = v === "hosts" ? "hosts" : "alerts";   // overview shares the alerts list
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === v));
  $("#alert-list").hidden = listMode !== "alerts";
  $("#host-list").hidden = listMode !== "hosts";
  const vt = $("#view-title"); if (vt) vt.textContent = VIEW_TITLE[v] || "Overview";
  const lt = $("#list-title"); if (lt) lt.textContent = listMode === "hosts" ? "Clients" : "Alerts";
  render();
}

/* ---------------- render ---------------- */
function render() {
  const f = state.filter;
  const active = Object.entries(f).filter(([, v]) => v);
  $("#filterbar").hidden = active.length === 0;
  $("#filter-label").textContent = "filter — " + active.map(([k, v]) => `${k}: ${v}`).join(" · ");

  if (state.view === "hosts") renderHosts();
  else renderAlerts();
}

function renderAlerts() {
  const f = state.filter;
  const rows = state.alerts.filter((a) =>
    (!f.severity || a.severity === f.severity) &&
    (!f.threat || a.threat_type === f.threat) &&
    (!f.host || a.src_host === f.host));
  $("#list-count").textContent = `${rows.length} / ${state.alerts.length} alerts`;

  const seen = state.prevAlertIds;
  const canFlash = seen.size > 0;

  const list = $("#alert-list");
  list.innerHTML = rows.length ? "" : `<div class="muted pad">No alerts match the filter.</div>`;
  rows.forEach((a) => {
    const sc = a.scores || {};
    const card = document.createElement("div");
    const fresh = canFlash && !seen.has(a.alert_id);
    card.className = "alert-card"
      + (a.alert_id === state.activeAlert ? " active" : "")
      + (fresh ? " fresh" : "");
    card.innerHTML = `
      <div class="stripe ${a.severity}"></div>
      <div class="alert-main">
        <div class="row1">
          <span class="badge sev-${a.severity}">${a.severity}</span>
          <span class="badge">${a.threat_type}</span>
          <span class="host">${a.src_host}</span>
        </div>
        <div class="ev">${a.evidence && a.evidence[0] ? a.evidence[0].detail : ""}</div>
      </div>
      <div class="alert-right">
        <span class="conf" style="color:${SEV_COLOR[a.severity]}">${a.confidence.toFixed(2)}</span>
        <span class="subscores">R ${(sc.rule ?? 0).toFixed(2)} · A ${(sc.anomaly ?? 0).toFixed(2)} · G ${(sc.graph ?? 0).toFixed(2)}</span>
      </div>`;
    card.onclick = () => selectAlert(a);
    list.appendChild(card);
  });

  state.prevAlertIds = new Set(state.alerts.map((a) => a.alert_id));

  if (!state.activeAlert && rows[0]) selectAlert(rows[0]);
}

function renderHosts() {
  const f = state.filter;
  const rows = state.hosts.filter((h) => !f.host || h.ip === f.host);
  $("#list-count").textContent = `${rows.length} clients`;

  const list = $("#host-list");
  list.innerHTML = "";
  rows.forEach((h) => {
    const al = h.alert;
    const sev = al ? al.severity : "none";
    const card = document.createElement("div");
    card.className = "alert-card" + (state.filter.host === h.ip ? " active" : "");
    const ports = h.dst_ports.slice(0, 8).join(", ") || "—";
    card.innerHTML = `
      <div class="stripe ${sev}"></div>
      <div class="alert-main">
        <div class="row1">
          <span class="host">${h.ip}</span>
          ${al ? `<span class="badge sev-${al.severity}">${al.threat}</span>`
               : `<span class="badge ok">clean</span>`}
        </div>
        <div class="meta">${h.flows} flows · ${h.bursts} bursts · ${h.peer_count} peers · ports ${ports}</div>
        <div class="fp">fp ${h.fingerprint} · periodicity ${h.periodicity}</div>
      </div>
      <div class="alert-right">
        <span class="conf" style="color:${al ? SEV_COLOR[al.severity] : "var(--muted)"}">${al ? al.confidence.toFixed(2) : ""}</span>
        <span class="subscores">${(h.bytes / 1e6).toFixed(1)} MB</span>
      </div>`;
    card.onclick = () => selectHost(h);
    list.appendChild(card);
  });
}

/* ---------------- selection ---------------- */
async function selectAlert(a) {
  state.activeAlert = a.alert_id;
  if (state.view !== "hosts") renderAlerts();

  $("#detail-empty").hidden = true;
  $("#detail").hidden = false;
  $("#host-meta").hidden = true;
  $("#ev-head").hidden = false;
  $("#detail-host").textContent = a.src_host;

  const ex = await j(`/api/explain/${a.alert_id}`);
  $("#verdict").innerHTML = `<b>${ex.threat_type}</b> · confidence ${ex.confidence.toFixed(2)}`;
  const ff = ex.fused_from || {};
  $("#score-bars").innerHTML = ["rule", "anomaly", "graph"].map((k) => {
    const v = ff[k] ?? 0;
    return `<div class="sb"><span>${k}</span>
      <span class="track"><span class="fill" style="width:${Math.round(v * 100)}%"></span></span>
      <span>${v.toFixed(2)}</span></div>`;
  }).join("");
  $("#evidence").innerHTML = (ex.evidence || []).map((e) => `
    <div class="ev-card">
      <div class="ev-kind ${e.kind}">${e.kind} · ${e.name} · ${(e.score ?? 0).toFixed(2)}</div>
      <div class="ev-detail">${e.detail}</div>
    </div>`).join("");

  drawGraph(await j(`/api/graph?host=${encodeURIComponent(a.src_host)}`));
}

async function selectHost(h) {
  state.filter.host = h.ip;
  state.activeAlert = null;
  render();

  $("#detail-empty").hidden = true;
  $("#detail").hidden = false;
  $("#detail-host").textContent = h.ip;

  if (h.alert) {
    const a = state.alerts.find((x) => x.alert_id === h.alert.alert_id);
    if (a) { await selectAlert(a); return; }
  }

  $("#verdict").innerHTML = `<b>${h.ip}</b> · no alert — baseline client`;
  $("#score-bars").innerHTML = "";
  $("#ev-head").hidden = true;
  $("#evidence").innerHTML = "";
  $("#host-meta").hidden = false;
  $("#host-meta").innerHTML = [
    ["flows", h.flows], ["bytes", (h.bytes / 1e6).toFixed(1) + " MB"], ["bursts", h.bursts],
    ["peers", h.peer_count], ["dst ports", h.dst_ports.join(", ") || "—"],
    ["domains", h.domains.slice(0, 6).join(", ") || "—"],
    ["periodicity", h.periodicity], ["fingerprint", h.fingerprint],
  ].map(([k, v]) => `<div class="kv"><b>${k}</b><span>${v}</span></div>`).join("");

  drawGraph(await j(`/api/graph?host=${encodeURIComponent(h.ip)}`));
}

/* ---------------- TB-graph (force layout + IP labels) ---------------- */
function drawGraph(view) {
  const svg = $("#graph");
  svg.innerHTML = "";
  const W = 540, H = 400;
  const nodes = view.nodes.slice(0, 80);
  const id2n = new Map(nodes.map((n) => [n.id, n]));
  const edges = view.edges.filter((e) => id2n.has(e.src) && id2n.has(e.dst));

  nodes.forEach((n, i) => {
    n.x = W / 2 + Math.cos(i) * (40 + i * 4);
    n.y = H / 2 + Math.sin(i) * (30 + i * 3);
    n.fx = n.type === "host" ? W / 2 : null;
    n.fy = n.type === "host" ? H / 2 : null;
  });
  for (let it = 0; it < 240; it++) {
    for (let a = 0; a < nodes.length; a++) {
      for (let b = a + 1; b < nodes.length; b++) {
        const p = nodes[a], q = nodes[b];
        let dx = p.x - q.x, dy = p.y - q.y;
        const f = 1500 / (dx * dx + dy * dy || 1);
        dx *= f; dy *= f;
        if (p.fx == null) { p.x += dx; p.y += dy; }
        if (q.fx == null) { q.x -= dx; q.y -= dy; }
      }
    }
    edges.forEach((e) => {
      const p = id2n.get(e.src), q = id2n.get(e.dst);
      let dx = q.x - p.x, dy = q.y - p.y;
      const d = Math.hypot(dx, dy) || 1;
      const k = (d - 74) * 0.02;
      dx = (dx / d) * k; dy = (dy / d) * k;
      if (p.fx == null) { p.x += dx; p.y += dy; }
      if (q.fx == null) { q.x -= dx; q.y -= dy; }
    });
    nodes.forEach((n) => {
      if (n.fx != null) { n.x = n.fx; n.y = n.fy; return; }
      n.x = Math.max(40, Math.min(W - 40, n.x));
      n.y = Math.max(18, Math.min(H - 18, n.y));
    });
  }

  const ecol = (r) => r === "periodic" ? "#ff9f45" : r === "direction_change" ? "#ff4d6d" : "#5b6b93";
  edges.forEach((e) => {
    const p = id2n.get(e.src), q = id2n.get(e.dst);
    const ln = document.createElementNS(SVGNS, "line");
    ln.setAttribute("x1", p.x); ln.setAttribute("y1", p.y);
    ln.setAttribute("x2", q.x); ln.setAttribute("y2", q.y);
    ln.setAttribute("stroke", ecol(e.rel));
    ln.setAttribute("stroke-width", e.rel === "emits" ? 0.5 : 1.5);
    ln.setAttribute("stroke-opacity", e.rel === "emits" ? 0.3 : 0.85);
    svg.appendChild(ln);
  });

  nodes.forEach((n) => {
    const a = n.attrs || {};
    const c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("cx", n.x); c.setAttribute("cy", n.y);
    c.setAttribute("r", n.type === "host" ? 9 : n.type === "burst" ? 5 : 4);
    c.setAttribute("fill", NODE_COLOR[n.type] || "#889");
    c.setAttribute("stroke", "#0c142a"); c.setAttribute("stroke-width", "1.5");

    let tip = n.id;
    if (n.type === "host") tip = `host ${a.ip}`;
    else if (n.type === "domain") tip = `domain ${a.name}`;
    else if (n.type === "burst") {
      const ports = (a.dst_ports || []).join(",");
      tip = `burst → ${a.peer || "?"}` +
        `\ndir ${a.direction} · ${(a.flow_count | 0)} flows · ${fmtBytes(a.byte_count)}` +
        (ports ? `\nports ${ports}` : "") +
        (a.domains && a.domains.length ? `\n${a.domains.slice(0, 3).join(", ")}` : "") +
        (a.intra_periodicity ? `\nperiodicity ${(+a.intra_periodicity).toFixed(2)}` : "");
    }
    const t = document.createElementNS(SVGNS, "title");
    t.textContent = tip;
    c.appendChild(t);
    svg.appendChild(c);

    if (n.type === "host" || n.type === "domain") {
      const lbl = document.createElementNS(SVGNS, "text");
      lbl.setAttribute("x", n.x + 11);
      lbl.setAttribute("y", n.y + 3);
      lbl.setAttribute("class", n.type === "host" ? "host-lbl" : "");
      lbl.textContent = n.type === "host" ? (a.ip || "") : (a.name || "");
      svg.appendChild(lbl);
    }
  });
}
const fmtBytes = (b) => {
  b = +b || 0;
  if (b > 1e6) return (b / 1e6).toFixed(1) + " MB";
  if (b > 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
};

/* ---------------- refresh loop ---------------- */
let _ticking = false;
async function tick() {
  if (_ticking) return;
  _ticking = true;
  try {
    const [, alerts, hosts] = await Promise.all([loadStats(), j("/api/alerts"), j("/api/hosts")]);
    state.alerts = alerts;
    state.hosts = hosts;
    state.lastUpdate = Date.now();
    render();
    paintRefreshed();
  } catch (_) {} finally { _ticking = false; }
}

/* debounce bursts of stream events into one refresh */
let _tickTimer = null;
function scheduleTick() {
  clearTimeout(_tickTimer);
  _tickTimer = setTimeout(tick, 250);
}

/* ---------------- real-time stream (SSE) ---------------- */
function connectStream() {
  const dot = $("#live-dot");
  let es;
  try { es = new EventSource("/api/stream"); }
  catch (_) { return; }

  es.onopen = () => { if (dot) { dot.className = "live-dot on"; dot.hidden = false; } };
  es.onmessage = (e) => {
    let v = null;
    try { v = JSON.parse(e.data).version; } catch (_) {}
    if (v == null || v !== state.version) scheduleTick();
  };
  es.onerror = () => { if (dot) dot.className = "live-dot stale"; };  // EventSource auto-reconnects
}

document.querySelectorAll(".tab").forEach((t) => t.onclick = () => setView(t.dataset.view));
document.querySelectorAll("[data-goto]").forEach((el) => el.onclick = () => setView(el.dataset.goto));
document.querySelectorAll("[data-filter-clear]").forEach((el) => el.onclick = clearFilter);
$("#filter-clear").onclick = clearFilter;

setView("overview");
loadConfig();
tick();
connectStream();
setInterval(tick, 20000);          // fallback poll if the stream is down
setInterval(paintRefreshed, 1000); // "updated Ns ago" ticker
