"use strict";
/* UniNet — "Obsidian Protocol" · 3 screens (Workspace · Graph Explorer · AI Intelligence)
   Wired to the passive read-only API:
     /api/stats  /api/alerts  /api/hosts  /api/explain/<id>  /api/graph  /api/stream  /api/ask
*/
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const SVGNS = "http://www.w3.org/2000/svg";

const SEV_COLOR = { critical: "#ffb4ab", high: "#ffe173", medium: "#00dbe7", low: "#849495" };
const NODE_COLOR = { host: "#00f2ff", burst: "#ffe173", domain: "#c3a3ff", alert: "#ffb4ab" };

const state = {
  screen: "workspace",
  queueMode: "alerts",        // "alerts" | "hosts"
  filter: {},
  alerts: [], hosts: [],
  activeAlert: null, activeHost: null,
  activeAlertObj: null,
  graphView: null,            // last /api/graph payload for the active target
  prevAlertIds: new Set(),
  lastUpdate: 0, version: -1,
  playing: false,
  chat: [], chatSeeded: false,
};

async function j(url, opts) {
  const r = await fetch(url, opts);
  if (r.status === 401) { window.location = "/login"; throw new Error("unauth"); }
  return r.json();
}
const fmtTime = (e) => new Date(e * 1000).toLocaleTimeString([], { hour12: false });
const fmtBytes = (b) => { b = +b || 0; return b > 1e6 ? (b / 1e6).toFixed(1) + " MB" : b > 1e3 ? (b / 1e3).toFixed(1) + " KB" : b + " B"; };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/* ================= screen switching ================= */
function setScreen(name) {
  state.screen = name;
  $$("#rail .nav-icon[data-screen]").forEach((b) => b.classList.toggle("is-active", b.dataset.screen === name));
  $$(".screen").forEach((s) => s.classList.toggle("hidden", s.id !== "screen-" + name));
  if (name === "graph") enterGraphScreen();
  if (name === "ai") enterAIScreen();
}

/* ================= config / loop ================= */
async function loadConfig() {
  try {
    const c = await j("/api/config");
    const d = $("#live-dot");
    if (d) d.title = c.live ? "live mode — detections refresh every few seconds" : "real-time stream connected";
  } catch (_) {}
}
let _ticking = false;
async function tick() {
  if (_ticking) return;
  _ticking = true;
  try {
    const [stats, alerts, hosts] = await Promise.all([j("/api/stats"), j("/api/alerts"), j("/api/hosts")]);
    if (typeof stats.version === "number") state.version = stats.version;
    state.alerts = alerts; state.hosts = hosts;
    state.lastUpdate = Date.now();
    paintStats(stats);
    render();
    paintRefreshed();
  } catch (_) {} finally { _ticking = false; }
}
let _tt = null;
function scheduleTick() { clearTimeout(_tt); _tt = setTimeout(tick, 250); }
function paintStats(s) {
  const g = s.graph || {};
  const gs = $("#graph-sub");
  if (gs) gs.textContent = `VIEW: LOGICAL TOPOLOGY | ACTIVE NODES: ${g.nodes ?? 0} | FLOWS: ${(s.flows ?? 0).toLocaleString()}`;
  const ha = $("#hdr-alerts"); if (ha) ha.textContent = s.alerts ?? "—";
}
function paintRefreshed() {
  const el = $("#refreshed");
  if (!el || !state.lastUpdate) return;
  const s = Math.round((Date.now() - state.lastUpdate) / 1000);
  el.textContent = s < 2 ? "LIVE" : s < 60 ? `${s}s AGO` : `${Math.round(s / 60)}m AGO`;
}

/* ================= filters ================= */
function clearFilter() {
  state.filter = {};
  const s = $("#search"); if (s) s.value = "";
  $("#search-clear").classList.add("hidden");
  render();
}
const matchQ = (txt) => { const q = state.filter.q; return !q || String(txt).toLowerCase().includes(q); };

/* ================= workspace render ================= */
function render() {
  const active = Object.entries(state.filter).filter(([, v]) => v);
  const fb = $("#filterbar");
  fb.classList.toggle("hidden", active.length === 0);
  fb.classList.toggle("flex", active.length > 0);
  $("#filter-label").textContent = active.map(([k, v]) => `${k}=${v}`).join("  ·  ");

  const hosts = state.queueMode === "hosts";
  $("#alert-list").classList.toggle("hidden", hosts);
  $("#host-list").classList.toggle("hidden", !hosts);
  $("#queue-title").textContent = hosts ? "HOST REGISTRY" : "ALERT QUEUE";
  if (hosts) renderHosts(); else renderAlerts();
  renderTimeline();
}

function renderAlerts() {
  const f = state.filter;
  const rows = state.alerts.filter((a) =>
    (!f.severity || a.severity === f.severity) &&
    (!f.host || a.src_host === f.host) &&
    matchQ(`${a.threat_type} ${a.src_host} ${a.severity}`));
  $("#list-count").textContent = `${rows.length}/${state.alerts.length}`;
  const seen = state.prevAlertIds, canFlash = seen.size > 0;
  let fresh = 0;
  const list = $("#alert-list");
  list.innerHTML = rows.length ? "" : `<div class="p-3 font-data-md text-[12px] text-outline">NO ALERTS MATCH FILTER</div>`;
  rows.forEach((a) => {
    const isFresh = canFlash && !seen.has(a.alert_id);
    if (isFresh) fresh++;
    const chip = a.severity === "critical" ? "crit" : a.severity === "high" ? "high" : "";
    const card = document.createElement("div");
    card.className = `q-card sev-${a.severity}` + (a.alert_id === state.activeAlert ? " active" : "") + (isFresh ? " fresh" : "");
    card.innerHTML = `
      <div class="flex justify-between items-start">
        <span class="q-title sev-${a.severity}">${esc((a.threat_type || "").toUpperCase().replace(/_/g, " "))}</span>
        <span class="q-time">${fmtTime(a.window_end || a.window_start || a.created_ts || Date.now() / 1000)}</span>
      </div>
      <div class="q-meta">HOST: ${esc(a.src_host)}</div>
      <div class="mt-2 flex gap-2 flex-wrap">
        <span class="q-chip ${chip}">${a.severity.toUpperCase()}</span>
        ${a.evidence && a.evidence[0] ? `<span class="q-chip">${esc(String(a.evidence[0].name).toUpperCase().slice(0, 14))}</span>` : ""}
        <span class="q-chip">CONF ${(a.confidence ?? 0).toFixed(2)}</span>
      </div>`;
    card.onclick = () => selectAlert(a);
    list.appendChild(card);
  });
  state.prevAlertIds = new Set(state.alerts.map((a) => a.alert_id));
  if (fresh) flashNewThreat();
  if (!state.activeAlert && !state.activeHost && rows[0]) selectAlert(rows[0]);
}

function renderHosts() {
  const rows = state.hosts.filter((h) => matchQ(`${h.ip} ${(h.alert && h.alert.threat) || ""}`));
  $("#list-count").textContent = `${rows.length}`;
  const list = $("#host-list");
  list.innerHTML = rows.length ? "" : `<div class="p-3 font-data-md text-[12px] text-outline">NO HOSTS</div>`;
  rows.forEach((h) => {
    const al = h.alert, sev = al ? al.severity : "low";
    const card = document.createElement("div");
    card.className = `q-card sev-${sev}` + (state.activeHost === h.ip ? " active" : "");
    card.innerHTML = `
      <div class="flex justify-between items-start"><span class="q-title">${esc(h.ip)}</span><span class="q-time">${h.flows} fl</span></div>
      <div class="q-meta">${h.bursts} bursts · ${h.peer_count} peers · ${(h.bytes / 1e6).toFixed(1)} MB</div>
      <div class="mt-2 flex gap-2 flex-wrap">
        ${al ? `<span class="q-chip ${al.severity === "critical" ? "crit" : al.severity === "high" ? "high" : ""}">${esc(al.threat.toUpperCase())}</span>` : `<span class="q-chip">CLEAN</span>`}
        <span class="q-chip">${esc(h.fingerprint || "—")}</span>
      </div>`;
    card.onclick = () => selectHost(h);
    list.appendChild(card);
  });
}

/* ================= selection ================= */
function wsShowDetail() {
  $("#ws-detail-empty").classList.add("hidden");
  const d = $("#ws-detail"); d.classList.remove("hidden"); d.classList.add("flex");
}
function renderWsDetail(a, evi) {
  wsShowDetail();
  $("#ws-target").textContent = `${a.src_host} · ${fmtTime(a.window_start || a.created_ts || Date.now() / 1000)}`;
  $("#ws-verdict").innerHTML =
    `<span style="color:${SEV_COLOR[a.severity] || "#dce4e4"}">${esc((a.threat_type || "").toUpperCase().replace(/_/g, " "))}</span>` +
    ` · CONF ${(a.confidence ?? 0).toFixed(2)} · ${(a.severity || "").toUpperCase()}`;
  $("#ws-summary").textContent = a.summary || "";
  $("#ws-evidence").innerHTML = (evi && evi.length)
    ? evi.map((e) => `<div class="ai-msg ${e.kind === "anomaly" ? "" : ""}"><div class="who">${esc(e.kind)} · ${esc(e.name)} · ${(e.score ?? 0).toFixed(2)}</div>${esc(e.detail)}</div>`).join("")
    : `<div class="font-data-md text-[12px] text-outline">no evidence</div>`;
}

async function selectAlert(a) {
  state.activeAlert = a.alert_id;
  state.activeAlertObj = a;
  state.activeHost = null;
  $("#investigation-id").textContent = "#" + String(a.alert_id).slice(0, 8).toUpperCase();
  $("#ai-alert").textContent = "#" + String(a.alert_id).slice(0, 8).toUpperCase();
  $("#ai-host").textContent = a.src_host;
  renderWsDetail(a, a.evidence || []);
  render();

  let ex;
  try { ex = await j(`/api/explain/${a.alert_id}`); } catch (_) { return; }
  renderScores(ex.fused_from || a.scores || {});
  $("#verdict").innerHTML =
    `<span class="text-primary-fixed-dim">${esc(ex.threat_type)}</span> · CONF ${(ex.confidence ?? 0).toFixed(2)}`;
  state.lastEvidence = ex.evidence || [];
  renderWsDetail(a, ex.evidence || []);

  try {
    state.graphView = await j(`/api/graph?host=${encodeURIComponent(a.src_host)}`);
    if (state.screen === "graph") drawGX(state.graphView);
  } catch (_) {}
  renderContext(ex.evidence || []);
  renderEvidenceRepo(ex.evidence || []);
}

async function selectHost(h) {
  state.activeHost = h.ip; state.activeAlert = null; state.activeAlertObj = null;
  $("#ai-host").textContent = h.ip;
  $("#ai-alert").textContent = h.alert ? "#" + String(h.alert.alert_id).slice(0, 8).toUpperCase() : "—";
  render();
  if (h.alert) {
    const a = state.alerts.find((x) => x.alert_id === h.alert.alert_id);
    if (a) return selectAlert(a);
  }
  $("#investigation-id").textContent = esc(h.ip);
  $("#score-bars").innerHTML = `<div class="font-data-md text-[12px] text-outline">NO ALERT — BASELINE CLIENT</div>`;
  $("#verdict").textContent = "";
  state.lastEvidence = [];
  wsShowDetail();
  $("#ws-target").textContent = `${h.ip} · baseline client`;
  $("#ws-verdict").innerHTML = `<span class="text-primary-fixed-dim">${esc(h.ip)}</span> · NO ALERT`;
  $("#ws-summary").textContent = `${h.flows} flows · ${h.bursts} bursts · ${h.peer_count} peers · ${(h.bytes / 1e6).toFixed(1)} MB · periodicity ${h.periodicity} · fp ${h.fingerprint}`;
  $("#ws-evidence").innerHTML = `<div class="font-data-md text-[12px] text-outline">baseline — no evidence · ports ${esc((h.dst_ports || []).slice(0, 12).join(", ") || "—")}</div>`;
  try {
    state.graphView = await j(`/api/graph?host=${encodeURIComponent(h.ip)}`);
    if (state.screen === "graph") drawGX(state.graphView);
  } catch (_) {}
}

function renderScores(ff) {
  const rows = [["rule", "Rule Signal"], ["anomaly", "Anomaly Signal"], ["graph", "TB-Graph Signal"]];
  $("#score-bars").innerHTML = rows.map(([k, label]) => {
    const v = Math.round((ff[k] ?? 0) * 100);
    return `<div class="score ${k}"><div class="row"><span class="text-on-surface">${label}</span><span class="val" style="background:transparent">${v}%</span></div><div class="track"><div class="fill" style="width:${v}%"></div></div></div>`;
  }).join("");
}
/* ================= attack storyline ================= */
function renderTimeline() {
  const track = $("#timeline-track");
  track.querySelectorAll(".tl-marker").forEach((n) => n.remove());
  const items = state.alerts.filter((a) => a.window_start);
  if (!items.length) { $("#timeline-range").textContent = "—"; $("#timeline-fill").style.width = "0%"; $("#timeline-legend").textContent = ""; return; }
  const t0 = Math.min(...items.map((a) => a.window_start));
  const t1 = Math.max(...items.map((a) => a.window_end || a.window_start));
  const span = (t1 - t0) || 1;
  items.forEach((a) => {
    const m = document.createElement("div");
    m.className = `tl-marker sev-${a.severity}` + (a.alert_id === state.activeAlert ? " active" : "");
    m.style.left = ((a.window_start - t0) / span) * 100 + "%";
    m.title = `${a.threat_type} · ${a.src_host} · ${fmtTime(a.window_start)}`;
    m.onclick = () => { const al = state.alerts.find((x) => x.alert_id === a.alert_id); if (al) selectAlert(al); };
    track.appendChild(m);
  });
  const act = state.alerts.find((a) => a.alert_id === state.activeAlert);
  $("#timeline-fill").style.width = Math.max(2, act ? ((act.window_start - t0) / span) * 100 : 100) + "%";
  $("#timeline-range").textContent = `${fmtTime(t0)} — ${fmtTime(t1)} UTC`;
  $("#timeline-legend").textContent = `${items.length} EVENTS`;
}
const storyItems = () => [...state.alerts].filter((a) => a.window_start).sort((a, b) => a.window_start - b.window_start);
function setPlayLabel(on) { $("#storyline-play-icon").textContent = on ? "stop" : "play_arrow"; $("#storyline-play-label").textContent = on ? "STOP" : "PLAY STORYLINE"; }
function stopStoryline() { state.playing = false; setPlayLabel(false); }
function playStoryline() {
  if (state.playing) return stopStoryline();
  const items = storyItems(); if (!items.length) return;
  state.playing = true; setPlayLabel(true);
  let i = 0;
  const step = () => { if (!state.playing || i >= items.length) return stopStoryline(); selectAlert(items[i++]); setTimeout(step, 1100); };
  step();
}
function storyStep(dir) {
  stopStoryline();
  const items = storyItems(); if (!items.length) return;
  let idx = items.findIndex((a) => a.alert_id === state.activeAlert);
  idx = idx < 0 ? (dir > 0 ? 0 : items.length - 1) : Math.min(items.length - 1, Math.max(0, idx + dir));
  selectAlert(items[idx]);
}

/* ================= new-threat badge ================= */
let _badge = null;
function flashNewThreat() { const b = $("#new-threat-badge"); b.classList.remove("hidden"); clearTimeout(_badge); _badge = setTimeout(() => b.classList.add("hidden"), 4500); }

/* ================= GRAPH EXPLORER — structured datapath layout ================= */
const GX_W = 1280, GX_H = 720;
const GX_TOP = 96, GX_BOT = 64, GX_COL_HOST = 96, GX_COL_BURST0 = 300;
const GX_MAX_BURSTS = 16;
const GX_SPINE = ["burst_in", "burst_out", "periodic", "direction_change"];
let gxZoom = 1, gxPanX = 0, gxPanY = 0;

function applyGX() {
  $("#gx-svg").setAttribute("viewBox", `${gxPanX} ${gxPanY} ${GX_W / gxZoom} ${GX_H / gxZoom}`);
}
function enterGraphScreen() {
  gxZoom = 1; gxPanX = 0; gxPanY = 0; applyGX();
  if (state.graphView) { drawGX(state.graphView); return; }
  // no selection yet — focus the busiest host so the datapath stays readable
  const host = (state.activeAlertObj && state.activeAlertObj.src_host)
    || (state.alerts[0] && state.alerts[0].src_host);
  const url = host ? `/api/graph?host=${encodeURIComponent(host)}` : "/api/graph";
  j(url).then((v) => { state.graphView = v; drawGX(v); }).catch(() => {});
}

/* Assign every node an (x,y) on a left→right datapath:
   host  ──emits──▶  ordered burst chain (t →)  ──resolves──▶  domain column   */
function datapathLayout(view) {
  const nodes = view.nodes || [], edges = view.edges || [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const hosts = nodes.filter((n) => n.type === "host");
  const bursts = nodes.filter((n) => n.type === "burst");
  const domains = nodes.filter((n) => n.type === "domain");
  const alerts = nodes.filter((n) => n.type === "alert");
  const colDom = GX_W - 150;

  // order bursts along their forward sequence edges
  const next = new Map();
  edges.forEach((e) => {
    if (byId.get(e.src)?.type === "burst" && byId.get(e.dst)?.type === "burst" && GX_SPINE.includes(e.rel) && !next.has(e.src))
      next.set(e.src, e.dst);
  });
  const indeg = new Map(bursts.map((b) => [b.id, 0]));
  next.forEach((d) => indeg.set(d, (indeg.get(d) || 0) + 1));
  const ordered = [], seen = new Set();
  bursts.filter((b) => (indeg.get(b.id) || 0) === 0).forEach((root) => {
    let cur = root.id;
    while (cur && !seen.has(cur)) { seen.add(cur); ordered.push(byId.get(cur)); cur = next.get(cur); }
  });
  bursts.forEach((b) => { if (!seen.has(b.id)) ordered.push(b); });

  // group into per-host lanes
  const hostKey = (h) => h.attrs?.ip || h.id;
  const laneKeys = hosts.length ? hosts.map(hostKey) : ["_"];
  const lanes = new Map(laneKeys.map((k) => [k, []]));
  ordered.forEach((b) => {
    const k = b.attrs?.host && lanes.has(b.attrs.host) ? b.attrs.host : laneKeys[0];
    lanes.get(k).push(b);
  });

  const place = new Map();
  const laneCount = Math.max(1, lanes.size);
  const laneH = (GX_H - GX_TOP - GX_BOT) / laneCount;
  const dense = laneCount > 3;
  let li = 0, shownBursts = 0, totalBursts = bursts.length;
  lanes.forEach((bs, key) => {
    const cy = GX_TOP + laneH * (li + 0.5); li++;
    const hNode = hosts.find((h) => hostKey(h) === key);
    if (hNode) place.set(hNode.id, { x: GX_COL_HOST, y: cy });
    const list = bs.slice(0, GX_MAX_BURSTS);
    shownBursts += list.length;
    const span = colDom - 120 - GX_COL_BURST0;
    list.forEach((b, i) => {
      const x = list.length === 1 ? GX_COL_BURST0 + span * 0.4 : GX_COL_BURST0 + span * (i / (list.length - 1));
      place.set(b.id, { x, y: cy });
    });
  });

  // domains: right column, y ≈ mean of the bursts that resolve to them, then de-overlap
  const rows = domains.map((d) => {
    const ys = edges.filter((e) => e.dst === d.id && e.rel === "resolves")
      .map((e) => place.get(e.src)?.y).filter((v) => v != null);
    return { d, y: ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : GX_H / 2 };
  }).sort((a, b) => a.y - b.y);
  const gap = 30;
  for (let i = 1; i < rows.length; i++) if (rows[i].y - rows[i - 1].y < gap) rows[i].y = rows[i - 1].y + gap;
  const overflow = rows.length ? rows[rows.length - 1].y - (GX_H - GX_BOT) : 0;
  rows.forEach((o) => place.set(o.d.id, { x: colDom, y: Math.max(GX_TOP, o.y - Math.max(0, overflow)) }));

  alerts.forEach((al) => {
    const on = edges.find((e) => e.src === al.id && e.rel === "raised_on");
    const p = on && place.get(on.dst);
    place.set(al.id, { x: p ? p.x : GX_COL_HOST, y: p ? p.y - 44 : GX_TOP });
  });

  nodes.forEach((n) => { const p = place.get(n.id); if (p) { n.x = p.x; n.y = p.y; } });
  return {
    nodes: nodes.filter((n) => place.has(n.id)),
    edges: edges.filter((e) => place.has(e.src) && place.has(e.dst)),
    shownBursts, totalBursts, dense,
  };
}

function gxEdgePath(x1, y1, x2, y2) {
  const mx = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
}
function styleGXEdge(p, rel) {
  if (rel === "periodic") { p.setAttribute("stroke", "url(#gx-flow)"); p.setAttribute("stroke-width", "2.5"); p.setAttribute("stroke-dasharray", "9 6"); p.setAttribute("class", "edge-anim"); }
  else if (rel === "direction_change") { p.setAttribute("stroke", "#ffb4ab"); p.setAttribute("stroke-width", "2"); p.setAttribute("stroke-dasharray", "5 4"); p.setAttribute("stroke-opacity", ".9"); }
  else if (rel === "burst_in" || rel === "burst_out") { p.setAttribute("stroke", "#00dbe7"); p.setAttribute("stroke-width", "2"); p.setAttribute("stroke-opacity", ".55"); }
  else if (rel === "resolves") { p.setAttribute("stroke", "#e8c423"); p.setAttribute("stroke-width", "1.4"); p.setAttribute("stroke-opacity", ".55"); }
  else if (rel === "emits") { p.setAttribute("stroke", "#849495"); p.setAttribute("stroke-width", "1"); p.setAttribute("stroke-opacity", ".28"); }
  else { p.setAttribute("stroke", "#3a494b"); p.setAttribute("stroke-width", "1.4"); p.setAttribute("stroke-opacity", ".7"); }
  p.setAttribute("fill", "none");
}
function gxText(x, y, str, cls, anchor) {
  const t = document.createElementNS(SVGNS, "text");
  t.setAttribute("x", x); t.setAttribute("y", y);
  t.setAttribute("text-anchor", anchor || "middle");
  t.setAttribute("class", cls || "gx-lbl");
  t.textContent = str;
  return t;
}
const clip = (s, n) => { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

function drawGX(view) {
  const svg = $("#gx-svg");
  [...svg.querySelectorAll(":scope > *:not(defs)")].forEach((n) => n.remove());
  const g = datapathLayout({ nodes: (view.nodes || []).map((n) => ({ ...n })), edges: view.edges || [] });
  const byId = new Map(g.nodes.map((n) => [n.id, n]));

  // column guide headers
  [["HOST", GX_COL_HOST], ["TRAFFIC BURSTS   ( t → )", (GX_COL_BURST0 + GX_W - 150) / 2], ["RESOLVED DOMAINS", GX_W - 150]]
    .forEach(([label, x]) => svg.appendChild(gxText(x, 40, label, "gx-head")));
  if (g.totalBursts > g.shownBursts)
    svg.appendChild(gxText((GX_COL_BURST0 + GX_W - 150) / 2, 60, `showing ${g.shownBursts} of ${g.totalBursts} bursts`, "gx-note"));

  // edges (behind nodes)
  g.edges.forEach((e) => {
    const p = byId.get(e.src), q = byId.get(e.dst); if (!p || !q) return;
    const path = document.createElementNS(SVGNS, "path");
    path.setAttribute("d", gxEdgePath(p.x, p.y, q.x, q.y));
    styleGXEdge(path, e.rel);
    svg.appendChild(path);
  });

  // nodes
  g.nodes.forEach((n) => {
    const a = n.attrs || {};
    const grp = document.createElementNS(SVGNS, "g");
    grp.setAttribute("transform", `translate(${n.x} ${n.y})`);
    grp.style.cursor = "pointer";

    if (n.type === "burst") {
      const halo = document.createElementNS(SVGNS, "circle");
      halo.setAttribute("r", "15"); halo.setAttribute("fill", "none");
      halo.setAttribute("stroke", "#ffb4ab"); halo.setAttribute("stroke-width", "1.5");
      halo.setAttribute("class", "node-ping");
      grp.appendChild(halo);
    }
    const c = document.createElementNS(SVGNS, "circle");
    const r = n.type === "host" ? 16 : n.type === "burst" ? 9 : n.type === "alert" ? 7 : 8;
    c.setAttribute("r", r);
    c.setAttribute("fill", n.type === "alert" ? "#ffb4ab" : NODE_COLOR[n.type] || "#889");
    c.setAttribute("filter", n.type === "burst" || n.type === "alert" ? "url(#gx-glow-burst)" : "url(#gx-glow)");
    if (n.type === "host") { c.setAttribute("fill", "#0d1515"); c.setAttribute("stroke", "#00f2ff"); c.setAttribute("stroke-width", "2.5"); }
    grp.appendChild(c);

    if (n.type === "host") {
      grp.appendChild(gxText(0, r + 18, clip(a.ip || "HOST", 22), "gx-lbl gx-host"));
      if (!g.dense) grp.appendChild(gxText(0, r + 32, "monitored endpoint", "gx-sub"));
    } else if (n.type === "domain") {
      grp.appendChild(gxText(0, -r - 8, clip(a.name || "domain", g.dense ? 18 : 26), "gx-lbl"));
    } else if (n.type === "burst") {
      if (!g.dense) {
        grp.appendChild(gxText(0, r + 16, clip(a.peer || "burst", 20), "gx-lbl"));
        grp.appendChild(gxText(0, r + 28, `${(a.flow_count | 0)} fl · ${fmtBytes(a.byte_count)}`, "gx-sub"));
      }
    } else if (n.type === "alert") {
      grp.appendChild(gxText(0, -r - 8, "ALERT", "gx-lbl gx-alert"));
    }

    grp.addEventListener("click", (ev) => { ev.stopPropagation(); showGXMeta(n); });
    svg.appendChild(grp);
  });
}
function showGXMeta(n) {
  const a = n.attrs || {};
  $("#gx-meta").classList.remove("translate-x-full");
  $("#gx-meta-empty").classList.add("hidden");
  const body = $("#gx-meta-body");
  body.classList.remove("hidden"); body.classList.add("flex");
  let title = n.id, addr = "—", metric = n.type.toUpperCase(), detail = "";
  if (n.type === "host") { title = a.ip || "HOST"; addr = a.ip || "—"; metric = "HOST NODE"; detail = "Local host / monitored endpoint. Central anchor of its TB-subgraph."; }
  else if (n.type === "domain") { title = a.name || "DOMAIN"; addr = a.name || "—"; metric = "DOMAIN"; detail = `Resolved domain observed in traffic bursts for this host.`; }
  else if (n.type === "burst") {
    title = "TRAFFIC BURST"; addr = a.peer || "—";
    metric = a.intra_periodicity != null ? `periodicity ${(+a.intra_periodicity).toFixed(2)}` : "BURST";
    detail = `direction ${a.direction || "?"} · ${(a.flow_count | 0)} flows · ${fmtBytes(a.byte_count)}\n` +
      `ports ${(a.dst_ports || []).join(", ") || "—"}\n` +
      ((a.domains && a.domains.length) ? `domains ${a.domains.slice(0, 5).join(", ")}` : "");
  }
  $("#gx-meta-title").textContent = title;
  $("#gx-meta-ip").textContent = addr;
  const sc = $("#gx-meta-score");
  sc.textContent = metric;
  sc.className = "font-data-md text-[14px] " + (n.type === "burst" ? "text-error" : "text-primary-fixed-dim");
  $("#gx-meta-history").textContent = detail || "—";
  $("#gx-meta").dataset.pivot = a.ip || a.peer || a.name || "";
}

/* ================= AI INTELLIGENCE screen ================= */
const SUGGESTED = [
  ["explore", "Analyze lateral movement risk", "Trace peer reachability from the target host"],
  ["history", "Correlate with prior detections", "Find alerts sharing this threat class"],
  ["hub", "Explain the TB-graph structure", "Summarise the burst subgraph around this host"],
];
function renderSuggestedPaths() {
  $("#suggested-paths").innerHTML = SUGGESTED.map(([ic, t, s]) => `
    <button class="path-btn w-full text-left bg-surface-container hover:bg-surface-container-highest p-3 rounded-lg border border-outline-variant/10 hover:border-primary-fixed-dim/30 transition-all group flex items-start gap-3" data-q="${esc(t)}">
      <span class="material-symbols-outlined text-on-surface-variant group-hover:text-primary-fixed-dim text-[18px] mt-0.5">${ic}</span>
      <div class="flex flex-col"><span class="text-[14px] text-on-surface">${esc(t)}</span>
      <span class="font-data-md text-on-surface-variant text-[11px] mt-1 line-clamp-1">${esc(s)}</span></div>
    </button>`).join("");
  $$("#suggested-paths .path-btn").forEach((b) => b.onclick = () => { setScreen("ai"); chatSend(b.dataset.q); });
}
function renderContext(evi) {
  const a = state.activeAlertObj;
  if (!a) return;
  $("#ctx-alert-name").textContent = a.title || (a.threat_type || "").replace(/_/g, " ");
  $("#ctx-alert-sub").textContent = `CONF ${(a.confidence ?? 0).toFixed(2)} · ${(evi[0] && evi[0].name) || a.threat_type}`;
  const sev = $("#ctx-alert-sev");
  sev.textContent = (a.severity || "").toUpperCase();
  sev.style.color = SEV_COLOR[a.severity] || "#ffb4ab";
  $("#ctx-host").textContent = a.src_host;
  $("#ctx-host-sub").textContent = (a.peers && a.peers.length) ? `${a.peers.length} peers` : "isolated";
  const gv = state.graphView || {};
  $("#ctx-edges").textContent = (gv.edges || []).length || "0";
  $("#ctx-peers").textContent = (a.peers || []).length;
  $("#ctx-impact").textContent = ((a.confidence ?? 0) * 10).toFixed(1);
}
function renderEvidenceRepo(evi) {
  const box = $("#evidence-repo");
  if (!evi || !evi.length) { box.innerHTML = `<div class="font-data-md text-[12px] text-outline">No evidence for the selected target.</div>`; return; }
  const icon = { rule: "gavel", anomaly: "show_chart", ml: "network_intelligence", graph: "account_tree" };
  box.innerHTML = evi.map((e) => {
    const data = e.data && typeof e.data === "object" ? Object.entries(e.data) : [];
    return `<div class="bg-surface border border-outline-variant/20 rounded-lg overflow-hidden">
      <div class="px-3 py-2 bg-surface-container flex items-center justify-between border-b border-outline-variant/10">
        <div class="flex items-center gap-2"><span class="material-symbols-outlined text-on-surface-variant text-[14px]">${icon[e.kind] || "description"}</span>
        <span class="font-data-md text-on-surface text-[11px]">${esc(e.name)}</span></div>
        <span class="font-label-caps text-[9px] text-on-surface-variant">${esc((e.kind || "").toUpperCase())} · ${(e.score ?? 0).toFixed(2)}</span>
      </div>
      <div class="p-3 evidence-body">
        <div class="font-data-md text-[11px] text-on-surface-variant leading-relaxed">${esc(e.detail)}</div>
        ${data.length ? `<div class="mt-2 flex flex-col gap-1 font-data-md text-[10px]">${data.slice(0, 8).map(([k, v]) =>
          `<div class="flex justify-between gap-3 text-on-surface-variant"><span>${esc(k)}</span><span class="text-on-surface truncate">${esc(typeof v === "object" ? JSON.stringify(v) : v)}</span></div>`).join("")}</div>` : ""}
      </div>
    </div>`;
  }).join("");
}

function appendChat(role, html, ts) {
  const t = ts || new Date().toISOString().slice(11, 23) + "Z";
  state.chat.push({ role, text: html.replace(/<[^>]+>/g, ""), ts: t });
  const c = $("#chat-container");
  const mine = role === "OPERATOR";
  const ai = role === "NEXUS_AI";
  const wrap = document.createElement("div");
  wrap.className = "flex gap-4 max-w-3xl" + (mine ? " self-end flex-row-reverse" : "");
  wrap.innerHTML = `
    <div class="w-8 h-8 rounded-full grid place-items-center shrink-0 border ${mine ? "bg-surface-container-highest border-outline-variant/30" : "bg-primary-container/10 border-primary-fixed-dim/30"}">
      <span class="material-symbols-outlined ${mine ? "text-on-surface" : "text-primary-fixed-dim"} text-[16px]">${mine ? "person" : role === "SYSTEM" ? "terminal" : "auto_awesome"}</span>
    </div>
    <div class="flex flex-col gap-2 pt-1 ${mine ? "items-end" : "w-full"}">
      <div class="flex items-center gap-2 ${mine ? "flex-row-reverse" : ""}">
        <span class="font-label-caps ${mine ? "text-on-surface" : "text-primary-fixed-dim"} text-[10px]">${role}</span>
        <span class="font-data-md text-on-surface-variant text-[10px]">${t}</span>
      </div>
      <div class="${mine ? "bg-surface-container p-4 rounded-2xl rounded-tr-sm text-[14px] text-on-surface"
        : ai ? "bg-surface-container-lowest p-5 rounded-xl border border-outline-variant/20 relative overflow-hidden font-data-md text-[13px] text-on-surface leading-relaxed"
        : "font-data-md text-[13px] text-on-surface opacity-80 leading-relaxed"}">
        ${ai ? '<div class="absolute top-0 left-0 w-1 h-full bg-primary-fixed-dim"></div>' : ""}${html}
      </div>
    </div>`;
  c.appendChild(wrap);
  c.scrollTop = c.scrollHeight;
}
function enterAIScreen() {
  renderSuggestedPaths();
  if (state.activeAlertObj) { renderContext(state.lastEvidence || []); renderEvidenceRepo(state.lastEvidence || []); }
  if (!state.chatSeeded) {
    state.chatSeeded = true;
    appendChat("SYSTEM", "Nexus AI connected to the UniNet TB-graph store. This is the Phase-4 read-only analyst assistant — it reads alerts, evidence and graph only. Awaiting operator query…");
  }
  $("#chat-input").focus();
}
async function chatSend(text) {
  const val = (text != null ? text : $("#chat-input").value).trim();
  if (!val) return;
  $("#chat-input").value = "";
  $("#chat-input").style.height = "auto";
  appendChat("OPERATOR", esc(val));
  try {
    const r = await fetch("/api/ask", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ q: val, alert_id: state.activeAlert, host: state.activeHost || (state.activeAlertObj && state.activeAlertObj.src_host) }),
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok && d.answer) appendChat("NEXUS_AI", esc(d.answer));
    else appendChat("NEXUS_AI",
      `<p><strong>Assistant offline (${r.status}).</strong> ${esc(d.error || "unavailable")}</p>` +
      (d.note ? `<p class="mt-2 text-on-surface-variant">${esc(d.note)}</p>` : "") +
      (state.activeAlertObj ? `<p class="mt-2 text-on-surface-variant">Context on file — alert <span class="text-primary-fixed-dim">${esc(state.activeAlertObj.threat_type)}</span> on <span class="text-primary-fixed-dim">${esc(state.activeAlertObj.src_host)}</span>, confidence ${(state.activeAlertObj.confidence ?? 0).toFixed(2)}. See the Evidence Repository panel.</p>` : ""));
  } catch (_) { appendChat("NEXUS_AI", "<p>Request failed.</p>"); }
}
function exportChat() {
  const lines = state.chat.map((m) => `[${m.ts}] ${m.role}: ${m.text}`).join("\n");
  const blob = new Blob([lines || "(empty)"], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "uninet-nexus-log.txt";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ================= SSE ================= */
function connectStream() {
  const dot = $("#live-dot"), label = $("#live-label");
  let es;
  try { es = new EventSource("/api/stream"); } catch (_) { return; }
  es.onopen = () => { if (dot) dot.className = "w-2 h-2 rounded-full bg-primary-container animate-pulse"; if (label) label.textContent = "SYSTEM_SYNCED"; };
  es.onmessage = (e) => { let v = null; try { v = JSON.parse(e.data).version; } catch (_) {} if (v == null || v !== state.version) scheduleTick(); };
  es.onerror = () => { if (dot) dot.className = "w-2 h-2 rounded-full bg-tertiary-fixed"; if (label) label.textContent = "RECONNECTING"; };
}

/* ================= wiring ================= */
$$("#rail .nav-icon[data-screen]").forEach((b) => b.onclick = () => setScreen(b.dataset.screen));
$("#filter-clear").onclick = clearFilter;
$("#queue-clear").onclick = clearFilter;
$("#queue-mode").onclick = () => { state.queueMode = state.queueMode === "alerts" ? "hosts" : "alerts"; render(); };
$("#queue-filter").onclick = () => {
  const order = [undefined, "critical", "high", "medium", "low"];
  state.filter.severity = order[(order.indexOf(state.filter.severity) + 1) % order.length];
  render();
};
$("#storyline-play").onclick = playStoryline;
$("#story-prev").onclick = () => storyStep(-1);
$("#story-next").onclick = () => storyStep(1);
$("#story-pause").onclick = stopStoryline;
$$(".ws-jump").forEach((b) => b.onclick = () => setScreen(b.dataset.to));
$("#ws-open-graph").onclick = () => setScreen("graph");
$("#ws-open-ai").onclick = () => {
  setScreen("ai");
  if (state.activeAlertObj) chatSend(`Summarise alert ${state.activeAlertObj.threat_type} on ${state.activeAlertObj.src_host}.`);
};

/* graph explorer controls */
$("#gx-zoom-in").onclick = () => { gxZoom = Math.min(5, gxZoom * 1.3); applyGX(); };
$("#gx-zoom-out").onclick = () => { gxZoom = Math.max(0.4, gxZoom / 1.3); applyGX(); };
$("#gx-center").onclick = () => { gxPanX = 0; gxPanY = 0; applyGX(); };
$("#gx-reset").onclick = () => { gxZoom = 1; gxPanX = 0; gxPanY = 0; applyGX(); if (state.graphView) drawGX(state.graphView); };
$("#gx-meta-close").onclick = () => $("#gx-meta").classList.add("translate-x-full");
$("#gx-expand").onclick = () => {
  const pivot = $("#gx-meta").dataset.pivot;
  if (!pivot) return;
  j(`/api/graph?host=${encodeURIComponent(pivot)}`).then((v) => { state.graphView = v; drawGX(v); }).catch(() => {});
};
$("#gx-trace").onclick = () => {
  const pivot = $("#gx-meta").dataset.pivot || "target";
  setScreen("ai");
  chatSend(`Trace and explain the traffic path for ${pivot}.`);
};
(() => {
  const svg = $("#gx-svg");
  let drag = false, sx = 0, sy = 0;
  svg.addEventListener("mousedown", (e) => { drag = true; sx = e.clientX; sy = e.clientY; });
  window.addEventListener("mouseup", () => { drag = false; });
  window.addEventListener("mousemove", (e) => {
    if (!drag) return;
    const r = svg.getBoundingClientRect();
    gxPanX -= (e.clientX - sx) * (GX_W / gxZoom) / r.width;
    gxPanY -= (e.clientY - sy) * (GX_H / gxZoom) / r.height;
    sx = e.clientX; sy = e.clientY;
    applyGX();
  });
})();

/* AI chat */
$("#chat-send").onclick = () => chatSend();
$("#chat-input").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); chatSend(); } });
$("#chat-input").addEventListener("input", function () { this.style.height = "auto"; this.style.height = Math.min(128, this.scrollHeight) + "px"; });
$("#chat-export").onclick = exportChat;

/* search */
const _search = $("#search");
_search.addEventListener("input", () => {
  state.filter.q = _search.value.trim().toLowerCase() || undefined;
  $("#search-clear").classList.toggle("hidden", !_search.value);
  render();
});
$("#search-clear").onclick = () => { _search.value = ""; state.filter.q = undefined; $("#search-clear").classList.add("hidden"); render(); };

setScreen("workspace");
loadConfig();
tick();
connectStream();
setInterval(tick, 20000);
setInterval(paintRefreshed, 1000);
