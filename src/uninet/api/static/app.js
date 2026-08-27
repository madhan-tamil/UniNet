"use strict";
const $ = (s) => document.querySelector(s);
const SVGNS = "http://www.w3.org/2000/svg";
const SEV = ["critical", "high", "medium", "low"];
const SEV_COLOR = { critical: "#ff5470", high: "#ff9f45", medium: "#ffd24a", low: "#4ad991" };
const NODE_COLOR = { host: "#6ea8ff", burst: "#ffd24a", domain: "#4ad991", alert: "#ff5470" };

let activeId = null;

async function j(url, opts) {
  const r = await fetch(url, opts);
  if (r.status === 401) { window.location = "/login"; throw new Error("unauth"); }
  return r.json();
}

/* ---------------- stats ---------------- */
async function loadStats() {
  const s = await j("/api/stats");
  $("#s-flows").textContent = s.flows.toLocaleString();
  $("#s-windows").textContent = s.windows;
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
    bar.title = `${n} ${k}`;
    mini.appendChild(bar);
  });

  const chips = $("#s-threats");
  chips.innerHTML = "";
  Object.entries(s.by_threat || {})
    .sort((a, b) => b[1] - a[1])
    .forEach(([k, v]) => {
      const c = document.createElement("span");
      c.className = "chip";
      c.textContent = `${k} · ${v}`;
      chips.appendChild(c);
    });

  $("#refreshed").textContent = "updated " + new Date().toLocaleTimeString();
}

/* ---------------- alerts ---------------- */
async function loadAlerts() {
  const rows = await j("/api/alerts");
  $("#alert-count").textContent = `${rows.length} shown`;
  const list = $("#alert-list");
  list.innerHTML = "";
  rows.forEach((a) => {
    const sc = a.scores || {};
    const card = document.createElement("div");
    card.className = "alert-card" + (a.alert_id === activeId ? " active" : "");
    card.dataset.id = a.alert_id;
    card.dataset.host = a.src_host;
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
    card.addEventListener("click", () => selectAlert(a.alert_id, a.src_host));
    list.appendChild(card);
  });
  if (!activeId && rows[0]) selectAlert(rows[0].alert_id, rows[0].src_host);
}

async function selectAlert(id, host) {
  activeId = id;
  document.querySelectorAll(".alert-card").forEach((c) =>
    c.classList.toggle("active", c.dataset.id === id));
  $("#detail-empty").hidden = true;
  $("#detail").hidden = false;
  $("#detail-host").textContent = host;

  const ex = await j(`/api/explain/${id}`);
  $("#verdict").innerHTML =
    `<b>${ex.threat_type}</b> · confidence ${ex.confidence.toFixed(2)}`;

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

  drawGraph(await j(`/api/graph?host=${encodeURIComponent(host)}`));
}

/* ---------------- TB-graph (tiny force layout) ---------------- */
function drawGraph(view) {
  const svg = $("#graph");
  svg.innerHTML = "";
  const W = 520, H = 380;
  const nodes = view.nodes.slice(0, 70);
  const id2n = new Map(nodes.map((n) => [n.id, n]));
  const edges = view.edges.filter((e) => id2n.has(e.src) && id2n.has(e.dst));

  nodes.forEach((n, i) => {
    n.x = W / 2 + Math.cos(i) * (40 + i * 4);
    n.y = H / 2 + Math.sin(i) * (30 + i * 3);
    n.fx = n.type === "host" ? W / 2 : null;
    n.fy = n.type === "host" ? H / 2 : null;
  });

  for (let it = 0; it < 220; it++) {
    for (let a = 0; a < nodes.length; a++) {
      for (let b = a + 1; b < nodes.length; b++) {
        const p = nodes[a], q = nodes[b];
        let dx = p.x - q.x, dy = p.y - q.y;
        let d2 = dx * dx + dy * dy || 1;
        const f = 1400 / d2;
        dx *= f; dy *= f;
        if (p.fx == null) { p.x += dx; p.y += dy; }
        if (q.fx == null) { q.x -= dx; q.y -= dy; }
      }
    }
    edges.forEach((e) => {
      const p = id2n.get(e.src), q = id2n.get(e.dst);
      let dx = q.x - p.x, dy = q.y - p.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const k = (d - 70) * 0.02;
      dx = (dx / d) * k; dy = (dy / d) * k;
      if (p.fx == null) { p.x += dx; p.y += dy; }
      if (q.fx == null) { q.x -= dx; q.y -= dy; }
    });
    nodes.forEach((n) => {
      if (n.fx != null) { n.x = n.fx; n.y = n.fy; return; }
      n.x = Math.max(16, Math.min(W - 16, n.x));
      n.y = Math.max(16, Math.min(H - 16, n.y));
    });
  }

  const edgeColor = (rel) =>
    rel === "periodic" ? "#ff9f45" : rel === "direction_change" ? "#ff5470" : "#5b6b93";
  edges.forEach((e) => {
    const p = id2n.get(e.src), q = id2n.get(e.dst);
    const ln = document.createElementNS(SVGNS, "line");
    ln.setAttribute("x1", p.x); ln.setAttribute("y1", p.y);
    ln.setAttribute("x2", q.x); ln.setAttribute("y2", q.y);
    ln.setAttribute("stroke", edgeColor(e.rel));
    ln.setAttribute("stroke-width", e.rel === "emits" ? 0.5 : 1.5);
    ln.setAttribute("stroke-opacity", e.rel === "emits" ? 0.35 : 0.8);
    svg.appendChild(ln);
  });
  nodes.forEach((n) => {
    const c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("cx", n.x); c.setAttribute("cy", n.y);
    c.setAttribute("r", n.type === "host" ? 9 : n.type === "burst" ? 5 : 4);
    c.setAttribute("fill", NODE_COLOR[n.type] || "#889");
    c.setAttribute("stroke", "#0c142a"); c.setAttribute("stroke-width", "1.5");
    const t = document.createElementNS(SVGNS, "title");
    t.textContent = n.id + (n.attrs && n.attrs.byte_count ? ` · ${(n.attrs.byte_count | 0)} B` : "");
    c.appendChild(t);
    svg.appendChild(c);
  });
}

/* ---------------- loop ---------------- */
async function tick() {
  try { await Promise.all([loadStats(), loadAlerts()]); } catch (_) {}
}
tick();
setInterval(loadStats, 5000);
