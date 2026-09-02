"""Flask API + interactive dashboard.

Passive-architecture note: "read-only" is a property of the *sensor architecture*
(no return path to the monitored network). The console itself is fully
interactive - filtering, drill-down, a live host/client view.

Endpoints (GET unless noted; session required except /api/health + login):
    /                     dashboard
    /login  /logout       session auth (single operator account)
    /api/health           liveness (open)
    /api/session          who am I / auth mode
    /api/config           bind host, port, base URL, mode  (for the header)
    /api/stats            flow / window / graph / alert / threat counts
    /api/hosts            per-host (client) summary: ip, flows, bursts, ports, alert
    /api/alerts           list of Alert JSON
    /api/alerts/<id>      one Alert
    /api/explain/<id>     evidence breakdown for one Alert
    /api/graph?host=IP    TB-Graph view (subgraph for a host, or whole graph)
    /api/ask   (POST)     read-only analyst assistant  {question, alert_id?}
"""
from __future__ import annotations

import json
import queue
import threading
import webbrowser
from datetime import timedelta
from threading import Timer

from flask import Flask, Response, jsonify, render_template, request, session

from uninet.api.auth import bp as auth_bp
from uninet.api.auth import is_authenticated, login_required
from uninet.config import Settings, load_settings
from uninet.features.fingerprint import behavioural_fingerprint
from uninet.streaming.worker import PipelineResult, run_pipeline

# --- real-time push (Server-Sent Events) ------------------------------ #
# The console subscribes to /api/stream; every set_result() bumps a version
# counter and wakes every open stream so the browser refreshes within ~200ms
# instead of waiting for the fallback poll.
_subscribers: set[queue.Queue] = set()
_subs_lock = threading.Lock()


def _publish_version(version: int) -> None:
    with _subs_lock:
        for q in list(_subscribers):
            try:
                q.put_nowait(version)
            except queue.Full:  # slow client - it will catch up on the next poll
                pass


def set_result(app: Flask, result: PipelineResult) -> None:
    """Swap in a fresh pipeline result (used by the live service)."""
    app.config["RESULT"] = result
    app.config["ALERTS_BY_ID"] = {a.alert_id: a for a in result.alerts}
    app.config["HOSTS"] = _hosts_summary(result)
    version = app.config.get("VERSION", 0) + 1
    app.config["VERSION"] = version
    _publish_version(version)


def _hosts_summary(result: PipelineResult) -> list[dict]:
    """Aggregate per-host (client) view across all windows."""
    _RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    by_host: dict[str, dict] = {}

    for f in result.features:
        h = by_host.setdefault(f.host, {
            "ip": f.host, "windows": 0, "flows": 0.0, "bytes": 0.0, "bursts": 0.0,
            "peers": set(), "dst_ports": set(), "domains": set(),
            "periodicity": 0.0, "fingerprint": "",
        })
        v = f.vector
        h["windows"] += 1
        h["flows"] += v.get("flow_count", 0.0)
        h["bytes"] += v.get("byte_count", 0.0)
        h["bursts"] += v.get("burst_count", 0.0)
        h["peers"].update(f.peers)
        h["dst_ports"].update(f.dst_ports)
        h["domains"].update(f.top_domains)
        h["periodicity"] = max(h["periodicity"], v.get("max_inter_burst_periodicity", 0.0))
        h["fingerprint"] = behavioural_fingerprint(f)

    alert_by_host: dict[str, dict] = {}
    for a in result.alerts:
        cur = alert_by_host.get(a.src_host)
        if cur is None or a.confidence > cur["confidence"]:
            alert_by_host[a.src_host] = {
                "threat": a.threat_type.value,
                "severity": a.severity.value,
                "confidence": a.confidence,
                "alert_id": a.alert_id,
            }

    out: list[dict] = []
    for ip, h in by_host.items():
        out.append({
            "ip": ip,
            "windows": h["windows"],
            "flows": int(h["flows"]),
            "bytes": int(h["bytes"]),
            "bursts": int(h["bursts"]),
            "peer_count": len(h["peers"]),
            "peers": sorted(h["peers"])[:12],
            "dst_ports": sorted(p for p in h["dst_ports"] if p)[:20],
            "domains": sorted(h["domains"])[:10],
            "periodicity": round(h["periodicity"], 3),
            "fingerprint": h["fingerprint"],
            "alert": alert_by_host.get(ip),
        })
    out.sort(key=lambda x: (
        _RANK.get(x["alert"]["severity"], -1) if x["alert"] else -1,
        x["flows"],
    ), reverse=True)
    return out


def create_app(result: PipelineResult | None = None, settings: Settings | None = None) -> Flask:
    settings = settings or load_settings()
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = settings.secret_key
    app.permanent_session_lifetime = timedelta(hours=12)

    if result is None:
        from uninet.ingestion.sources.synthetic import SyntheticSource

        result = run_pipeline(SyntheticSource(), settings)

    app.config["SETTINGS"] = settings
    app.config["VERSION"] = 0
    set_result(app, result)
    app.register_blueprint(auth_bp)

    # ---- UI ------------------------------------------------------- #
    @app.get("/")
    @login_required
    def index():
        return render_template("index.html", user=session.get("user", "operator"))

    # ---- API ------------------------------------------------------ #
    @app.get("/api/health")
    def health():
        return jsonify(status="ok", architecture="passive/read-only")

    @app.get("/api/session")
    def whoami():
        return jsonify(authenticated=is_authenticated(), user=session.get("user"),
                       auth_disabled=settings.auth_disabled)

    @app.get("/api/config")
    @login_required
    def api_config():
        host = "localhost" if settings.api_host in ("0.0.0.0", "") else settings.api_host
        return jsonify(
            bind_host=settings.api_host,
            port=settings.api_port,
            base_url=f"http://{host}:{settings.api_port}",
            window_seconds=settings.window_seconds,
            bus=settings.bus,
            live=bool(app.config.get("LIVE")),
        )

    @app.get("/api/stats")
    @login_required
    def stats():
        r: PipelineResult = app.config["RESULT"]
        by_sev: dict[str, int] = {}
        by_threat: dict[str, int] = {}
        for a in r.alerts:
            by_sev[a.severity.value] = by_sev.get(a.severity.value, 0) + 1
            by_threat[a.threat_type.value] = by_threat.get(a.threat_type.value, 0) + 1
        return jsonify(
            flows=r.flow_count, windows=r.window_count, graph=r.graph.stats(),
            alerts=len(r.alerts), hosts=len(app.config["HOSTS"]),
            by_severity=by_sev, by_threat=by_threat,
            version=app.config.get("VERSION", 0),
        )

    @app.get("/api/stream")
    @login_required
    def stream():
        """Server-Sent Events: emits {"version": N} whenever detections change."""
        def _events():
            q: queue.Queue = queue.Queue(maxsize=8)
            with _subs_lock:
                _subscribers.add(q)
            try:
                yield f'data: {json.dumps({"version": app.config.get("VERSION", 0)})}\n\n'
                while True:
                    try:
                        v = q.get(timeout=15)
                        yield f'data: {json.dumps({"version": v})}\n\n'
                    except queue.Empty:
                        yield ": ping\n\n"
            finally:
                with _subs_lock:
                    _subscribers.discard(q)

        return Response(
            _events(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/hosts")
    @login_required
    def hosts():
        return jsonify(app.config["HOSTS"])

    @app.get("/api/alerts")
    @login_required
    def alerts():
        r: PipelineResult = app.config["RESULT"]
        return jsonify([a.model_dump(mode="json")
                        for a in sorted(r.alerts, key=lambda x: -x.confidence)])

    @app.get("/api/alerts/<alert_id>")
    @login_required
    def alert_one(alert_id: str):
        a = app.config["ALERTS_BY_ID"].get(alert_id)
        return (jsonify(a.model_dump(mode="json")) if a else (jsonify(error="not found"), 404))

    @app.get("/api/explain/<alert_id>")
    @login_required
    def explain(alert_id: str):
        a = app.config["ALERTS_BY_ID"].get(alert_id)
        if not a:
            return jsonify(error="not found"), 404
        from uninet.explainability.explainer import explain_alert

        payload = explain_alert(a)
        payload["evidence"] = [e.model_dump(mode="json") for e in a.evidence]
        return jsonify(payload)

    @app.get("/api/graph")
    @login_required
    def graph():
        r: PipelineResult = app.config["RESULT"]
        host = request.args.get("host")
        view = (r.graph.to_view(r.graph.subgraph_for_host(host)) if host
                else r.graph.to_view())
        return jsonify(view.model_dump(mode="json"))

    @app.post("/api/ask")
    @login_required
    def ask():
        """Read-only analyst assistant. Body: {question, alert_id?}."""
        from uninet.assistant import ask as assistant_ask
        from uninet.assistant import build_context

        body = request.get_json(silent=True) or {}
        question = (body.get("question") or "").strip()
        if not question:
            return jsonify(error="missing 'question'"), 400

        r: PipelineResult = app.config["RESULT"]
        alert_id = body.get("alert_id")
        a = (app.config["ALERTS_BY_ID"].get(alert_id) if alert_id
             else max(r.alerts, key=lambda x: x.confidence, default=None))
        if a is None:
            return jsonify(error="no alert to explain"), 404

        view = r.graph.to_view(r.graph.subgraph_for_host(a.src_host))
        ctx = build_context(a, view)
        return jsonify(assistant_ask(question, ctx))

    return app


def serve(app: Flask, settings: Settings | None = None, open_browser: bool = True) -> None:
    settings = settings or load_settings()
    host = "localhost" if settings.api_host in ("0.0.0.0", "") else settings.api_host
    url = f"http://{host}:{settings.api_port}/"
    if open_browser:
        Timer(0.8, lambda: webbrowser.open(url)).start()
    banner = "  UniNet dashboard  ->  " + url
    if not settings.auth_disabled:
        banner += f"   login: {settings.auth_user} / {settings.auth_password}"
    print(banner + "   (Ctrl+C to stop)")
    # threaded: each SSE (/api/stream) client holds a worker thread for its
    # lifetime - fine at console scale, not a production server.
    app.run(host=settings.api_host, port=settings.api_port, debug=False, threaded=True)


if __name__ == "__main__":
    serve(create_app())
