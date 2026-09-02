import pytest

from uninet.api.app import create_app
from uninet.config import load_settings
from uninet.detection.detector import Detector
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.streaming.worker import run_pipeline


@pytest.fixture(scope="module")
def client():
    settings = load_settings()
    settings.auth_disabled = True  # exercise the API without the login flow
    result = run_pipeline(SyntheticSource(seed=7), settings, detector=Detector.from_settings(settings))
    app = create_app(result, settings=settings)
    app.config.update(TESTING=True)
    return app.test_client()


def test_health(client):
    assert client.get("/api/health").get_json()["status"] == "ok"


def test_alerts_and_explain(client):
    alerts = client.get("/api/alerts").get_json()
    assert isinstance(alerts, list) and alerts
    aid = alerts[0]["alert_id"]
    ex = client.get(f"/api/explain/{aid}").get_json()
    assert ex["alert_id"] == aid
    assert ex["evidence"]


def test_graph_for_host(client):
    alerts = client.get("/api/alerts").get_json()
    host = alerts[0]["src_host"]
    view = client.get(f"/api/graph?host={host}").get_json()
    assert "nodes" in view and "edges" in view
    burst = next((n for n in view["nodes"] if n["type"] == "burst"), None)
    assert burst and "peer" in burst["attrs"]  # IP info is on graph nodes


def test_hosts_endpoint(client):
    hosts = client.get("/api/hosts").get_json()
    assert isinstance(hosts, list) and hosts
    h = hosts[0]
    for key in ("ip", "flows", "bursts", "peer_count", "dst_ports", "fingerprint"):
        assert key in h
    # at least one client should carry an alert badge
    assert any(x["alert"] for x in hosts)


def test_config_endpoint(client):
    c = client.get("/api/config").get_json()
    assert c["port"] and c["base_url"].startswith("http://")


def test_stats_carries_version(client):
    assert isinstance(client.get("/api/stats").get_json()["version"], int)


def test_stream_emits_version(client):
    resp = client.get("/api/stream", buffered=False)
    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"
    first = next(resp.response).decode()  # generator yields the current version at once
    resp.close()
    assert '"version"' in first


def test_ask_requires_question(client):
    assert client.post("/api/ask", json={}).status_code == 400


def test_ask_answers_read_only(client):
    r = client.post("/api/ask", json={"question": "why is this an alert?"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["read_only"] is True
    assert body["intent"] == "why"
    assert len(body["answer"]) > 30
    assert body["refs"]["alert_id"]


def test_ask_intent_routing(client):
    for q, want in [
        ("how confident are you?", "confidence"),
        ("which bursts caused this?", "graph"),
        ("what should I do next?", "next"),
        ("who is the host talking to?", "peers"),
    ]:
        got = client.post("/api/ask", json={"question": q}).get_json()["intent"]
        assert got == want, (q, got)
