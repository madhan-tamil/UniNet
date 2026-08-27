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


def test_ask_is_blocked(client):
    assert client.post("/api/ask", json={"q": "hi"}).status_code == 501
