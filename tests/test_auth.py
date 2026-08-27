import pytest

from uninet.api.app import create_app
from uninet.config import load_settings
from uninet.streaming.worker import PipelineResult


@pytest.fixture
def app():
    settings = load_settings()
    settings.auth_disabled = False
    settings.auth_user = "admin"
    settings.auth_password = "secret"
    settings.secret_key = "test-key"
    return create_app(PipelineResult(), settings=settings)


def test_protected_routes_require_login(app):
    c = app.test_client()
    assert c.get("/api/health").status_code == 200          # open
    assert c.get("/api/alerts").status_code == 401          # gated
    assert c.get("/", follow_redirects=False).status_code in (301, 302)


def test_login_bad_then_good(app):
    c = app.test_client()
    bad = c.post("/login", data={"username": "admin", "password": "nope"})
    assert bad.status_code == 401

    ok = c.post("/login", data={"username": "admin", "password": "secret"},
                follow_redirects=False)
    assert ok.status_code == 302
    assert c.get("/api/alerts").status_code == 200          # session now valid

    c.get("/logout")
    assert c.get("/api/alerts").status_code == 401


def test_auth_disabled_opens_everything():
    settings = load_settings()
    settings.auth_disabled = True
    c = create_app(PipelineResult(), settings=settings).test_client()
    assert c.get("/api/alerts").status_code == 200
    assert c.get("/").status_code == 200
