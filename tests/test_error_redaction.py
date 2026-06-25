"""Credential material must not leak into stored/returned integration errors —
the webhook URL embeds its token (#33)."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.api import routes
from thumper.db import Base, get_db
from thumper.main import app
from thumper.services.integrations import redact_secrets

SECRET_URL = "https://hooks.slack.com/services/T00/B00/superSecretToken123"


@pytest.fixture
def client_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app), db
    del app.dependency_overrides[get_db]
    db.close()


def test_redact_secrets_removes_url_and_token():
    text = f"connect to {SECRET_URL} failed"
    out = redact_secrets(text, {"url": SECRET_URL})
    assert "superSecretToken123" not in out
    assert SECRET_URL not in out
    assert "•••" in out


def test_redact_keeps_short_values():
    # short/boolean-ish values aren't redacted (avoid mangling normal text)
    assert redact_secrets("port 443 ok", {"port": "443"}) == "port 443 ok"


def test_test_endpoint_error_is_redacted(client_db, monkeypatch):
    tc, db = client_db
    tc.post("/api/integrations/webhook", json={"url": SECRET_URL})

    class Boom:
        def test(self):
            raise RuntimeError(f"POST {SECRET_URL} -> connection refused")

    monkeypatch.setattr(routes, "load_plugin", lambda name, cfg: Boom())
    resp = tc.post("/api/integrations/webhook/test")
    assert resp.status_code == 200
    assert "superSecretToken123" not in resp.json()["error"]
    stored = store.get_integration(db, "webhook").last_test_error
    assert "superSecretToken123" not in stored
