"""The management/UI API is gated by the shared admin token (#20), fail-closed
when THUMPER_ADMIN_TOKEN is unset. Agent-facing routes keep their own tokens and
are NOT subject to the admin gate.

These tests remove the conftest `_bypass_admin_auth` override so the real
`require_admin` dependency runs.
"""
import pytest
from fastapi.testclient import TestClient

from thumper import config
from thumper.api.routes import require_admin
from thumper.db import Base, get_db
from thumper.main import app
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

TOKEN = "s3cr3t-admin-token"


@pytest.fixture
def client(monkeypatch):
    # Real auth: drop the global bypass override for these tests.
    app.dependency_overrides.pop(require_admin, None)
    monkeypatch.setattr(config, "ADMIN_TOKEN", TOKEN)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app)
    del app.dependency_overrides[get_db]
    app.dependency_overrides[require_admin] = lambda: None  # restore conftest's bypass
    db.close()


def test_management_route_requires_token(client):
    assert client.get("/api/stats").status_code == 401


def test_management_route_rejects_wrong_token(client):
    r = client.get("/api/stats", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_management_route_accepts_correct_token(client):
    r = client.get("/api/stats", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200


def test_fail_closed_when_token_unset(client, monkeypatch):
    # No admin token configured -> management API disabled (503), never open.
    monkeypatch.setattr(config, "ADMIN_TOKEN", "")
    assert client.get("/api/stats").status_code == 503
    # even a "Bearer " request can't reach it
    assert client.get("/api/stats", headers={"Authorization": "Bearer x"}).status_code == 503


def test_agent_route_not_gated_by_admin_token(client):
    # The agent fetches its own script with no admin token; must stay reachable.
    r = client.get("/api/agent/thumper_agent.sh")
    assert r.status_code == 200
    # and the management gate's 401/503 must NOT apply here
    assert r.status_code not in (401, 503)
