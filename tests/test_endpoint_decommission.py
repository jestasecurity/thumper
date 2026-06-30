"""Remote endpoint self-destruct: request → kill signal on heartbeat → confirm/delete."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.db import Alert, Base, Deployment, Endpoint, get_db
from thumper.main import app


@pytest.fixture
def client_db():
    engine = create_engine("sqlite://", echo=False,
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app), db
    del app.dependency_overrides[get_db]
    db.close()


def _raw_endpoint(db, eid, token):
    ep = Endpoint(id=eid, hostname="host-1", platform="linux", machine_id=f"m-{eid}",
                  agent_token=token, enrolled_at="2026-01-01T00:00:00Z",
                  last_seen="2026-06-17T12:00:00Z")
    db.add(ep)
    db.commit()
    return ep


def _deployment(db, did, eid):
    db.add(Deployment(id=did, tripwire_id="tw_1", endpoint_id=eid, path="/x",
                      content="bait", hmac_secret="s", state="planted",
                      created_at="2026-01-01T00:00:00Z"))
    db.commit()


# ── store ────────────────────────────────────────────────────────────────────

def test_request_decommission_sets_flag_and_returns_row(client_db):
    _, db = client_db
    _raw_endpoint(db, "ep_1", "tok_1")
    ep = store.request_decommission(db, "ep_1")
    assert ep is not None and ep.id == "ep_1"
    assert ep.decommission_requested_at is not None


def test_request_decommission_unknown_returns_none(client_db):
    _, db = client_db
    assert store.request_decommission(db, "nope") is None


def test_delete_endpoint_removes_deployments_keeps_alerts(client_db):
    _, db = client_db
    _raw_endpoint(db, "ep_1", "tok_1")
    _deployment(db, "dp_1", "ep_1")
    store.create_alert(db, deployment_id="dp_1", tripwire_id="tw_1", endpoint_id="ep_1",
                       tripwire_name="t", endpoint_hostname="host-1", token_type="aws",
                       timestamp="2026-06-17T10:00:00Z", triggered_by=None)
    assert store.delete_endpoint(db, "ep_1") is True
    assert store.get_endpoint(db, "ep_1") is None
    assert db.query(Deployment).filter(Deployment.endpoint_id == "ep_1").count() == 0
    assert db.query(Alert).filter(Alert.endpoint_id == "ep_1").count() == 1  # history kept


# ── API ──────────────────────────────────────────────────────────────────────

def test_decommission_endpoint_endpoint(client_db):
    tc, db = client_db
    _raw_endpoint(db, "ep_1", "tok_1")
    resp = tc.post("/api/endpoints/ep_1/decommission")
    assert resp.status_code == 200
    assert resp.json()["status"] == "decommissioning"
    db.expire_all()
    assert store.get_endpoint(db, "ep_1").decommission_requested_at is not None


def test_decommission_unknown_404(client_db):
    tc, _ = client_db
    assert tc.post("/api/endpoints/nope/decommission").status_code == 404


def test_heartbeat_returns_ok_when_live(client_db):
    tc, db = client_db
    _raw_endpoint(db, "ep_1", "tok_1")
    resp = tc.post("/api/agent/heartbeat", headers={"Authorization": "Bearer tok_1"})
    assert resp.status_code == 200
    assert resp.text.strip() == "ok"


def test_heartbeat_returns_kill_signal_when_decommissioning(client_db):
    tc, db = client_db
    _raw_endpoint(db, "ep_1", "tok_1")
    store.request_decommission(db, "ep_1")
    resp = tc.post("/api/agent/heartbeat", headers={"Authorization": "Bearer tok_1"})
    assert resp.status_code == 200
    assert resp.text.strip() == "decommission"


def test_agent_confirm_deletes_endpoint(client_db):
    tc, db = client_db
    _raw_endpoint(db, "ep_1", "tok_1")
    _deployment(db, "dp_1", "ep_1")
    store.request_decommission(db, "ep_1")
    resp = tc.post("/api/agent/decommissioned", headers={"Authorization": "Bearer tok_1"})
    assert resp.status_code == 200
    db.expire_all()
    assert store.get_endpoint(db, "ep_1") is None


def test_agent_confirm_is_idempotent_when_already_removed(client_db):
    # Operator force-removed the endpoint while the agent was confirming: the row
    # (and token) are already gone. Confirm must still succeed, not 401.
    tc, _ = client_db
    resp = tc.post("/api/agent/decommissioned", headers={"Authorization": "Bearer gone"})
    assert resp.status_code == 200
    assert resp.text.strip() == "ok"


def test_force_delete_endpoint(client_db):
    tc, db = client_db
    _raw_endpoint(db, "ep_1", "tok_1")
    _deployment(db, "dp_1", "ep_1")
    resp = tc.delete("/api/endpoints/ep_1")
    assert resp.status_code == 200
    db.expire_all()
    assert store.get_endpoint(db, "ep_1") is None
    assert db.query(Deployment).filter(Deployment.endpoint_id == "ep_1").count() == 0


def test_endpoints_list_shows_decommissioning_status(client_db):
    tc, db = client_db
    _raw_endpoint(db, "ep_1", "tok_1")
    store.request_decommission(db, "ep_1")
    body = tc.get("/api/endpoints").json()
    assert body[0]["status"] == "decommissioning"
