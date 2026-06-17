"""Alert lifecycle: manual resolve (Open → Resolved), per-alert + bulk."""
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.db import Base, get_db
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


def _mk(db, *, did, tid="tw_1", eid="ep_1"):
    return store.create_alert(
        db, deployment_id=did, tripwire_id=tid, endpoint_id=eid,
        tripwire_name="AWS creds", endpoint_hostname="host-1", token_type="aws",
        accessed_path="~/.aws/credentials", process="cat", pid=1, os_user="root",
        event_type="openat", timestamp="2026-06-17T10:00:00Z", triggered_by="cat")


# ── store ────────────────────────────────────────────────────────────────────

def test_new_alert_is_open(client_db):
    _, db = client_db
    a = _mk(db, did="dp_1")
    assert a.resolved_at is None


def test_resolve_alert_sets_timestamp_and_returns_row(client_db):
    _, db = client_db
    a = _mk(db, did="dp_1")
    resolved = store.resolve_alert(db, a.id)
    assert resolved is not None and resolved.id == a.id
    assert resolved.resolved_at is not None


def test_resolve_unknown_alert_returns_none(client_db):
    _, db = client_db
    assert store.resolve_alert(db, "nope") is None


def test_list_alerts_invalid_status_raises(client_db):
    _, db = client_db
    with pytest.raises(ValueError):
        store.list_alerts(db, status="typo")


def test_resolve_all_alerts_store(client_db):
    _, db = client_db
    _mk(db, did="dp_1"); _mk(db, did="dp_2"); _mk(db, did="dp_3")
    assert store.resolve_all_alerts(db) == 3
    assert store.resolve_all_alerts(db) == 0  # nothing left open
    assert store.list_alerts(db, status="open") == []


def test_resolve_all_endpoint(client_db):
    tc, db = client_db
    _mk(db, did="dp_1"); _mk(db, did="dp_2")
    resp = tc.post("/api/alerts/resolve-all")
    assert resp.status_code == 200
    assert resp.json() == {"resolved": 2}
    assert tc.get("/api/stats").json()["active_triggers"] == 0


def test_bulk_resolve_for_deployment(client_db):
    _, db = client_db
    _mk(db, did="dp_1"); _mk(db, did="dp_1"); _mk(db, did="dp_2")
    assert store.resolve_deployment_alerts(db, "dp_1") == 2
    # a second call resolves nothing new
    assert store.resolve_deployment_alerts(db, "dp_1") == 0
    assert store.count_alerts_for_deployment(db, "dp_2") == 1


def test_active_triggers_counts_open_deployments_only(client_db):
    _, db = client_db
    _mk(db, did="dp_1"); _mk(db, did="dp_2")
    assert store.count_distinct_alert_deployments(db) == 2
    store.resolve_deployment_alerts(db, "dp_1")
    assert store.count_distinct_alert_deployments(db) == 1


def test_list_alerts_status_filter(client_db):
    _, db = client_db
    a = _mk(db, did="dp_1"); _mk(db, did="dp_2")
    store.resolve_alert(db, a.id)
    assert len(store.list_alerts(db)) == 2
    assert len(store.list_alerts(db, status="open")) == 1
    assert len(store.list_alerts(db, status="resolved")) == 1


# ── API ──────────────────────────────────────────────────────────────────────

def test_alert_out_exposes_status(client_db):
    tc, db = client_db
    _mk(db, did="dp_1")
    body = tc.get("/api/alerts").json()
    assert body[0]["status"] == "open"
    assert body[0]["resolved_at"] is None


def test_resolve_alert_endpoint(client_db):
    tc, db = client_db
    a = _mk(db, did="dp_1")
    resp = tc.post(f"/api/alerts/{a.id}/resolve")
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"
    assert resp.json()["resolved_at"] is not None


def test_resolve_unknown_alert_endpoint_404(client_db):
    tc, _ = client_db
    assert tc.post("/api/alerts/nope/resolve").status_code == 404


def test_bulk_resolve_endpoint(client_db):
    tc, db = client_db
    _mk(db, did="dp_1"); _mk(db, did="dp_1")
    resp = tc.post("/api/alerts/resolve", json={"deployment_id": "dp_1"})
    assert resp.status_code == 200
    assert resp.json() == {"resolved": 2}
    assert all(a["status"] == "resolved" for a in tc.get("/api/alerts").json())


def test_stats_active_triggers_reflects_open(client_db):
    tc, db = client_db
    _mk(db, did="dp_1"); _mk(db, did="dp_2")
    assert tc.get("/api/stats").json()["active_triggers"] == 2
    tc.post("/api/alerts/resolve", json={"deployment_id": "dp_1"})
    assert tc.get("/api/stats").json()["active_triggers"] == 1


# ── trigger counts everywhere reflect OPEN alerts only ───────────────────────

def test_endpoint_trigger_count_is_open_only(client_db):
    _, db = client_db
    a = _mk(db, did="dp_1", eid="ep_1"); _mk(db, did="dp_2", eid="ep_1")
    assert store.count_alerts_for_endpoint(db, "ep_1") == 2
    store.resolve_alert(db, a.id)
    assert store.count_alerts_for_endpoint(db, "ep_1") == 1


def test_tripwire_trigger_count_is_open_only(client_db):
    _, db = client_db
    a = _mk(db, did="dp_1", tid="tw_1"); _mk(db, did="dp_2", tid="tw_1")
    assert store.count_alerts_for_tripwire(db, "tw_1") == 2
    store.resolve_alert(db, a.id)
    assert store.count_alerts_for_tripwire(db, "tw_1") == 1


def test_deployment_trigger_count_is_open_only(client_db):
    _, db = client_db
    a = _mk(db, did="dp_1"); _mk(db, did="dp_1")
    assert store.count_alerts_for_deployment(db, "dp_1") == 2
    store.resolve_alert(db, a.id)
    assert store.count_alerts_for_deployment(db, "dp_1") == 1


def test_batched_counts_are_open_only(client_db):
    _, db = client_db
    a = _mk(db, did="dp_1", eid="ep_1", tid="tw_1")
    _mk(db, did="dp_2", eid="ep_1", tid="tw_1")
    store.resolve_alert(db, a.id)
    assert store.alert_counts_by_endpoint(db)["ep_1"] == 1
    assert store.alert_counts_by_tripwire(db)["tw_1"] == 1


def test_stats_alerts_24h_excludes_resolved(client_db):
    tc, db = client_db
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    a = store.create_alert(db, deployment_id="dp_1", tripwire_id="tw_1", endpoint_id="ep_1",
                           tripwire_name="x", endpoint_hostname="h", token_type="aws",
                           timestamp=now, triggered_by=None)
    store.create_alert(db, deployment_id="dp_2", tripwire_id="tw_1", endpoint_id="ep_1",
                       tripwire_name="x", endpoint_hostname="h", token_type="aws",
                       timestamp=now, triggered_by=None)
    assert tc.get("/api/stats").json()["alerts_24h"] == 2
    store.resolve_alert(db, a.id)
    assert tc.get("/api/stats").json()["alerts_24h"] == 1


def test_endpoints_api_trigger_count_decays(client_db):
    tc, db = client_db
    from thumper.db import Endpoint
    db.add(Endpoint(id="ep_1", hostname="h", platform="linux", machine_id="m1",
                    agent_token="t", enrolled_at="2026-01-01T00:00:00Z",
                    last_seen="2026-01-01T00:00:00Z"))
    db.commit()
    _mk(db, did="dp_1", eid="ep_1")
    assert tc.get("/api/endpoints").json()[0]["triggered_count"] == 1
    tc.post("/api/alerts/resolve", json={"deployment_id": "dp_1"})
    assert tc.get("/api/endpoints").json()[0]["triggered_count"] == 0
