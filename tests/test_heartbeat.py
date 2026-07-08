"""Agent heartbeat: liveness-only signal."""
from datetime import datetime, timedelta, timezone

from thumper.api.routes import _endpoint_status
from thumper.db import Deployment, Endpoint


def _seed_endpoint(db, eid="ep_1", token="tok_abc"):
    db.add(Endpoint(id=eid, hostname="test-host", platform="darwin",
                    machine_id=f"mid_{eid}", agent_token=token,
                    enrolled_at="2026-01-01T00:00:00Z",
                    last_seen="2026-01-01T00:00:00Z"))
    db.commit()


def _seed_deployment(db, did, eid="ep_1", state="pending", tripwire_id=None):
    tid = tripwire_id or f"tw_{did}"
    db.add(Deployment(id=did, tripwire_id=tid, endpoint_id=eid,
                      path=f"/tmp/bait_{did}", content="bait-body",
                      hmac_secret=f"secret_{did}", state=state,
                      created_at="2026-01-01T00:00:00Z"))
    db.commit()


def test_heartbeat_updates_last_seen(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    old = db.query(Endpoint).filter(Endpoint.id == "ep_1").first().last_seen

    resp = tc.post("/api/agent/heartbeat", headers={"Authorization": "Bearer tok_abc"})

    assert resp.status_code == 200
    assert resp.text == "ok\n"
    db.expire_all()
    new = db.query(Endpoint).filter(Endpoint.id == "ep_1").first().last_seen
    assert new > old


def test_heartbeat_rejects_bad_token(client_db):
    tc, db = client_db
    _seed_endpoint(db)

    resp = tc.post("/api/agent/heartbeat", headers={"Authorization": "Bearer wrong_token"})

    assert resp.status_code == 401


def test_heartbeat_does_not_change_deployment_state(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    _seed_deployment(db, "dp_1", state="pending")

    resp = tc.post("/api/agent/heartbeat", headers={"Authorization": "Bearer tok_abc"})

    assert resp.status_code == 200
    db.expire_all()
    # heartbeat is liveness only - planted-state now comes from the agent's report
    assert db.query(Deployment).filter(Deployment.id == "dp_1").first().state == "pending"


def test_heartbeat_rejects_missing_auth(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    resp = tc.post("/api/agent/heartbeat")
    assert resp.status_code == 401


# ── endpoint status thresholds ──────────────────────────────────────────────

def _ts_ago(**kwargs):
    return (datetime.now(timezone.utc) - timedelta(**kwargs)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_endpoint_status_online_when_recent():
    assert _endpoint_status(_ts_ago(minutes=5)) == "online"


def test_endpoint_status_stale_after_15_minutes():
    assert _endpoint_status(_ts_ago(minutes=30)) == "stale"


def test_endpoint_status_inactive_after_12_hours():
    assert _endpoint_status(_ts_ago(hours=13)) == "inactive"


def test_endpoint_status_inactive_when_never_seen():
    assert _endpoint_status(None) == "inactive"


# ── POST /agent/deployments/{id}/state ──────────────────────────────────────

def test_state_endpoint_sets_planted(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    _seed_deployment(db, "dp_1", state="pending")

    resp = tc.post("/api/agent/deployments/dp_1/state",
                   headers={"Authorization": "Bearer tok_abc"},
                   data={"state": "planted"})

    assert resp.status_code == 200
    db.expire_all()
    assert db.query(Deployment).filter(Deployment.id == "dp_1").first().state == "planted"


def test_state_endpoint_sets_failed(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    _seed_deployment(db, "dp_1", state="pending")

    resp = tc.post("/api/agent/deployments/dp_1/state",
                   headers={"Authorization": "Bearer tok_abc"}, data={"state": "failed"})

    assert resp.status_code == 200
    db.expire_all()
    assert db.query(Deployment).filter(Deployment.id == "dp_1").first().state == "failed"


def test_state_endpoint_rejects_bad_state(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    _seed_deployment(db, "dp_1", state="pending")

    resp = tc.post("/api/agent/deployments/dp_1/state",
                   headers={"Authorization": "Bearer tok_abc"}, data={"state": "bogus"})

    assert resp.status_code == 400
    db.expire_all()
    assert db.query(Deployment).filter(Deployment.id == "dp_1").first().state == "pending"


def test_state_endpoint_rejects_other_endpoints_deployment(client_db):
    tc, db = client_db
    _seed_endpoint(db, eid="ep_1", token="tok_abc")
    _seed_endpoint(db, eid="ep_2", token="tok_def")
    _seed_deployment(db, "dp_2", eid="ep_2", state="pending")

    resp = tc.post("/api/agent/deployments/dp_2/state",
                   headers={"Authorization": "Bearer tok_abc"}, data={"state": "planted"})

    assert resp.status_code == 404
    db.expire_all()
    assert db.query(Deployment).filter(Deployment.id == "dp_2").first().state == "pending"


def test_state_endpoint_rejects_missing_state(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    _seed_deployment(db, "dp_1", state="pending")

    resp = tc.post("/api/agent/deployments/dp_1/state",
                   headers={"Authorization": "Bearer tok_abc"}, data={})

    assert resp.status_code == 400
    db.expire_all()
    assert db.query(Deployment).filter(Deployment.id == "dp_1").first().state == "pending"


def test_state_endpoint_rejects_bad_token(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    _seed_deployment(db, "dp_1", state="pending")

    resp = tc.post("/api/agent/deployments/dp_1/state",
                   headers={"Authorization": "Bearer wrong"}, data={"state": "planted"})

    assert resp.status_code == 401


# ── GET /agent/deployments/{id}/content (#200) ───────────────────────────────

def test_content_endpoint_returns_bait_body(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    _seed_deployment(db, "dp_1")

    resp = tc.get("/api/agent/deployments/dp_1/content",
                  headers={"Authorization": "Bearer tok_abc"})

    assert resp.status_code == 200
    assert resp.text == "bait-body"


def test_content_endpoint_rejects_other_endpoints_deployment(client_db):
    tc, db = client_db
    _seed_endpoint(db, eid="ep_1", token="tok_abc")
    _seed_endpoint(db, eid="ep_2", token="tok_def")
    _seed_deployment(db, "dp_2", eid="ep_2")

    resp = tc.get("/api/agent/deployments/dp_2/content",
                  headers={"Authorization": "Bearer tok_abc"})

    assert resp.status_code == 404


def test_content_endpoint_unknown_deployment_404(client_db):
    tc, db = client_db
    _seed_endpoint(db)

    resp = tc.get("/api/agent/deployments/dp_nope/content",
                  headers={"Authorization": "Bearer tok_abc"})

    assert resp.status_code == 404


def test_content_endpoint_rejects_bad_token(client_db):
    tc, db = client_db
    _seed_endpoint(db)
    _seed_deployment(db, "dp_1")

    resp = tc.get("/api/agent/deployments/dp_1/content",
                  headers={"Authorization": "Bearer wrong"})

    assert resp.status_code == 401
