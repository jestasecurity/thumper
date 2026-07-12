"""Endpoint <-> tripwire assignment (SP3 of #34): assign/unassign tripwires on an
already-enrolled endpoint, and confirm re-enroll is additive (never removes).
The live agent (SP2) applies the resulting deployment-set changes.
"""
from thumper import store

ENROLL_TOKEN = "dev-enroll-token"


def _mk(db, name, path="~/.aws/credentials"):
    return store.create_tripwire(db, name=name, token_type="aws", path=path,
                                 token=f"bait-{name}")


def _enroll(tc, db, machine_id, tripwire_ids):
    existing = db.query(store.Endpoint).filter(store.Endpoint.machine_id == machine_id).first()
    r = tc.post("/api/enroll", data={
        "enroll_token": ENROLL_TOKEN, "hostname": "h", "machine_id": machine_id,
        "platform": "darwin", "tripwire_ids": tripwire_ids,
        "agent_token": existing.agent_token if existing else "",
    })
    assert r.status_code == 200
    return [ln for ln in r.text.splitlines() if ln.startswith("endpoint_id=")][0].split("=", 1)[1]


def test_assign_creates_pending_deployment(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    eid = _enroll(tc, db, "m1", "")

    resp = tc.post(f"/api/endpoints/{eid}/tripwires", json={"tripwire_id": a.id})

    assert resp.status_code == 200
    db.expire_all()
    deps = store.list_deployments_for_endpoint(db, eid)
    assert len(deps) == 1
    assert deps[0].tripwire_id == a.id
    assert deps[0].state == "pending"


def test_assign_is_idempotent(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    eid = _enroll(tc, db, "m1", "")

    first = tc.post(f"/api/endpoints/{eid}/tripwires", json={"tripwire_id": a.id}).json()
    again = tc.post(f"/api/endpoints/{eid}/tripwires", json={"tripwire_id": a.id}).json()

    assert first["id"] == again["id"]
    db.expire_all()
    assert len(store.list_deployments_for_endpoint(db, eid)) == 1


def test_unassign_deletes_deployment(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    eid = _enroll(tc, db, "m1", a.id)
    db.expire_all()
    assert len(store.list_deployments_for_endpoint(db, eid)) == 1

    resp = tc.delete(f"/api/endpoints/{eid}/tripwires/{a.id}")

    assert resp.status_code == 200
    db.expire_all()
    assert store.list_deployments_for_endpoint(db, eid) == []


def test_unassign_absent_is_404(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    eid = _enroll(tc, db, "m1", "")
    assert tc.delete(f"/api/endpoints/{eid}/tripwires/{a.id}").status_code == 404


def test_assign_unknown_endpoint_404_unknown_tripwire_400(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    eid = _enroll(tc, db, "m1", "")

    assert tc.post("/api/endpoints/ep_nope/tripwires",
                   json={"tripwire_id": a.id}).status_code == 404
    assert tc.post(f"/api/endpoints/{eid}/tripwires",
                   json={"tripwire_id": "tw_nope"}).status_code == 400


def test_reenroll_is_additive(client_db):
    """Re-running the install (re-enroll) adds new tripwires and never removes."""
    tc, db = client_db
    a = _mk(db, "aws")
    b = _mk(db, "npm", "~/.npmrc")

    eid = _enroll(tc, db, "m1", a.id)
    db.expire_all()
    assert {d.tripwire_id for d in store.list_deployments_for_endpoint(db, eid)} == {a.id}

    _enroll(tc, db, "m1", f"{a.id},{b.id}")
    db.expire_all()
    assert {d.tripwire_id for d in store.list_deployments_for_endpoint(db, eid)} == {a.id, b.id}

    _enroll(tc, db, "m1", a.id)
    db.expire_all()
    assert {d.tripwire_id for d in store.list_deployments_for_endpoint(db, eid)} == {a.id, b.id}


# ── GET /api/endpoints/{eid} (#200) ──────────────────────────────────────────

def test_get_endpoint_includes_deployments(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    eid = _enroll(tc, db, "m1", a.id)

    resp = tc.get(f"/api/endpoints/{eid}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == eid
    assert len(body["deployments"]) == 1
    assert body["deployments"][0]["tripwire_id"] == a.id


def test_get_endpoint_unknown_404(client_db):
    tc, _ = client_db
    assert tc.get("/api/endpoints/ep_nope").status_code == 404
