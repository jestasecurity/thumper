"""Modify & delete tripwires (#26): rename a tripwire, and hard-delete it +
cascade its deployments (live agents unplant via SP2 on re-pull). Alert history
survives a delete (alerts store a denormalized tripwire_name).
"""
from thumper import store

ENROLL_TOKEN = "dev-enroll-token"


def _mk(db, name="aws", path="~/.aws/credentials"):
    return store.create_tripwire(db, name=name, token_type="aws", path=path,
                                 token=f"bait-{name}")


def _enroll(tc, machine_id, tripwire_ids):
    r = tc.post("/api/enroll", data={
        "enroll_token": ENROLL_TOKEN, "hostname": "h", "machine_id": machine_id,
        "platform": "darwin", "tripwire_ids": tripwire_ids,
    })
    assert r.status_code == 200


def test_create_tripwire_strips_name(client_db):
    tc, db = client_db

    resp = tc.post("/api/tripwires", json={
        "name": "  foo  ",
        "token_type": "aws",
        "path": "~/.aws/credentials",
        "source": "template",
    })

    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "foo"
    assert store.get_tripwire(db, body["id"]).name == "foo"


def test_create_empty_name_is_400(client_db):
    tc, db = client_db

    resp = tc.post("/api/tripwires", json={
            "name": "   ",
            "token_type": "aws",
            "path": "~/.aws/credentials", 
            "source": "template",
    })

    assert resp.status_code == 400


def test_rename_tripwire(client_db):
    tc, db = client_db
    a = _mk(db, "old-name")

    resp = tc.patch(f"/api/tripwires/{a.id}", json={"name": "new-name"})

    assert resp.status_code == 200
    assert resp.json()["name"] == "new-name"
    assert store.get_tripwire(db, a.id).name == "new-name"


def test_rename_empty_name_is_400(client_db):
    tc, db = client_db
    a = _mk(db)
    assert tc.patch(f"/api/tripwires/{a.id}", json={"name": "   "}).status_code == 400


def test_rename_unknown_404(client_db):
    tc, _ = client_db
    assert tc.patch("/api/tripwires/tw_nope", json={"name": "x"}).status_code == 404


def test_delete_removes_tripwire_and_its_deployments(client_db):
    tc, db = client_db
    a = _mk(db)
    _enroll(tc, "m1", a.id)
    assert len(store.list_deployments_for_tripwire(db, a.id)) == 1

    resp = tc.delete(f"/api/tripwires/{a.id}")

    assert resp.status_code == 200
    assert store.get_tripwire(db, a.id) is None
    assert store.list_deployments_for_tripwire(db, a.id) == []
    assert tc.get(f"/api/tripwires/{a.id}").status_code == 404


def test_delete_unknown_404(client_db):
    tc, _ = client_db
    assert tc.delete("/api/tripwires/tw_nope").status_code == 404


def test_alert_history_survives_delete(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    store.create_alert(
        db, deployment_id="dp_x", tripwire_id=a.id, endpoint_id="ep_x",
        tripwire_name="aws", endpoint_hostname="host", token_type="aws",
        timestamp="2026-01-01T00:00:00Z", triggered_by="test")

    tc.delete(f"/api/tripwires/{a.id}")

    alerts = tc.get("/api/alerts").json()
    assert any(al["tripwire_name"] == "aws" for al in alerts)
