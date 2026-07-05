"""Coverage for the POST /api/tripwires/{tid}/distribute HTTP route: the 404
branch and delegation to the service. The service's own failure-isolation
contract is already covered by test_deploy_isolation.py - this file only
checks the route wrapper (#200)."""


def test_distribute_unknown_tripwire_is_404(client_db):
    tc, _ = client_db
    resp = tc.post("/api/tripwires/does-not-exist/distribute")
    assert resp.status_code == 404


def test_distribute_with_no_deploy_integration_is_400(client_db):
    tc, _ = client_db
    tid = tc.post("/api/tripwires", json={
        "name": "distribute-bait", "token_type": "aws",
        "path": "~/.aws/credentials", "source": "template",
    }).json()["id"]

    resp = tc.post(f"/api/tripwires/{tid}/distribute")
    assert resp.status_code == 400
    assert "No deploy integration configured" in resp.json()["detail"]


def test_distribute_isolates_a_failing_plugin(client_db, monkeypatch):
    """Route-level check that a configured-but-failing deploy plugin still
    returns 200 with a per-plugin 'failed' result."""
    tc, db = client_db
    from thumper import store
    from thumper.services import deploy as deploy_svc

    store.upsert_integration(db, plugin="ssh", kind="deploy", config={})

    class Boom:
        def deploy(self, install, targets):
            raise RuntimeError("ssh unreachable")

    monkeypatch.setattr(deploy_svc, "load_plugin", lambda name, config: Boom())

    tid = tc.post("/api/tripwires", json={
        "name": "distribute-bait-2", "token_type": "aws",
        "path": "~/.aws/credentials", "source": "template",
    }).json()["id"]

    resp = tc.post(f"/api/tripwires/{tid}/distribute")
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 1
    assert results[0]["plugin"] == "ssh"
    assert results[0]["state"] == "failed"
