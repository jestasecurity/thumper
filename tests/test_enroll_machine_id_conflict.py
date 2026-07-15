"""POST /api/enroll must not let a holder of the shared ENROLL_TOKEN hijack an
existing endpoint by guessing its machine_id - re-enrolling an existing
machine_id requires that endpoint's current agent_token (#107)."""
from thumper import store

ENROLL_TOKEN = "dev-enroll-token"


def _enroll_raw(tc, machine_id, agent_token="", hostname="h1"):
    return tc.post("/api/enroll", data={
        "enroll_token": ENROLL_TOKEN, "hostname": hostname, "machine_id": machine_id,
        "platform": "linux", "tripwire_ids": "", "agent_token": agent_token,
    })


def test_fresh_machine_id_enrolls_without_agent_token(client_db):
    tc, db = client_db
    resp = _enroll_raw(tc, "new-machine-1")
    assert resp.status_code == 200
    assert "agent_token=" in resp.text


def test_reenroll_with_correct_agent_token_updates_hostname(client_db):
    tc, db = client_db
    first = _enroll_raw(tc, "m1", hostname="old-name")
    token = [ln for ln in first.text.splitlines()
             if ln.startswith("agent_token=")][0].split("=", 1)[1]

    resp = _enroll_raw(tc, "m1", agent_token=token, hostname="new-name")

    assert resp.status_code == 200
    db.expire_all()
    ep = db.query(store.Endpoint).filter(store.Endpoint.machine_id == "m1").first()
    assert ep.hostname == "new-name"


def test_reenroll_with_wrong_agent_token_is_409(client_db):
    tc, db = client_db
    _enroll_raw(tc, "m1", hostname="victim-host")

    resp = _enroll_raw(tc, "m1", agent_token="attacker-guessed-wrong-token",
                       hostname="attacker-controlled-name")

    assert resp.status_code == 409
    db.expire_all()
    ep = db.query(store.Endpoint).filter(store.Endpoint.machine_id == "m1").first()
    assert ep.hostname == "victim-host"


def test_reenroll_with_no_agent_token_is_409(client_db):
    """The actual attack: caller only has the shared ENROLL_TOKEN and a
    guessed/learned machine_id, no agent_token at all."""
    tc, db = client_db
    first = _enroll_raw(tc, "m1", hostname="victim-host")
    victim_token = [ln for ln in first.text.splitlines()
                    if ln.startswith("agent_token=")][0].split("=", 1)[1]

    resp = _enroll_raw(tc, "m1", agent_token="", hostname="attacker-controlled-name")

    assert resp.status_code == 409
    # The response must not hand back the victim's token either.
    assert victim_token not in resp.text
    db.expire_all()
    ep = db.query(store.Endpoint).filter(store.Endpoint.machine_id == "m1").first()
    assert ep.hostname == "victim-host"
    assert ep.agent_token == victim_token


def test_rejected_reenroll_does_not_reassign_tripwires(client_db):
    tc, db = client_db
    a = store.create_tripwire(db, name="aws", token_type="aws",
                              path="~/.aws/credentials", token="bait")
    _enroll_raw(tc, "m1")

    resp = tc.post("/api/enroll", data={
        "enroll_token": ENROLL_TOKEN, "hostname": "h", "machine_id": "m1",
        "platform": "linux", "tripwire_ids": a.id, "agent_token": "",
    })

    assert resp.status_code == 409
    db.expire_all()
    ep = db.query(store.Endpoint).filter(store.Endpoint.machine_id == "m1").first()
    assert store.list_deployments_for_endpoint(db, ep.id) == []