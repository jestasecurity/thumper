"""GET /api/install?tripwire=A&tripwire=B - build one install command for a set
of tripwires (SP1 of #34). The single-tripwire path (build_install, used by
TripwireDetail + the deploy plugins) must stay byte-for-byte unchanged.
"""
from thumper import store


def _mk(db, name, path="~/.aws/credentials"):
    return store.create_tripwire(db, name=name, token_type="aws", path=path,
                                 token=f"bait-{name}")


def test_builds_command_for_multiple_tripwires(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    b = _mk(db, "npm", "~/.npmrc")

    resp = tc.get(f"/api/install?tripwire={a.id}&tripwire={b.id}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["tripwire_ids"] == [a.id, b.id]
    assert f"tripwire={a.id}" in body["command"]
    assert f"tripwire={b.id}" in body["command"]
    assert "token=" in body["command"]
    assert "install.sh" in body["command"]


def test_no_tripwire_param_is_400(client_db):
    tc, _ = client_db
    assert tc.get("/api/install").status_code == 400


def test_unknown_tripwire_is_400(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    resp = tc.get(f"/api/install?tripwire={a.id}&tripwire=tw_nope")
    assert resp.status_code == 400
    assert "tw_nope" in resp.json()["detail"]


def test_inactive_tripwire_is_400(client_db):
    tc, db = client_db
    a = _mk(db, "aws")
    inactive = _mk(db, "old", "~/.netrc")
    inactive.active = False
    db.commit()

    resp = tc.get(f"/api/install?tripwire={a.id}&tripwire={inactive.id}")
    assert resp.status_code == 400
    assert inactive.id in resp.json()["detail"]


def test_single_tripwire_install_command_unchanged(client_db):
    """Regression: TripwireDetail's per-tripwire command still builds the same."""
    tc, db = client_db
    a = _mk(db, "aws")

    detail = tc.get(f"/api/tripwires/{a.id}").json()
    multi = tc.get(f"/api/install?tripwire={a.id}").json()

    assert detail["install"]["command"] == multi["command"]


def test_enroll_with_two_tripwires_materializes_two_deployments(client_db):
    """Guards the end-to-end claim that one agent gets one deployment per tripwire."""
    tc, db = client_db
    a = _mk(db, "aws")
    b = _mk(db, "npm", "~/.npmrc")

    resp = tc.post("/api/enroll", data={
        "enroll_token": "dev-enroll-token", "hostname": "h", "machine_id": "m1",
        "platform": "darwin", "tripwire_ids": f"{a.id},{b.id}",
    })
    assert resp.status_code == 200
    eid = [ln for ln in resp.text.splitlines() if ln.startswith("endpoint_id=")][0].split("=", 1)[1]
    assert len(store.list_deployments_for_endpoint(db, eid)) == 2


def test_install_script_autoinstalls_inotify_tools(client_db):
    """The bootstrap installer should ensure inotify-tools on Linux across the
    main package managers, so read detection works without a manual step (#3/#7)."""
    tc, _ = client_db
    resp = tc.get("/api/install.sh", params={"token": "dev-install-token", "tripwire": "tw_x"})
    assert resp.status_code == 200
    s = resp.text
    assert "inotify-tools" in s
    assert 'uname -s' in s          # gated to Linux
    for pm in ("apt-get", "dnf", "yum", "zypper", "apk", "pacman"):
        assert pm in s, f"missing package manager {pm}"
