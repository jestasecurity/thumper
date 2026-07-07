"""Coverage for GET /api/manifests: public plugin manifests (#200)."""


def test_manifests_lists_known_plugins(client_db):
    tc, _ = client_db
    resp = tc.get("/api/manifests")
    assert resp.status_code == 200
    by_name = {m["name"]: m for m in resp.json()}
    assert by_name["webhook"]["kind"] == "alert"
    assert by_name["ssh"]["kind"] == "deploy"


def test_manifests_strips_internal_fields(client_db):
    tc, _ = client_db
    resp = tc.get("/api/manifests")
    for manifest in resp.json():
        assert not any(k.startswith("_") for k in manifest), \
            f"internal field leaked in manifest: {manifest}"
