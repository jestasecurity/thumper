from thumper import store


def test_save_integration_rejects_unknown_key(client_db):
    tc, db = client_db
    resp = tc.post("/api/integrations/webhook", json={
        "url": "http://127.0.0.1/x", "admin": True,
    })
    assert resp.status_code == 400
    assert "admin" in resp.json()["detail"]
    db.expire_all()
    assert store.get_integration(db, "webhook") is None


def test_save_integration_accepts_only_schema_keys(client_db):
    tc, db = client_db
    resp = tc.post("/api/integrations/webhook", json={
        "url": "http://127.0.0.1/x", "signing_secret": "s3cr3t",
    })
    assert resp.status_code == 200
    db.expire_all()
    row = store.get_integration(db, "webhook")
    assert row is not None


def test_save_integration_rejects_oversized_value(client_db):
    tc, db = client_db
    resp = tc.post("/api/integrations/webhook", json={
        "url": "http://127.0.0.1/x" + "a" * 5000,
    })
    assert resp.status_code == 400
    assert "exceeds max length" in resp.json()["detail"]
    db.expire_all()
    assert store.get_integration(db, "webhook") is None


def test_save_integration_unknown_key_does_not_leak_into_existing_config(client_db):
    """A rejected request must not partially merge - the existing saved config
    (e.g. a previously-set secret) must be untouched."""
    tc, db = client_db
    tc.post("/api/integrations/webhook", json={
        "url": "http://127.0.0.1/x", "signing_secret": "original-secret",
    })

    resp = tc.post("/api/integrations/webhook", json={
        "url": "http://127.0.0.1/y", "extra_field": "smuggled",
    })

    assert resp.status_code == 400
    db.expire_all()
    row = store.get_integration(db, "webhook")
    from thumper.services.secrets_crypto import unpack_config
    saved = unpack_config(row.config_json)
    assert saved["url"] == "http://127.0.0.1/x"
    assert "extra_field" not in saved


def test_save_integration_unknown_plugin_still_404s_before_validation(client_db):
    tc, _ = client_db
    resp = tc.post("/api/integrations/nope", json={"anything": "x"})
    assert resp.status_code == 404
