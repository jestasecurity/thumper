"""Integration config is encrypted at rest when THUMPER_SECRET_KEY is set, with
a plaintext fallback and decrypt-or-passthrough reads (#24)."""
import json

import pytest

from thumper import config
from thumper.services import secrets_crypto as sc
from thumper.services.secrets_crypto import (
    ConfigDecryptError, pack_config, unpack_config)

SECRET = {"hec_url": "https://splunk.example", "hec_token": "super-secret-token"}


def test_roundtrip_with_key(monkeypatch):
    monkeypatch.setattr(config, "SECRET_KEY", "k-1")
    stored = pack_config(SECRET)
    assert stored.startswith("fernet:")
    assert "super-secret-token" not in stored      # opaque at rest
    assert unpack_config(stored) == SECRET


def test_plaintext_fallback_without_key(monkeypatch):
    monkeypatch.setattr(config, "SECRET_KEY", None)
    stored = pack_config(SECRET)
    assert stored == json.dumps(SECRET)            # plaintext
    assert unpack_config(stored) == SECRET


def test_legacy_plaintext_reads_even_with_key(monkeypatch):
    monkeypatch.setattr(config, "SECRET_KEY", None)
    legacy = pack_config(SECRET)                    # plaintext row
    monkeypatch.setattr(config, "SECRET_KEY", "k-1")  # key added later
    assert unpack_config(legacy) == SECRET          # passthrough still works


def test_wrong_key_raises(monkeypatch):
    monkeypatch.setattr(config, "SECRET_KEY", "right-key")
    stored = pack_config(SECRET)
    monkeypatch.setattr(config, "SECRET_KEY", "different-key")
    with pytest.raises(ConfigDecryptError):
        unpack_config(stored)


def test_encrypted_but_key_missing_raises(monkeypatch):
    monkeypatch.setattr(config, "SECRET_KEY", "k-1")
    stored = pack_config(SECRET)
    monkeypatch.setattr(config, "SECRET_KEY", None)
    with pytest.raises(ConfigDecryptError):
        unpack_config(stored)


def test_list_integrations_survives_undecryptable_row(monkeypatch, client_db):
    # A row encrypted under a key that's since changed must not 500 the whole
    # list - the integration is surfaced as unreadable, others still render.
    tc, db = client_db
    monkeypatch.setattr(config, "SECRET_KEY", "old-key")
    assert tc.post("/api/integrations/webhook",
                   json={"url": "https://hooks.example/x", "signing_secret": "shhh"}
                   ).status_code == 200
    monkeypatch.setattr(config, "SECRET_KEY", "rotated-key")  # old row now opaque

    resp = tc.get("/api/integrations")
    assert resp.status_code == 200                            # not a 500
    webhook = next(i for i in resp.json() if i["plugin"] == "webhook")
    assert webhook["configured"] is True
    assert webhook["config"] == {}                            # secrets not leaked
    assert webhook["last_test_status"] == "failed"
    assert "decrypt" in (webhook["last_test_error"] or "").lower()


def test_save_integration_encrypts_in_db(monkeypatch, client_db):
    monkeypatch.setattr(config, "SECRET_KEY", "k-1")
    tc, db = client_db
    resp = tc.post("/api/integrations/webhook",
                   json={"url": "https://hooks.example/x", "signing_secret": "shhh"})
    assert resp.status_code == 200
    from thumper.db import Integration
    row = db.query(Integration).filter(Integration.plugin == "webhook").first()
    assert row.config_json.startswith("fernet:")
    assert "shhh" not in row.config_json           # secret not readable at rest
    # ...but the API still round-trips the real config to plugins
    assert sc.unpack_config(row.config_json)["signing_secret"] == "shhh"
