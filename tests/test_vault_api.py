import pytest
import yaml

from thumper.plugins import loader
from thumper import store


@pytest.fixture(autouse=True)
def _clear_plugin_cache():
    loader.reset_cache()
    yield
    loader.reset_cache()


@pytest.fixture
def vault_plugin_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "PLUGINS_DIR", tmp_path)
    vault_dir = tmp_path / "vault" / "hashicorp"
    vault_dir.mkdir(parents=True)
    (vault_dir / "manifest.yaml").write_text(yaml.dump({
        "name": "hashicorp",
        "kind": "vault",
        "display_name": "HashiCorp Vault",
        "version": "0.1.0",
        "author": "test",
        "description": "Test vault",
        "config_schema": [
            {"key": "url", "label": "Vault URL", "type": "string", "required": True},
            {"key": "secret_id", "label": "Secret ID", "type": "secret", "required": True},
        ],
    }))
    (vault_dir / "plugin.py").write_text(
        "from thumper.plugins.base import VaultPlugin, PluginError\n"
        "class Plugin(VaultPlugin):\n"
        "    def connect(self):\n"
        "        if not self.config.get('url'): raise PluginError('url required')\n"
        "    def plant(self, path, value, metadata): pass\n"
        "    def delete(self, path): pass\n"
        "    def poll(self, paths): return []\n"
    )
    return vault_dir


def test_create_vault_connection(client_db, vault_plugin_dir):
    tc, db = client_db
    resp = tc.post("/api/vault/connections", json={
        "name": "Prod Vault", "plugin": "hashicorp",
        "config": {"url": "http://vault:8200", "secret_id": "abc"},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Prod Vault"
    assert data["id"].startswith("vc_")
    assert data["config"]["secret_id"] == "••••••••"


def test_list_vault_connections(client_db, vault_plugin_dir):
    tc, db = client_db
    tc.post("/api/vault/connections", json={
        "name": "A", "plugin": "hashicorp", "config": {"url": "http://a"}})
    tc.post("/api/vault/connections", json={
        "name": "B", "plugin": "hashicorp", "config": {"url": "http://b"}})
    resp = tc.get("/api/vault/connections")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_update_vault_connection(client_db, vault_plugin_dir):
    tc, db = client_db
    create = tc.post("/api/vault/connections", json={
        "name": "Old", "plugin": "hashicorp", "config": {"url": "http://old"}})
    vid = create.json()["id"]
    resp = tc.put(f"/api/vault/connections/{vid}", json={
        "name": "New", "config": {"url": "http://new"}})
    assert resp.status_code == 200
    assert resp.json()["name"] == "New"


def test_delete_vault_connection(client_db, vault_plugin_dir):
    tc, db = client_db
    create = tc.post("/api/vault/connections", json={
        "name": "Doomed", "plugin": "hashicorp", "config": {"url": "http://x"}})
    vid = create.json()["id"]
    resp = tc.delete(f"/api/vault/connections/{vid}")
    assert resp.status_code == 200
    assert tc.get("/api/vault/connections").json() == []


def test_test_vault_connection(client_db, vault_plugin_dir):
    tc, db = client_db
    create = tc.post("/api/vault/connections", json={
        "name": "Test", "plugin": "hashicorp",
        "config": {"url": "http://vault:8200", "secret_id": "s"}})
    vid = create.json()["id"]
    resp = tc.post(f"/api/vault/connections/{vid}/test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True


def test_list_templates(client_db):
    tc, db = client_db
    resp = tc.get("/api/vault/templates")
    assert resp.status_code == 200
    templates = resp.json()
    assert len(templates) >= 10
    slugs = {t["slug"] for t in templates}
    assert "stripe" in slugs


def test_create_canary_secret(client_db, vault_plugin_dir):
    tc, db = client_db
    create = tc.post("/api/vault/connections", json={
        "name": "Test", "plugin": "hashicorp",
        "config": {"url": "http://vault:8200", "secret_id": "s"}})
    vid = create.json()["id"]
    # Mark as configured
    store.set_vault_connection_test(db, vid=vid, configured=True)

    resp = tc.post("/api/vault/secrets", json={
        "vault_connection_id": vid,
        "template": "stripe",
        "path": "production/stripe/key",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["template"] == "stripe"
    assert data["state"] == "planted"


def test_list_canary_secrets(client_db, vault_plugin_dir):
    tc, db = client_db
    create = tc.post("/api/vault/connections", json={
        "name": "Test", "plugin": "hashicorp",
        "config": {"url": "http://vault:8200", "secret_id": "s"}})
    vid = create.json()["id"]
    store.set_vault_connection_test(db, vid=vid, configured=True)
    tc.post("/api/vault/secrets", json={
        "vault_connection_id": vid, "template": "stripe",
        "path": "production/stripe/key"})
    resp = tc.get("/api/vault/secrets")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_delete_canary_secret(client_db, vault_plugin_dir):
    tc, db = client_db
    create = tc.post("/api/vault/connections", json={
        "name": "Test", "plugin": "hashicorp",
        "config": {"url": "http://vault:8200", "secret_id": "s"}})
    vid = create.json()["id"]
    store.set_vault_connection_test(db, vid=vid, configured=True)
    create_secret = tc.post("/api/vault/secrets", json={
        "vault_connection_id": vid, "template": "stripe",
        "path": "production/stripe/key"})
    csid = create_secret.json()["id"]
    resp = tc.delete(f"/api/vault/secrets/{csid}")
    assert resp.status_code == 200
    assert tc.get("/api/vault/secrets").json() == []


def test_access_logs_404_for_unknown_secret(client_db):
    tc, db = client_db
    assert tc.get("/api/vault/secrets/cs_nope/access-logs").status_code == 404


def test_access_logs_lists_recorded_reads(client_db, vault_plugin_dir):
    tc, db = client_db
    create = tc.post("/api/vault/connections", json={
        "name": "Test", "plugin": "hashicorp",
        "config": {"url": "http://vault:8200", "secret_id": "s"}})
    vid = create.json()["id"]
    store.set_vault_connection_test(db, vid=vid, configured=True)
    csid = tc.post("/api/vault/secrets", json={
        "vault_connection_id": vid, "template": "stripe",
        "path": "production/stripe/key"}).json()["id"]

    # A read recorded by the poller must surface through the endpoint.
    store.record_canary_access(db, csid=csid, event_id="evt-1",
                               accessor="attacker", source_ip="10.0.0.5",
                               timestamp="2026-07-21T10:00:00Z")
    resp = tc.get(f"/api/vault/secrets/{csid}/access-logs")
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) == 1
    assert logs[0]["accessor"] == "attacker"
    assert logs[0]["source_ip"] == "10.0.0.5"
    assert logs[0]["event_id"] == "evt-1"
