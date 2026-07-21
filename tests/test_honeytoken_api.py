import pytest
import yaml

from thumper import store
from thumper.plugins import loader


@pytest.fixture(autouse=True)
def _clear_plugin_cache():
    loader.reset_cache()
    yield
    loader.reset_cache()


@pytest.fixture
def honeytoken_plugin_dir(tmp_path, monkeypatch):
    """A fake honeytoken plugin so the API's create/test/revoke paths run without
    reaching any real SaaS platform."""
    monkeypatch.setattr(loader, "PLUGINS_DIR", tmp_path)
    d = tmp_path / "honeytoken" / "datadog"
    d.mkdir(parents=True)
    d.joinpath("manifest.yaml").write_text(yaml.dump({
        "name": "datadog",
        "kind": "honeytoken",
        "display_name": "Datadog",
        "version": "0.1.0",
        "author": "test",
        "description": "Test Datadog honeytokens",
        "config_schema": [
            {"key": "api_key", "label": "API Key", "type": "secret", "required": True},
            {"key": "app_key", "label": "App Key", "type": "secret", "required": True},
        ],
    }))
    d.joinpath("plugin.py").write_text(
        "from thumper.plugins.base import HoneytokenPlugin\n"
        "class Plugin(HoneytokenPlugin):\n"
        "    def connect(self):\n"
        "        if not self.config.get('api_key'): raise ValueError('api_key required')\n"
        "    def create_token(self, name, options=None):\n"
        "        return {'token_id': 'ddog_key_1', 'token_type': 'datadog_api_key',\n"
        "                'key_id': 'abc123'}\n"
        "    def revoke_token(self, token_id): pass\n"
        "    def poll_usage(self, token_ids, since=None): return []\n"
    )
    return d


def _make_connection(tc, db, configured=True):
    vid = tc.post("/api/honeytokens/connections", json={
        "name": "Prod Datadog", "plugin": "datadog",
        "config": {"api_key": "k", "app_key": "a"}}).json()["id"]
    if configured:
        store.set_honeytoken_connection_test(db, hid=vid, configured=True)
    return vid


def test_create_connection_masks_secrets(client_db, honeytoken_plugin_dir):
    tc, db = client_db
    resp = tc.post("/api/honeytokens/connections", json={
        "name": "Prod", "plugin": "datadog",
        "config": {"api_key": "supersecret", "app_key": "a"}})
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"].startswith("htc_")
    assert data["config"]["api_key"] == "••••••••"


def test_create_connection_rejects_unknown_plugin(client_db, honeytoken_plugin_dir):
    tc, db = client_db
    resp = tc.post("/api/honeytokens/connections", json={
        "name": "X", "plugin": "nope", "config": {}})
    assert resp.status_code == 400


def test_test_connection_sets_configured(client_db, honeytoken_plugin_dir):
    tc, db = client_db
    vid = _make_connection(tc, db, configured=False)
    resp = tc.post(f"/api/honeytokens/connections/{vid}/test")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert store.get_honeytoken_connection(db, vid).configured is True


def test_create_token_requires_configured_connection(client_db, honeytoken_plugin_dir):
    tc, db = client_db
    vid = _make_connection(tc, db, configured=False)
    resp = tc.post("/api/honeytokens/tokens", json={
        "connection_id": vid, "name": "canary"})
    assert resp.status_code == 400


def test_create_and_list_token(client_db, honeytoken_plugin_dir):
    tc, db = client_db
    vid = _make_connection(tc, db)
    resp = tc.post("/api/honeytokens/tokens", json={
        "connection_id": vid, "name": "canary-key"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["token_id"] == "ddog_key_1"
    assert data["token_type"] == "datadog_api_key"
    assert data["state"] == "active"
    assert data["metadata"]["key_id"] == "abc123"
    listing = tc.get("/api/honeytokens/tokens").json()
    assert len(listing) == 1
    assert listing[0]["connection_name"] == "Prod Datadog"


def test_delete_token(client_db, honeytoken_plugin_dir):
    tc, db = client_db
    vid = _make_connection(tc, db)
    htid = tc.post("/api/honeytokens/tokens", json={
        "connection_id": vid, "name": "k"}).json()["id"]
    assert tc.delete(f"/api/honeytokens/tokens/{htid}").status_code == 200
    assert tc.get("/api/honeytokens/tokens").json() == []


def test_usage_logs_endpoint(client_db, honeytoken_plugin_dir):
    tc, db = client_db
    vid = _make_connection(tc, db)
    htid = tc.post("/api/honeytokens/tokens", json={
        "connection_id": vid, "name": "k"}).json()["id"]
    store.record_honeytoken_usage(db, htid=htid, event_id="e1", actor="mallory",
                                  source_ip="10.0.0.9", action="query", timestamp="t")
    logs = tc.get(f"/api/honeytokens/tokens/{htid}/usage").json()
    assert len(logs) == 1
    assert logs[0]["actor"] == "mallory"
    assert logs[0]["source_ip"] == "10.0.0.9"


def test_usage_logs_404_for_unknown_token(client_db):
    tc, db = client_db
    assert tc.get("/api/honeytokens/tokens/ht_nope/usage").status_code == 404
