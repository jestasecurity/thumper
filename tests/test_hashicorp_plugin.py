import importlib.util
from pathlib import Path

import pytest

from thumper.plugins.base import AccessEvent, PluginError

PLUGIN_FILE = Path(__file__).resolve().parents[1] / "plugins" / "vault" / "hashicorp" / "plugin.py"


def load_plugin_module():
    spec = importlib.util.spec_from_file_location("thumper_plugin_hashicorp_test", PLUGIN_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeKVv2:
    def __init__(self):
        self.created = []
        self.deleted = []

    def create_or_update_secret(self, path, secret, mount_point=None):
        self.created.append({"path": path, "secret": secret, "mount_point": mount_point})

    def delete_metadata_and_all_versions(self, path, mount_point=None):
        self.deleted.append({"path": path, "mount_point": mount_point})


class FakeAuditLogs:
    def __init__(self, entries=None):
        self.entries = entries or []

    def list_enabled_audit_devices(self):
        return {"data": {"file/": {"type": "file", "options": {"file_path": "/tmp/audit.log"}}}}


class FakeAuth:
    def __init__(self):
        self.token = "s.faketoken"

    class approle:
        @staticmethod
        def login(role_id, secret_id):
            return {"auth": {"client_token": "s.faketoken"}}


class FakeHvacClient:
    def __init__(self, url=None, token=None, namespace=None):
        self.url = url
        self.token = token
        self.namespace = namespace
        self.secrets = type("secrets", (), {"kv": type("kv", (), {"v2": FakeKVv2()})()})()
        self.sys = FakeAuditLogs()
        self.auth = FakeAuth()
        self._is_authenticated = True

    def is_authenticated(self):
        return self._is_authenticated


@pytest.fixture
def module(monkeypatch):
    mod = load_plugin_module()
    monkeypatch.setattr(mod, "hvac", type("hvac", (), {"Client": FakeHvacClient}))
    return mod


def test_connect_succeeds(module):
    plugin = module.Plugin({
        "url": "http://vault:8200",
        "mount": "secret",
        "role_id": "role123",
        "secret_id": "secret456",
    })
    plugin.connect()
    assert plugin._client is not None


def test_connect_fails_without_url(module):
    plugin = module.Plugin({"mount": "secret", "role_id": "r", "secret_id": "s"})
    with pytest.raises(PluginError, match="url"):
        plugin.connect()


def test_plant_writes_secret(module):
    plugin = module.Plugin({
        "url": "http://vault:8200",
        "mount": "secret",
        "role_id": "r",
        "secret_id": "s",
    })
    plugin.connect()
    plugin.plant("production/stripe/key", "sk_live_fake", {"created_by": "terraform"})
    kv = plugin._client.secrets.kv.v2
    assert len(kv.created) == 1
    assert kv.created[0]["path"] == "production/stripe/key"
    assert kv.created[0]["secret"]["value"] == "sk_live_fake"
    assert kv.created[0]["secret"]["created_by"] == "terraform"


def test_delete_removes_secret(module):
    plugin = module.Plugin({
        "url": "http://vault:8200",
        "mount": "secret",
        "role_id": "r",
        "secret_id": "s",
    })
    plugin.connect()
    plugin.delete("production/stripe/key")
    kv = plugin._client.secrets.kv.v2
    assert len(kv.deleted) == 1
    assert kv.deleted[0]["path"] == "production/stripe/key"


def test_poll_returns_empty_when_no_reads(module, monkeypatch):
    plugin = module.Plugin({
        "url": "http://vault:8200",
        "mount": "secret",
        "role_id": "r",
        "secret_id": "s",
    })
    plugin.connect()
    monkeypatch.setattr(plugin, "_fetch_audit_entries", lambda: [])
    events = plugin.poll(["production/stripe/key"])
    assert events == []


def test_poll_returns_access_events(module, monkeypatch):
    plugin = module.Plugin({
        "url": "http://vault:8200",
        "mount": "secret",
        "role_id": "r",
        "secret_id": "s",
    })
    plugin.connect()
    monkeypatch.setattr(plugin, "_fetch_audit_entries", lambda: [
        {
            "type": "response",
            "time": "2026-06-22T10:00:00Z",
            "request": {
                "path": "secret/data/production/stripe/key",
                "operation": "read",
            },
            "auth": {
                "display_name": "approle-canary-reader",
                "policies": ["default", "reader"],
                "metadata": {"role_name": "canary-reader"},
            },
            "request_metadata": {
                "remote_address": "10.0.0.5",
            },
        },
    ])
    events = plugin.poll(["production/stripe/key"])
    assert len(events) == 1
    assert isinstance(events[0], AccessEvent)
    assert events[0].path == "production/stripe/key"
    assert events[0].accessor == "approle-canary-reader"
    assert events[0].source_ip == "10.0.0.5"
