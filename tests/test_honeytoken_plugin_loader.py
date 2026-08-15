"""The plugin loader is kind-agnostic; verify it discovers and instantiates a
`honeytoken`-kind plugin exactly like deploy/alert."""
import pytest
import yaml

from thumper.plugins import loader


@pytest.fixture(autouse=True)
def _clear_cache():
    loader.reset_cache()
    yield
    loader.reset_cache()


@pytest.fixture
def honeytoken_plugin_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "PLUGINS_DIR", tmp_path)
    d = tmp_path / "honeytoken" / "acme"
    d.mkdir(parents=True)
    (d / "manifest.yaml").write_text(yaml.dump({
        "name": "acme",
        "kind": "honeytoken",
        "display_name": "Acme SaaS",
        "version": "0.1.0",
        "author": "test",
        "description": "Test honeytoken provider",
        "config_schema": [
            {"key": "api_key", "label": "API Key", "type": "secret", "required": True},
        ],
    }))
    (d / "plugin.py").write_text(
        "from thumper.plugins.base import HoneytokenPlugin\n"
        "class Plugin(HoneytokenPlugin):\n"
        "    def connect(self):\n"
        "        if not self.config.get('api_key'): raise ValueError('api_key required')\n"
        "    def create_token(self, name, options=None):\n"
        "        return {'token_id': 'tok_1', 'token_type': 'acme_key'}\n"
        "    def revoke_token(self, token_id): pass\n"
        "    def poll_usage(self, token_ids, since=None): return []\n"
    )
    return d


def test_honeytoken_is_a_known_kind():
    assert "honeytoken" in loader._KINDS


def test_discover_finds_honeytoken_manifest(honeytoken_plugin_dir):
    manifests = loader.discover_manifests()
    acme = next((m for m in manifests if m["name"] == "acme"), None)
    assert acme is not None
    assert acme["kind"] == "honeytoken"


def test_public_manifests_strip_internal_fields(honeytoken_plugin_dir):
    acme = next(m for m in loader.public_manifests() if m["name"] == "acme")
    assert "_dir" not in acme
    assert acme["display_name"] == "Acme SaaS"


def test_load_plugin_instantiates_honeytoken(honeytoken_plugin_dir):
    plugin = loader.load_plugin("acme", {"api_key": "secret"})
    plugin.connect()  # does not raise
    created = plugin.create_token("prod-key")
    assert created["token_id"] == "tok_1"
    assert plugin.poll_usage(["tok_1"]) == []
