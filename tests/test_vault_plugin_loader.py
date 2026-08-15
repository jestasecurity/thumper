import pytest
import yaml

from thumper.plugins import loader


@pytest.fixture(autouse=True)
def _clear_cache():
    loader.reset_cache()
    yield
    loader.reset_cache()


@pytest.fixture
def vault_plugin_dir(tmp_path, monkeypatch):
    """Create a minimal vault plugin under a temp PLUGINS_DIR."""
    monkeypatch.setattr(loader, "PLUGINS_DIR", tmp_path)
    vault_dir = tmp_path / "vault" / "fakevault"
    vault_dir.mkdir(parents=True)
    (vault_dir / "manifest.yaml").write_text(yaml.dump({
        "name": "fakevault",
        "kind": "vault",
        "display_name": "Fake Vault",
        "version": "0.1.0",
        "author": "test",
        "description": "A test vault plugin",
        "config_schema": [
            {"key": "url", "label": "Vault URL", "type": "string", "required": True},
        ],
    }))
    (vault_dir / "plugin.py").write_text(
        "from thumper.plugins.base import VaultPlugin\n"
        "class Plugin(VaultPlugin):\n"
        "    def connect(self): pass\n"
        "    def plant(self, path, value, metadata): pass\n"
        "    def delete(self, path): pass\n"
        "    def poll(self, paths, since=None): return []\n"
    )
    return vault_dir


def test_discover_finds_vault_plugin(vault_plugin_dir):
    manifests = loader.discover_manifests()
    names = [m["name"] for m in manifests]
    assert "fakevault" in names


def test_discovered_vault_manifest_has_kind(vault_plugin_dir):
    manifests = loader.discover_manifests()
    fake = next(m for m in manifests if m["name"] == "fakevault")
    assert fake["kind"] == "vault"


def test_load_vault_plugin(vault_plugin_dir):
    plugin = loader.load_plugin("fakevault", {"url": "http://localhost:8200"})
    for method in ("connect", "plant", "delete", "poll"):
        assert hasattr(plugin, method)


def test_vault_plugin_poll_returns_list(vault_plugin_dir):
    plugin = loader.load_plugin("fakevault", {"url": "http://localhost:8200"})
    assert plugin.poll(["/secret/test"]) == []
