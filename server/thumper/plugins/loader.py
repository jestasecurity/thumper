"""Discover and instantiate plugins from the filesystem.

Drop a directory with a manifest.yaml + plugin.py into plugins/{deploy,alert}/
and it shows up - no registration code, no imports to edit.

Discovery and module loading are cached: the plugin set is fixed at process
start, so re-walking the tree and re-exec'ing plugin modules on every request is
pure waste. `reset_cache()` clears both (used by tests).
"""
import importlib.util
from pathlib import Path

import yaml

from ..config import PLUGINS_DIR

_KINDS = ("deploy", "alert", "honeytoken")

_manifest_cache: list[dict] | None = None
_module_cache: dict[str, object] = {}


def reset_cache() -> None:
    """Drop cached manifests and loaded plugin modules (mainly for tests)."""
    global _manifest_cache
    _manifest_cache = None
    _module_cache.clear()


def discover_manifests() -> list[dict]:
    """Return every plugin manifest (with an injected `_dir`), sorted by kind/name.

    Cached after the first walk - see module docstring."""
    global _manifest_cache
    if _manifest_cache is not None:
        return _manifest_cache
    manifests: list[dict] = []
    for kind in _KINDS:
        base = PLUGINS_DIR / kind
        if not base.is_dir():
            continue
        for plugin_dir in sorted(base.iterdir()):
            manifest_file = plugin_dir / "manifest.yaml"
            if not manifest_file.is_file():
                continue
            data = yaml.safe_load(manifest_file.read_text()) or {}
            data.setdefault("kind", kind)
            data["_dir"] = str(plugin_dir)
            manifests.append(data)
    _manifest_cache = manifests
    return manifests


def public_manifests() -> list[dict]:
    """Manifests with internal fields stripped - safe to return over the API."""
    return [{k: v for k, v in m.items() if not k.startswith("_")} for m in discover_manifests()]


def get_manifest(name: str) -> dict | None:
    return next((m for m in discover_manifests() if m.get("name") == name), None)


def load_plugin(name: str, config: dict):
    """Import <plugin>/plugin.py and instantiate its `Plugin` class with `config`.

    The module is imported once and cached - a fresh `Plugin(config)` instance is
    returned each call, but the module isn't re-exec'd on every request."""
    module = _module_cache.get(name)
    if module is None:
        manifest = get_manifest(name)
        if manifest is None:
            raise KeyError(f"unknown plugin: {name!r}")
        plugin_file = Path(manifest["_dir"]) / "plugin.py"
        spec = importlib.util.spec_from_file_location(f"thumper_plugin_{name}", plugin_file)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {plugin_file}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, "Plugin"):
            raise ImportError(f"{plugin_file} does not define a `Plugin` class")
        _module_cache[name] = module
    return module.Plugin(config)
