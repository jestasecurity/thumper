"""Datadog honeytoken plugin: create/revoke/poll against a faked httpx."""
import importlib.util
from pathlib import Path

import pytest

from thumper.plugins.base import PluginError

PLUGIN_FILE = (Path(__file__).resolve().parents[1]
               / "plugins" / "honeytoken" / "datadog" / "plugin.py")


def load_plugin_module():
    spec = importlib.util.spec_from_file_location("thumper_plugin_datadog_test", PLUGIN_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class FakeHttpx:
    """Routes by (method, url-substring) to a queued FakeResponse, recording calls."""
    HTTPError = Exception  # so `except module.httpx.HTTPError` works when swapped in

    def __init__(self, routes):
        self._routes = routes
        self.calls = []

    def _match(self, method, url):
        for (m, frag), resp in self._routes.items():
            if m == method and frag in url:
                return resp
        raise AssertionError(f"no fake route for {method} {url}")

    def get(self, url, headers=None, timeout=None):
        self.calls.append(("GET", url))
        return self._match("GET", url)

    def post(self, url, headers=None, timeout=None, json=None):
        self.calls.append(("POST", url, json))
        return self._match("POST", url)

    def delete(self, url, headers=None, timeout=None):
        self.calls.append(("DELETE", url))
        return self._match("DELETE", url)


CONFIG = {"site": "datadoghq.com", "api_key": "k", "app_key": "a"}


@pytest.fixture
def module():
    return load_plugin_module()


def _install(module, monkeypatch, routes):
    fake = FakeHttpx(routes)
    monkeypatch.setattr(module, "httpx", fake)
    return fake


def test_connect_requires_config(module):
    with pytest.raises(PluginError):
        module.Plugin({"site": "datadoghq.com"}).connect()  # missing keys


def test_connect_validates(module, monkeypatch):
    fake = _install(module, monkeypatch, {("GET", "/v1/validate"): FakeResponse(200)})
    module.Plugin(CONFIG).connect()
    assert fake.calls[0] == ("GET", "https://api.datadoghq.com/api/v1/validate")


def test_connect_raises_on_auth_failure(module, monkeypatch):
    _install(module, monkeypatch, {("GET", "/v1/validate"): FakeResponse(403, text="forbidden")})
    with pytest.raises(PluginError):
        module.Plugin(CONFIG).connect()


def test_create_token_returns_id_and_metadata(module, monkeypatch):
    _install(module, monkeypatch, {
        ("GET", "/v1/validate"): FakeResponse(200),
        ("POST", "/v2/api_keys"): FakeResponse(201, payload={"data": {
            "id": "key-123",
            "attributes": {"name": "canary", "key": "ddsecret"},
        }}),
    })
    result = module.Plugin(CONFIG).create_token("canary")
    assert result["token_id"] == "key-123"
    assert result["token_type"] == "api_key"
    assert result["key_value"] == "ddsecret"


def test_create_token_raises_on_error(module, monkeypatch):
    _install(module, monkeypatch, {
        ("GET", "/v1/validate"): FakeResponse(200),
        ("POST", "/v2/api_keys"): FakeResponse(400, text="bad"),
    })
    with pytest.raises(PluginError):
        module.Plugin(CONFIG).create_token("canary")


def test_revoke_token_treats_404_as_success(module, monkeypatch):
    _install(module, monkeypatch, {
        ("GET", "/v1/validate"): FakeResponse(200),
        ("DELETE", "/v2/api_keys/"): FakeResponse(404),
    })
    module.Plugin(CONFIG).revoke_token("key-123")  # does not raise


def test_poll_usage_emits_event_when_used(module, monkeypatch):
    _install(module, monkeypatch, {
        ("GET", "/v1/validate"): FakeResponse(200),
        ("GET", "/v2/api_keys/key-1"): FakeResponse(200, payload={"data": {"attributes": {
            "used_in_last_24_hours": True,
            "date_last_used": "2026-07-21T10:00:00Z",
        }}}),
    })
    events = module.Plugin(CONFIG).poll_usage(["key-1"])
    assert len(events) == 1
    assert events[0].token_id == "key-1"
    assert events[0].timestamp == "2026-07-21T10:00:00Z"
    assert events[0].extra["event_id"] == "usage_key-1_2026-07-21T10:00:00Z"


def test_poll_usage_ignores_unused_keys(module, monkeypatch):
    _install(module, monkeypatch, {
        ("GET", "/v1/validate"): FakeResponse(200),
        ("GET", "/v2/api_keys/key-1"): FakeResponse(200, payload={"data": {"attributes": {
            "used_in_last_24_hours": False,
        }}}),
    })
    assert module.Plugin(CONFIG).poll_usage(["key-1"]) == []
