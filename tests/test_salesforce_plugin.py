"""Salesforce honeytoken plugin against a faked httpx + jwt (no real org/key)."""
import importlib.util
from pathlib import Path

import pytest

from thumper.plugins.base import PluginError

PLUGIN_FILE = (Path(__file__).resolve().parents[1]
               / "plugins" / "honeytoken" / "salesforce" / "plugin.py")


def load_plugin_module():
    spec = importlib.util.spec_from_file_location("thumper_plugin_salesforce_test", PLUGIN_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text="", content_type="application/json"):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text
        self.headers = {"content-type": content_type}

    def json(self):
        return self._payload


class FakeHttpx:
    HTTPError = Exception

    def __init__(self, routes):
        self._routes = routes
        self.calls = []

    def _match(self, method, url):
        for (m, frag), resp in self._routes.items():
            if m == method and frag in url:
                return resp
        raise AssertionError(f"no fake route for {method} {url}")

    def post(self, url, data=None, timeout=None):
        self.calls.append(("POST", url, data))
        return self._match("POST", url)

    def request(self, method, url, headers=None, timeout=None, **kwargs):
        self.calls.append((method, url, kwargs))
        return self._match(method, url)


CONFIG = {
    "instance_url": "https://myorg.my.salesforce.com",
    "consumer_key": "ck", "username": "admin@example.com", "private_key": "PEM",
}

TOKEN_OK = FakeResponse(200, payload={"access_token": "at", "instance_url": CONFIG["instance_url"]})


@pytest.fixture
def module(monkeypatch):
    mod = load_plugin_module()
    # Sign with a stub so tests need no real RSA key.
    monkeypatch.setattr(mod.jwt, "encode", lambda payload, key, algorithm=None: "signed.jwt")
    return mod


def _install(module, monkeypatch, routes):
    fake = FakeHttpx(routes)
    monkeypatch.setattr(module, "httpx", fake)
    return fake


def test_connect_requires_all_config(module):
    with pytest.raises(PluginError):
        module.Plugin({"instance_url": "https://x"}).connect()


def test_connect_obtains_access_token(module, monkeypatch):
    _install(module, monkeypatch, {("POST", "/services/oauth2/token"): TOKEN_OK})
    plugin = module.Plugin(CONFIG)
    plugin.connect()
    assert plugin._access_token == "at"


def test_connect_raises_on_auth_failure(module, monkeypatch):
    _install(module, monkeypatch, {
        ("POST", "/services/oauth2/token"): FakeResponse(
            400, payload={"error_description": "invalid_grant"}),
    })
    with pytest.raises(PluginError) as exc:
        module.Plugin(CONFIG).connect()
    assert "invalid_grant" in str(exc.value)


def test_create_token_returns_connected_app_id(module, monkeypatch):
    _install(module, monkeypatch, {
        ("POST", "/services/oauth2/token"): TOKEN_OK,
        ("POST", "/tooling/sobjects/ConnectedApplication"): FakeResponse(
            201, payload={"id": "toolingId"}),
        ("GET", "/tooling/query"): FakeResponse(
            200, payload={"records": [{"Id": "0H4xx", "Name": "Thumper_Canary_c"}]}),
    })
    result = module.Plugin(CONFIG).create_token("c")
    assert result["token_id"] == "0H4xx"
    assert result["token_type"] == "connected_app"
    assert result["app_name"] == "Thumper_Canary_c"


def test_revoke_token_idempotent_on_404(module, monkeypatch):
    _install(module, monkeypatch, {
        ("POST", "/services/oauth2/token"): TOKEN_OK,
        ("DELETE", "/tooling/sobjects/ConnectedApplication/"): FakeResponse(404),
    })
    module.Plugin(CONFIG).revoke_token("0H4xx")  # no raise


def test_poll_usage_collects_login_and_oauth_events(module, monkeypatch):
    login = FakeResponse(200, payload={"records": [{
        "Id": "login-1", "UserId": "005xx", "LoginTime": "2026-07-21T10:00:00.000+0000",
        "SourceIp": "10.0.0.9", "LoginType": "Application",
    }]})
    oauth = FakeResponse(200, payload={"records": [{
        "Id": "oauth-1", "AppName": "app", "LastUsedDate": "2026-07-21T11:00:00.000+0000",
        "UseCount": 3, "UserId": "005xx",
    }]})

    # /query serves LoginHistory first, then OAuthToken - route by call order.
    seq = [login, oauth]

    class Seq(FakeHttpx):
        def request(self, method, url, headers=None, timeout=None, **kwargs):
            self.calls.append((method, url))
            if method == "POST":
                return TOKEN_OK
            return seq.pop(0)

    fake = Seq({})
    monkeypatch.setattr(module, "httpx", fake)
    plugin = module.Plugin(CONFIG)
    plugin._access_token = "at"
    plugin._instance_url = CONFIG["instance_url"]
    events = plugin.poll_usage(["app"])
    assert len(events) == 2
    assert events[0].source_ip == "10.0.0.9"
    assert events[0].extra["event_id"] == "login-1"
    assert events[1].extra["event_id"] == "oauth_oauth-1"
