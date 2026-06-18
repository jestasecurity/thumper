import importlib.util
import json
from pathlib import Path

import httpx
import pytest

from thumper.plugins.base import PluginError
from thumper.services import signing

PLUGIN_FILE = Path(__file__).resolve().parents[1] / "plugins" / "alert" / "webhook" / "plugin.py"


def load_plugin_module():
    spec = importlib.util.spec_from_file_location("thumper_plugin_webhook_test", PLUGIN_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://recv")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(f"HTTP {self.status_code}", request=request, response=response)


class FakeHttpx:
    def __init__(self, status_code=200):
        self.calls = []
        self._status = status_code

    def post(self, url, content=None, headers=None, timeout=None):
        self.calls.append({"url": url, "content": content, "headers": headers, "timeout": timeout})
        return FakeResponse(self._status)


EVENT = {"alert_id": "al_1", "tripwire_name": "aws-creds", "process": "node (pid 8841)"}


@pytest.fixture
def module(monkeypatch):
    mod = load_plugin_module()
    monkeypatch.setattr(mod, "_now_unix", lambda: 1749369600)
    # These tests use a non-resolvable fake host ("recv") and only exercise
    # signing/headers - neutralize the SSRF guard (covered in test_ssrf.py).
    monkeypatch.setattr(mod, "assert_url_allowed", lambda url: None)
    return mod


def test_missing_url_raises(module):
    plugin = module.Plugin({})
    with pytest.raises(PluginError):
        plugin.alert(EVENT)


def test_unsigned_post_has_no_signature_headers(module, monkeypatch):
    fake = FakeHttpx()
    monkeypatch.setattr(module, "httpx", fake)
    module.Plugin({"url": "http://recv"}).alert(EVENT)

    call = fake.calls[0]
    assert call["url"] == "http://recv"
    assert json.loads(call["content"]) == EVENT
    assert "X-Thumper-Signature" not in call["headers"]
    assert "X-Thumper-Timestamp" not in call["headers"]


def test_signed_post_sets_both_headers_with_valid_signature(module, monkeypatch):
    fake = FakeHttpx()
    monkeypatch.setattr(module, "httpx", fake)
    module.Plugin({"url": "http://recv", "signing_secret": "s3cr3t"}).alert(EVENT)

    call = fake.calls[0]
    assert call["headers"]["X-Thumper-Timestamp"] == "1749369600"
    body = call["content"]
    expected = signing.sign_timestamped("s3cr3t", 1749369600, body)
    assert call["headers"]["X-Thumper-Signature"] == expected


def test_non_2xx_raises(module, monkeypatch):
    monkeypatch.setattr(module, "httpx", FakeHttpx(status_code=500))
    with pytest.raises(httpx.HTTPStatusError):
        module.Plugin({"url": "http://recv"}).alert(EVENT)
