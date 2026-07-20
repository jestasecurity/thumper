import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

from thumper.plugins.base import AccessEvent, PluginError

PLUGIN_FILE = (Path(__file__).resolve().parents[1]
               / "plugins" / "vault" / "aws" / "plugin.py")


def load_plugin_module():
    spec = importlib.util.spec_from_file_location(
        "thumper_plugin_aws_vault_test", PLUGIN_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeSecretsManager:
    def __init__(self):
        self.created = []
        self.deleted = []

    def list_secrets(self, MaxResults=None):
        return {"SecretList": []}

    def create_secret(self, Name, SecretString, Description=None, Tags=None):
        self.created.append({"Name": Name, "SecretString": SecretString,
                             "Tags": Tags})

    def delete_secret(self, SecretId, ForceDeleteWithoutRecovery=None):
        self.deleted.append(SecretId)


class FakePaginator:
    def __init__(self, events):
        self._events = events

    def paginate(self, **kwargs):
        return [{"Events": self._events}]


class FakeCloudTrail:
    def __init__(self, events=None):
        self._events = events or []

    def get_paginator(self, name):
        return FakePaginator(self._events)


class FakeSession:
    def __init__(self, sm, ct, **kwargs):
        self._sm, self._ct = sm, ct

    def client(self, name):
        return self._sm if name == "secretsmanager" else self._ct


@pytest.fixture
def module():
    return load_plugin_module()


def _connect(module, ct_events=None):
    sm = FakeSecretsManager()
    ct = FakeCloudTrail(ct_events)
    plugin = module.Plugin({
        "region": "us-east-1", "access_key_id": "AKIAFAKE",
        "secret_access_key": "secret", "prefix": "",
    })
    module.boto3.Session = lambda **kw: FakeSession(sm, ct, **kw)
    plugin.connect()
    return plugin, sm, ct


def test_connect_requires_region(module):
    plugin = module.Plugin({"access_key_id": "a", "secret_access_key": "s"})
    with pytest.raises(PluginError, match="region"):
        plugin.connect()


def test_connect_requires_keys(module):
    plugin = module.Plugin({"region": "us-east-1"})
    with pytest.raises(PluginError, match="access_key_id"):
        plugin.connect()


def test_plant_creates_secret(module):
    plugin, sm, _ = _connect(module)
    plugin.plant("production/stripe/key", "sk_live_fake",
                 {"created_by": "terraform"})
    assert len(sm.created) == 1
    assert sm.created[0]["Name"] == "production/stripe/key"
    assert sm.created[0]["SecretString"] == "sk_live_fake"
    assert {"Key": "created_by", "Value": "terraform"} in sm.created[0]["Tags"]


def test_delete_removes_secret(module):
    plugin, sm, _ = _connect(module)
    plugin.delete("production/stripe/key")
    assert sm.deleted == ["production/stripe/key"]


def test_poll_empty_when_no_events(module):
    plugin, _, _ = _connect(module, ct_events=[])
    assert plugin.poll(["production/stripe/key"]) == []


def test_poll_parses_getsecretvalue_into_access_event(module):
    ct_event = {
        "EventTime": datetime(2026, 6, 22, 10, 0, tzinfo=timezone.utc),
        "Username": "attacker",
        "EventId": "evt-1",
        "Resources": [{"ResourceType": "AWS::SecretsManager::Secret",
                       "ResourceName": "production/stripe/key"}],
        "CloudTrailEvent": '{"sourceIPAddress": "10.0.0.5", '
                           '"requestParameters": {"secretId": "production/stripe/key"}}',
    }
    plugin, _, _ = _connect(module, ct_events=[ct_event])
    events = plugin.poll(["production/stripe/key"])
    assert len(events) == 1
    ev = events[0]
    assert isinstance(ev, AccessEvent)
    assert ev.path == "production/stripe/key"
    assert ev.accessor == "attacker"
    assert ev.source_ip == "10.0.0.5"
    assert ev.extra["event_id"] == "evt-1"
