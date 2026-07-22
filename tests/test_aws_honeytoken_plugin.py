"""AWS honeytoken plugin against a faked boto3 session (no real AWS calls)."""
import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from thumper.plugins.base import PluginError

PLUGIN_FILE = (Path(__file__).resolve().parents[1]
               / "plugins" / "honeytoken" / "aws" / "plugin.py")


def load_plugin_module():
    spec = importlib.util.spec_from_file_location("thumper_plugin_aws_ht_test", PLUGIN_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Op")


class FakeIAM:
    def __init__(self, create_user_error=None):
        self.calls = []
        self._create_user_error = create_user_error
        self.deleted_users = []

    def create_user(self, **kw):
        self.calls.append(("create_user", kw))
        if self._create_user_error:
            raise self._create_user_error

    def put_user_policy(self, **kw):
        self.calls.append(("put_user_policy", kw))

    def create_access_key(self, UserName):
        self.calls.append(("create_access_key", UserName))
        return {"AccessKey": {"AccessKeyId": "AKIACANARY", "SecretAccessKey": "secret"}}

    def get_paginator(self, name):
        class Pag:
            def paginate(self, **kw):
                return [{"Users": [{"UserName": "thumper-canary-c"},
                                   {"UserName": "real-user"}]}]
        return Pag()

    def list_access_keys(self, UserName):
        if UserName == "thumper-canary-c":
            return {"AccessKeyMetadata": [{"AccessKeyId": "AKIACANARY"}]}
        return {"AccessKeyMetadata": []}

    def list_user_policies(self, UserName):
        return {"PolicyNames": ["thumper-deny-all"]}

    def delete_access_key(self, **kw):
        self.calls.append(("delete_access_key", kw))

    def delete_user_policy(self, **kw):
        self.calls.append(("delete_user_policy", kw))

    def delete_user(self, UserName):
        self.deleted_users.append(UserName)


class FakeCloudTrail:
    def __init__(self, events):
        self._events = events

    def lookup_events(self, **kw):
        return {"Events": self._events}


class FakeSession:
    def __init__(self, clients):
        self._clients = clients

    def client(self, name):
        return self._clients[name]


CONFIG = {"access_key_id": "AKIA", "secret_access_key": "s", "region": "us-east-1"}


@pytest.fixture
def module():
    return load_plugin_module()


def _with_session(module, monkeypatch, clients):
    monkeypatch.setattr(module.boto3, "Session", lambda **kw: FakeSession(clients))


def test_connect_requires_keys(module):
    with pytest.raises(PluginError):
        module.Plugin({"region": "us-east-1"}).connect()


def test_connect_calls_sts(module, monkeypatch):
    class STS:
        def get_caller_identity(self):
            return {"Arn": "arn:aws:iam::1:user/x"}
    _with_session(module, monkeypatch, {"sts": STS()})
    module.Plugin(CONFIG).connect()  # no raise


def test_create_token_provisions_key_and_deny_all(module, monkeypatch):
    iam = FakeIAM()
    _with_session(module, monkeypatch, {"iam": iam})
    result = module.Plugin(CONFIG).create_token("C")
    assert result["token_id"] == "AKIACANARY"
    assert result["username"] == "thumper-canary-c"
    assert result["secret_access_key"] == "secret"
    ops = [c[0] for c in iam.calls]
    assert "put_user_policy" in ops  # deny-all attached
    assert "create_access_key" in ops


def test_create_token_tolerates_existing_user(module, monkeypatch):
    iam = FakeIAM(create_user_error=_client_error("EntityAlreadyExists"))
    _with_session(module, monkeypatch, {"iam": iam})
    result = module.Plugin(CONFIG).create_token("C")  # does not raise
    assert result["token_id"] == "AKIACANARY"


def test_create_token_raises_on_other_error(module, monkeypatch):
    iam = FakeIAM(create_user_error=_client_error("AccessDenied"))
    _with_session(module, monkeypatch, {"iam": iam})
    with pytest.raises(PluginError):
        module.Plugin(CONFIG).create_token("C")


def test_revoke_token_cleans_up_canary_user(module, monkeypatch):
    iam = FakeIAM()
    _with_session(module, monkeypatch, {"iam": iam})
    module.Plugin(CONFIG).revoke_token("AKIACANARY")
    assert "thumper-canary-c" in iam.deleted_users


def test_poll_usage_maps_cloudtrail_events(module, monkeypatch):
    ct = FakeCloudTrail(events=[{
        "EventTime": datetime(2026, 7, 21, 10, 0, tzinfo=timezone.utc),
        "EventId": "evt-1", "EventName": "GetCallerIdentity", "Username": "attacker",
        "Resources": [{"ResourceName": "203.0.113.5"}],
    }])
    _with_session(module, monkeypatch, {"cloudtrail": ct})
    events = module.Plugin(CONFIG).poll_usage(["AKIACANARY"])
    assert len(events) == 1
    assert events[0].token_id == "AKIACANARY"
    assert events[0].action == "GetCallerIdentity"
    assert events[0].actor == "attacker"
    assert events[0].extra["event_id"] == "evt-1"
