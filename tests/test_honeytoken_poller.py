import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.db import Base
from thumper.plugins.base import TokenUsageEvent
from thumper.services import honeytoken_poller


@pytest.fixture
def db():
    engine = create_engine("sqlite://", echo=False,
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


class FakePlugin:
    def __init__(self, events=None):
        self._events = events or []

    def connect(self):
        pass

    def poll_usage(self, token_ids, since=None):
        return self._events


def _active_token(db, conn, token_id="tok_1"):
    ht = store.create_honeytoken(db, connection_id=conn.id, name="canary",
                                 token_id=token_id, token_type="datadog_key",
                                 metadata={})
    store.set_honeytoken_state(db, ht.id, "active")
    return ht


def _conn(db):
    conn = store.create_honeytoken_connection(db, name="Prod", plugin="datadog",
                                              config={"api_key": "k"})
    store.set_honeytoken_connection_test(db, hid=conn.id, configured=True)
    return conn


def test_poll_once_no_connections(db):
    assert honeytoken_poller.poll_once(db) == 0


def test_poll_once_no_active_tokens(db):
    _conn(db)
    assert honeytoken_poller.poll_once(db) == 0


def test_poll_once_detects_usage(db, monkeypatch):
    conn = _conn(db)
    ht = _active_token(db, conn)
    fake = FakePlugin(events=[
        TokenUsageEvent(token_id="tok_1", timestamp="2026-07-21T10:00:00Z",
                        actor="attacker", source_ip="10.0.0.5", action="query"),
    ])
    monkeypatch.setattr(honeytoken_poller, "load_plugin", lambda name, config: fake)
    delivered = []
    monkeypatch.setattr(honeytoken_poller, "deliver_alert", delivered.append)

    assert honeytoken_poller.poll_once(db) == 1
    db.expire_all()
    assert store.get_honeytoken(db, ht.id).state == "triggered"
    assert store.get_honeytoken(db, ht.id).last_used_at is not None
    assert store.get_honeytoken_connection(db, conn.id).last_poll_at is not None
    assert len(delivered) == 1
    assert delivered[0]["event_type"] == "honeytoken_usage"
    assert delivered[0]["actor"] == "attacker"
    assert len(store.list_honeytoken_usage_logs(db, ht.id)) == 1


def test_poll_once_dedupes_repeated_event(db, monkeypatch):
    conn = _conn(db)
    ht = _active_token(db, conn)
    fake = FakePlugin(events=[
        TokenUsageEvent(token_id="tok_1", timestamp="t", actor="a",
                        extra={"event_id": "evt-1"}),
    ])
    monkeypatch.setattr(honeytoken_poller, "load_plugin", lambda name, config: fake)
    delivered = []
    monkeypatch.setattr(honeytoken_poller, "deliver_alert", delivered.append)

    assert honeytoken_poller.poll_once(db) == 1
    assert honeytoken_poller.poll_once(db) == 0   # same event again -> no re-alert
    assert len(delivered) == 1
    assert len(store.list_honeytoken_usage_logs(db, ht.id)) == 1


def test_poll_once_skips_unconfigured(db, monkeypatch):
    conn = store.create_honeytoken_connection(db, name="X", plugin="datadog", config={})
    _active_token(db, conn)
    fake = FakePlugin(events=[TokenUsageEvent(token_id="tok_1", timestamp="t")])
    monkeypatch.setattr(honeytoken_poller, "load_plugin", lambda name, config: fake)
    monkeypatch.setattr(honeytoken_poller, "deliver_alert", lambda e: None)
    assert honeytoken_poller.poll_once(db) == 0


def test_poll_once_continues_on_plugin_error(db, monkeypatch):
    broken = store.create_honeytoken_connection(db, name="Broken", plugin="datadog",
                                               config={"api_key": "bad"})
    store.set_honeytoken_connection_test(db, hid=broken.id, configured=True)
    good = _conn(db)
    ht = _active_token(db, good)

    def fake_load(name, config):
        if config.get("api_key") == "bad":
            raise RuntimeError("auth failed")
        return FakePlugin(events=[TokenUsageEvent(token_id=ht.token_id, timestamp="t")])

    monkeypatch.setattr(honeytoken_poller, "load_plugin", fake_load)
    delivered = []
    monkeypatch.setattr(honeytoken_poller, "deliver_alert", delivered.append)
    assert honeytoken_poller.poll_once(db) == 1
    assert len(delivered) == 1


def test_poll_once_survives_poll_failure(db, monkeypatch):
    conn = _conn(db)
    _active_token(db, conn)

    class Boom:
        def poll_usage(self, token_ids, since=None):
            raise RuntimeError("audit API down")

    monkeypatch.setattr(honeytoken_poller, "load_plugin", lambda name, config: Boom())
    monkeypatch.setattr(honeytoken_poller, "deliver_alert", lambda e: None)
    assert honeytoken_poller.poll_once(db) == 0
