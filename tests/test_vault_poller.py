import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.db import Base
from thumper.plugins.base import AccessEvent
from thumper.services import vault_poller


@pytest.fixture
def db():
    engine = create_engine("sqlite://", echo=False,
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


class FakeVaultPlugin:
    def __init__(self, events=None):
        self._events = events or []

    def connect(self):
        pass

    def poll(self, paths, since=None):
        return self._events


def _planted(db, vc, template="stripe", path="production/stripe/key"):
    cs = store.create_canary_secret(db, vault_connection_id=vc.id,
                                    template=template, path=path,
                                    value="sk_live_fake")
    store.set_canary_secret_state(db, cs.id, "planted")
    return cs


def test_poll_once_no_connections(db):
    assert vault_poller.poll_once(db) == 0


def test_poll_once_no_planted_secrets(db):
    vc = store.create_vault_connection(db, name="Test", plugin="hashicorp",
                                       config={"url": "http://vault"})
    store.set_vault_connection_test(db, vid=vc.id, configured=True)
    assert vault_poller.poll_once(db) == 0


def test_poll_once_detects_read(db, monkeypatch):
    vc = store.create_vault_connection(db, name="Test", plugin="hashicorp",
                                       config={"url": "http://vault"})
    store.set_vault_connection_test(db, vid=vc.id, configured=True)
    cs = _planted(db, vc)

    fake = FakeVaultPlugin(events=[
        AccessEvent(path=cs.path, timestamp="2026-07-21T10:00:00Z",
                    accessor="attacker", source_ip="10.0.0.5", policy="default"),
    ])
    monkeypatch.setattr(vault_poller, "load_plugin", lambda name, config: fake)
    delivered = []
    monkeypatch.setattr(vault_poller, "deliver_alert", delivered.append)

    assert vault_poller.poll_once(db) == 1
    db.expire_all()
    assert store.get_canary_secret(db, cs.id).last_accessed_at is not None
    assert store.get_canary_secret(db, cs.id).state == "triggered"
    assert store.get_vault_connection(db, vc.id).last_poll_at is not None
    assert len(delivered) == 1
    assert delivered[0]["event_type"] == "vault_read"
    assert delivered[0]["accessor"] == "attacker"
    assert len(store.list_canary_access_logs(db, cs.id)) == 1


def test_poll_once_dedupes_repeated_event(db, monkeypatch):
    """Overlapping poll windows re-surface the same audit event (the AWS plugin
    uses a lookback). A read with a stable event_id must alert exactly once."""
    vc = store.create_vault_connection(db, name="Test", plugin="hashicorp",
                                       config={"url": "http://vault"})
    store.set_vault_connection_test(db, vid=vc.id, configured=True)
    cs = _planted(db, vc)

    fake = FakeVaultPlugin(events=[
        AccessEvent(path=cs.path, timestamp="2026-07-21T10:00:00Z",
                    accessor="attacker", extra={"event_id": "evt-1"}),
    ])
    monkeypatch.setattr(vault_poller, "load_plugin", lambda name, config: fake)
    delivered = []
    monkeypatch.setattr(vault_poller, "deliver_alert", delivered.append)

    assert vault_poller.poll_once(db) == 1
    assert vault_poller.poll_once(db) == 0   # same event again -> no re-alert
    assert len(delivered) == 1
    assert len(store.list_canary_access_logs(db, cs.id)) == 1


def test_poll_once_skips_unconfigured_connections(db, monkeypatch):
    vc = store.create_vault_connection(db, name="Not Ready", plugin="hashicorp",
                                       config={"url": "http://vault"})
    _planted(db, vc, path="a")
    fake = FakeVaultPlugin(events=[AccessEvent(path="a", timestamp="t")])
    monkeypatch.setattr(vault_poller, "load_plugin", lambda name, config: fake)
    monkeypatch.setattr(vault_poller, "deliver_alert", lambda event: None)
    assert vault_poller.poll_once(db) == 0


def test_poll_once_continues_on_plugin_error(db, monkeypatch):
    broken = store.create_vault_connection(db, name="Broken", plugin="hashicorp",
                                           config={"url": "http://broken"})
    store.set_vault_connection_test(db, vid=broken.id, configured=True)
    good = store.create_vault_connection(db, name="Good", plugin="hashicorp",
                                         config={"url": "http://good"})
    store.set_vault_connection_test(db, vid=good.id, configured=True)
    cs = _planted(db, good, path="a")

    def fake_load(name, config):
        if config.get("url") == "http://broken":
            raise RuntimeError("connection refused")
        return FakeVaultPlugin(events=[AccessEvent(path=cs.path, timestamp="t")])

    monkeypatch.setattr(vault_poller, "load_plugin", fake_load)
    delivered = []
    monkeypatch.setattr(vault_poller, "deliver_alert", delivered.append)

    assert vault_poller.poll_once(db) == 1
    assert len(delivered) == 1


def test_poll_once_survives_poll_failure(db, monkeypatch):
    vc = store.create_vault_connection(db, name="Test", plugin="hashicorp",
                                       config={"url": "http://vault"})
    store.set_vault_connection_test(db, vid=vc.id, configured=True)
    _planted(db, vc)

    class Boom:
        def poll(self, paths, since=None):
            raise RuntimeError("audit log unreachable")

    monkeypatch.setattr(vault_poller, "load_plugin", lambda name, config: Boom())
    monkeypatch.setattr(vault_poller, "deliver_alert", lambda event: None)
    assert vault_poller.poll_once(db) == 0
