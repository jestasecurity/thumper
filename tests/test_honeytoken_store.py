import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.db import Base


@pytest.fixture
def db():
    engine = create_engine("sqlite://", echo=False,
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


# ── connections ──────────────────────────────────────────────────────────────
def test_create_honeytoken_connection(db):
    c = store.create_honeytoken_connection(
        db, name="Prod Datadog", plugin="datadog", config={"site": "datadoghq.com"})
    assert c.id.startswith("htc_")
    assert c.name == "Prod Datadog"
    assert c.configured is False
    assert json.loads(c.config_json) == {"site": "datadoghq.com"}


def test_update_honeytoken_connection(db):
    c = store.create_honeytoken_connection(db, name="Old", plugin="datadog", config={})
    updated = store.update_honeytoken_connection(db, c.id, name="New", config={"k": "v"})
    assert updated is not None
    assert updated.name == "New"
    assert json.loads(updated.config_json) == {"k": "v"}
    assert store.update_honeytoken_connection(db, "htc_nope", name="x", config={}) is None


def test_set_connection_test_and_last_poll(db):
    c = store.create_honeytoken_connection(db, name="C", plugin="datadog", config={})
    store.set_honeytoken_connection_test(db, hid=c.id, configured=True)
    store.update_honeytoken_last_poll(db, c.id)
    row = store.get_honeytoken_connection(db, c.id)
    assert row.configured is True
    assert row.last_poll_at is not None


def test_delete_connection_cascades_tokens_and_logs(db):
    c = store.create_honeytoken_connection(db, name="C", plugin="datadog", config={})
    ht = store.create_honeytoken(db, connection_id=c.id, name="k", token_id="tok",
                                 token_type="datadog_key", metadata={})
    store.record_honeytoken_usage(db, htid=ht.id, event_id="e1", actor="a",
                                  source_ip=None, action="use", timestamp="t")
    assert store.delete_honeytoken_connection(db, c.id) is True
    assert store.list_honeytokens(db) == []
    assert store.list_honeytoken_usage_logs(db, ht.id) == []
    assert store.delete_honeytoken_connection(db, "htc_nope") is False


# ── tokens ───────────────────────────────────────────────────────────────────
def test_create_and_list_honeytokens(db):
    c = store.create_honeytoken_connection(db, name="C", plugin="datadog", config={})
    ht = store.create_honeytoken(db, connection_id=c.id, name="canary-key",
                                 token_id="tok_1", token_type="datadog_key",
                                 metadata={"key_id": "abc"})
    assert ht.id.startswith("ht_")
    assert ht.state == "pending"
    assert json.loads(ht.metadata_json) == {"key_id": "abc"}
    assert [h.id for h in store.list_honeytokens(db)] == [ht.id]


def test_active_honeytokens_filter(db):
    c = store.create_honeytoken_connection(db, name="C", plugin="datadog", config={})
    pending = store.create_honeytoken(db, connection_id=c.id, name="p", token_id="t1",
                                      token_type="k", metadata={})
    active = store.create_honeytoken(db, connection_id=c.id, name="a", token_id="t2",
                                     token_type="k", metadata={})
    store.set_honeytoken_state(db, active.id, "active")
    ids = [h.id for h in store.list_active_honeytokens_for_connection(db, c.id)]
    assert active.id in ids
    assert pending.id not in ids


def test_mark_honeytoken_used(db):
    c = store.create_honeytoken_connection(db, name="C", plugin="datadog", config={})
    ht = store.create_honeytoken(db, connection_id=c.id, name="k", token_id="t",
                                 token_type="k", metadata={})
    store.mark_honeytoken_used(db, ht.id)
    row = store.get_honeytoken(db, ht.id)
    assert row.state == "triggered"
    assert row.last_used_at is not None


def test_delete_honeytoken(db):
    c = store.create_honeytoken_connection(db, name="C", plugin="datadog", config={})
    ht = store.create_honeytoken(db, connection_id=c.id, name="k", token_id="t",
                                 token_type="k", metadata={})
    assert store.delete_honeytoken(db, ht.id) is True
    assert store.get_honeytoken(db, ht.id) is None
    assert store.delete_honeytoken(db, "ht_nope") is False


# ── usage logs ───────────────────────────────────────────────────────────────
def _token(db):
    c = store.create_honeytoken_connection(db, name="C", plugin="datadog", config={})
    return store.create_honeytoken(db, connection_id=c.id, name="k", token_id="t",
                                   token_type="k", metadata={})


def test_record_usage_dedupes_by_event_id(db):
    ht = _token(db)
    first = store.record_honeytoken_usage(db, htid=ht.id, event_id="e1", actor="mallory",
                                          source_ip="10.0.0.1", action="query", timestamp="t1")
    dup = store.record_honeytoken_usage(db, htid=ht.id, event_id="e1", actor="mallory",
                                        source_ip="10.0.0.1", action="query", timestamp="t2")
    assert first is not None
    assert dup is None
    assert len(store.list_honeytoken_usage_logs(db, ht.id)) == 1


def test_record_usage_without_event_id_not_deduped(db):
    ht = _token(db)
    store.record_honeytoken_usage(db, htid=ht.id, event_id=None, actor="a",
                                  source_ip=None, action=None, timestamp="t1")
    store.record_honeytoken_usage(db, htid=ht.id, event_id=None, actor="a",
                                  source_ip=None, action=None, timestamp="t2")
    assert len(store.list_honeytoken_usage_logs(db, ht.id)) == 2


def test_list_usage_logs_newest_first(db):
    ht = _token(db)
    store.record_honeytoken_usage(db, htid=ht.id, event_id="e1", actor="a",
                                  source_ip=None, action=None, timestamp="2026-07-21T00:00:00Z")
    store.record_honeytoken_usage(db, htid=ht.id, event_id="e2", actor="b",
                                  source_ip=None, action=None, timestamp="2026-07-21T09:00:00Z")
    logs = store.list_honeytoken_usage_logs(db, ht.id)
    assert [entry.event_id for entry in logs] == ["e2", "e1"]
