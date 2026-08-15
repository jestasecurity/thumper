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


# ── vault connections ────────────────────────────────────────────────────────
def test_create_vault_connection(db):
    vc = store.create_vault_connection(
        db, name="Production Vault", plugin="hashicorp",
        config={"url": "http://vault:8200", "role_id": "abc"})
    assert vc.id.startswith("vc_")
    assert vc.name == "Production Vault"
    assert vc.plugin == "hashicorp"
    assert vc.configured is False
    assert vc.created_at is not None
    assert json.loads(vc.config_json) == {"url": "http://vault:8200", "role_id": "abc"}


def test_list_vault_connections_newest_first(db):
    a = store.create_vault_connection(db, name="A", plugin="hashicorp", config={})
    b = store.create_vault_connection(db, name="B", plugin="hashicorp", config={})
    ids = [c.id for c in store.list_vault_connections(db)]
    assert set(ids) == {a.id, b.id}
    assert len(ids) == 2


def test_get_vault_connection(db):
    vc = store.create_vault_connection(db, name="T", plugin="hashicorp", config={})
    assert store.get_vault_connection(db, vc.id).id == vc.id
    assert store.get_vault_connection(db, "vc_nope") is None


def test_update_vault_connection(db):
    vc = store.create_vault_connection(db, name="Old", plugin="hashicorp",
                                       config={"url": "http://old"})
    updated = store.update_vault_connection(db, vc.id, name="New",
                                            config={"url": "http://new"})
    assert updated.name == "New"
    assert json.loads(updated.config_json)["url"] == "http://new"
    assert store.update_vault_connection(db, "vc_nope", name="X", config={}) is None


def test_set_vault_connection_test_flips_configured(db):
    vc = store.create_vault_connection(db, name="T", plugin="hashicorp", config={})
    store.set_vault_connection_test(db, vid=vc.id, configured=True)
    assert store.get_vault_connection(db, vc.id).configured is True


def test_update_vault_last_poll(db):
    vc = store.create_vault_connection(db, name="T", plugin="hashicorp", config={})
    assert store.get_vault_connection(db, vc.id).last_poll_at is None
    store.update_vault_last_poll(db, vc.id)
    assert store.get_vault_connection(db, vc.id).last_poll_at is not None


def test_delete_vault_connection_cascades_canaries(db):
    vc = store.create_vault_connection(db, name="T", plugin="hashicorp", config={})
    store.create_canary_secret(db, vault_connection_id=vc.id, template="stripe",
                               path="secret/stripe/key", value="sk_live_fake")
    assert store.delete_vault_connection(db, vc.id) is True
    assert store.list_canary_secrets_for_connection(db, vc.id) == []
    assert store.delete_vault_connection(db, "vc_nope") is False


# ── canary secrets ────────────────────────────────────────────────────────────
def test_create_canary_secret(db):
    vc = store.create_vault_connection(db, name="T", plugin="hashicorp", config={})
    cs = store.create_canary_secret(db, vault_connection_id=vc.id,
                                    template="stripe", path="secret/stripe/key",
                                    value="sk_live_fake")
    assert cs.id.startswith("cs_")
    assert cs.state == "pending"
    assert cs.last_accessed_at is None


def test_set_canary_secret_state(db):
    vc = store.create_vault_connection(db, name="T", plugin="hashicorp", config={})
    cs = store.create_canary_secret(db, vault_connection_id=vc.id, template="s",
                                    path="p", value="v")
    store.set_canary_secret_state(db, cs.id, "planted")
    assert store.get_canary_secret(db, cs.id).state == "planted"


def test_mark_canary_secret_accessed_triggers(db):
    vc = store.create_vault_connection(db, name="T", plugin="hashicorp", config={})
    cs = store.create_canary_secret(db, vault_connection_id=vc.id, template="s",
                                    path="p", value="v")
    store.mark_canary_secret_accessed(db, cs.id)
    row = store.get_canary_secret(db, cs.id)
    assert row.state == "triggered"
    assert row.last_accessed_at is not None


def test_list_planted_canary_secrets_for_connection(db):
    vc = store.create_vault_connection(db, name="T", plugin="hashicorp", config={})
    pending = store.create_canary_secret(db, vault_connection_id=vc.id,
                                         template="s", path="p1", value="v")
    planted = store.create_canary_secret(db, vault_connection_id=vc.id,
                                         template="s", path="p2", value="v")
    store.set_canary_secret_state(db, planted.id, "planted")
    ids = [c.id for c in store.list_planted_canary_secrets_for_connection(db, vc.id)]
    assert planted.id in ids
    assert pending.id not in ids


def test_delete_canary_secret(db):
    vc = store.create_vault_connection(db, name="T", plugin="hashicorp", config={})
    cs = store.create_canary_secret(db, vault_connection_id=vc.id, template="s",
                                    path="p", value="v")
    assert store.delete_canary_secret(db, cs.id) is True
    assert store.get_canary_secret(db, cs.id) is None
    assert store.delete_canary_secret(db, "cs_nope") is False
