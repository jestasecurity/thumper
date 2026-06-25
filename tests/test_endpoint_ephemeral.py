"""Ephemeral endpoints: per-job CI flag (issue #3).

Verifies that enroll with ephemeral=1 sets the flag on the row and that the
/api/endpoints response exposes it; also verifies the default-false path.
"""
import importlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.db import Base, Endpoint, get_db
from thumper.main import app
from thumper.config import ENROLL_TOKEN


@pytest.fixture
def client_db():
    engine = create_engine("sqlite://", echo=False,
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app), db
    del app.dependency_overrides[get_db]
    db.close()


# ── store-layer tests ─────────────────────────────────────────────────────────

def test_enroll_ephemeral_sets_flag(client_db):
    _, db = client_db
    ep = store.enroll_endpoint(db, hostname="ci-runner", platform="linux",
                               machine_id="m-ci-1", ephemeral=True)
    assert ep.ephemeral == 1


def test_enroll_non_ephemeral_default_zero(client_db):
    _, db = client_db
    ep = store.enroll_endpoint(db, hostname="prod-host", platform="linux",
                               machine_id="m-prod-1")
    assert ep.ephemeral == 0


def test_enroll_explicit_false_is_zero(client_db):
    _, db = client_db
    ep = store.enroll_endpoint(db, hostname="prod-host", platform="linux",
                               machine_id="m-prod-2", ephemeral=False)
    assert ep.ephemeral == 0


def test_reenroll_updates_ephemeral_flag(client_db):
    """Re-enrolling an existing machine_id should update the ephemeral flag."""
    _, db = client_db
    ep1 = store.enroll_endpoint(db, hostname="runner", platform="linux",
                                machine_id="m-re-1", ephemeral=False)
    assert ep1.ephemeral == 0
    ep2 = store.enroll_endpoint(db, hostname="runner", platform="linux",
                                machine_id="m-re-1", ephemeral=True)
    assert ep2.id == ep1.id        # same row
    assert ep2.ephemeral == 1


def test_reenroll_clears_ephemeral_flag(client_db):
    """Re-enrolling an ephemeral machine as non-ephemeral should clear the flag."""
    _, db = client_db
    store.enroll_endpoint(db, hostname="runner", platform="linux",
                          machine_id="m-re-2", ephemeral=True)
    ep = store.enroll_endpoint(db, hostname="runner", platform="linux",
                               machine_id="m-re-2", ephemeral=False)
    assert ep.ephemeral == 0


# ── API-layer tests ───────────────────────────────────────────────────────────

def _enroll(tc, *, machine_id, ephemeral=None):
    data = (
        f"enroll_token={ENROLL_TOKEN}&hostname=ci-host"
        f"&platform=linux&machine_id={machine_id}&tripwire_ids="
    )
    if ephemeral is not None:
        data += f"&ephemeral={ephemeral}"
    return tc.post("/api/enroll", content=data,
                   headers={"Content-Type": "application/x-www-form-urlencoded"})


def test_enroll_route_ephemeral_one_sets_flag(client_db):
    tc, db = client_db
    resp = _enroll(tc, machine_id="m-api-1", ephemeral="1")
    assert resp.status_code == 200
    db.expire_all()
    ep = db.query(Endpoint).filter(Endpoint.machine_id == "m-api-1").first()
    assert ep is not None and ep.ephemeral == 1


def test_enroll_route_no_field_defaults_zero(client_db):
    tc, db = client_db
    resp = _enroll(tc, machine_id="m-api-2")
    assert resp.status_code == 200
    db.expire_all()
    ep = db.query(Endpoint).filter(Endpoint.machine_id == "m-api-2").first()
    assert ep is not None and ep.ephemeral == 0


def test_endpoints_list_exposes_ephemeral_true(client_db):
    tc, db = client_db
    _enroll(tc, machine_id="m-api-3", ephemeral="1")
    body = tc.get("/api/endpoints").json()
    assert len(body) == 1
    assert body[0]["ephemeral"] is True


def test_endpoints_list_exposes_ephemeral_false(client_db):
    tc, db = client_db
    _enroll(tc, machine_id="m-api-4")
    body = tc.get("/api/endpoints").json()
    assert len(body) == 1
    assert body[0]["ephemeral"] is False


def test_enroll_route_ephemeral_zero_does_not_set_flag(client_db):
    """ephemeral=0 in the form body should leave the flag clear."""
    tc, db = client_db
    resp = _enroll(tc, machine_id="m-api-5", ephemeral="0")
    assert resp.status_code == 200
    db.expire_all()
    ep = db.query(Endpoint).filter(Endpoint.machine_id == "m-api-5").first()
    assert ep.ephemeral == 0


# ── migration import test ─────────────────────────────────────────────────────

def test_migration_imports_cleanly():
    """The migration module must be importable (catches syntax errors / bad imports)."""
    mod = importlib.import_module(
        "thumper.migrations.versions.endpoint_ephemeral_v1")
    assert mod.revision == "endpoint_ephemeral_v1"
    assert mod.down_revision == "merge_heads_v1"
