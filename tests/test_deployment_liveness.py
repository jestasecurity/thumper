"""A deployment should surface its endpoint's liveness, so the UI can stop showing
green 'planted' for an endpoint that's gone stale/offline (#27)."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper.db import Base, Deployment, Endpoint, get_db
from thumper.main import app


@pytest.fixture
def client_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app), db
    del app.dependency_overrides[get_db]
    db.close()


def _ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seed(db, last_seen, *, decommission_requested_at=None, with_endpoint=True):
    if with_endpoint:
        db.add(Endpoint(id="ep_1", hostname="h", platform="linux", machine_id="m1",
                        agent_token="t", enrolled_at="2026-01-01T00:00:00Z",
                        last_seen=last_seen,
                        decommission_requested_at=decommission_requested_at))
    db.add(Deployment(id="dp_1", tripwire_id="tw_1", endpoint_id="ep_1", path="/x",
                      content="b", hmac_secret="s", state="planted",
                      created_at="2026-01-01T00:00:00Z"))
    # tripwire row so the detail endpoint resolves
    from thumper import store
    db.add  # noqa
    store.create_tripwire(db, name="t", token_type="aws", path="/x", token="x")
    # point the deployment at the real tripwire id
    tw = store.list_tripwires(db)[0]
    db.query(Deployment).filter(Deployment.id == "dp_1").update({"tripwire_id": tw.id})
    db.commit()
    return tw.id


def _endpoint_status_in_detail(tc, tid):
    body = tc.get(f"/api/tripwires/{tid}").json()
    return body["deployments"][0]["endpoint_status"]


def test_planted_on_online_endpoint(client_db):
    tc, db = client_db
    tid = _seed(db, _ago(minutes=2))
    assert _endpoint_status_in_detail(tc, tid) == "online"


def test_planted_on_stale_endpoint(client_db):
    tc, db = client_db
    tid = _seed(db, _ago(hours=1))
    assert _endpoint_status_in_detail(tc, tid) == "stale"


def test_planted_on_decommissioning_endpoint(client_db):
    # A pending decommission overrides liveness: even a freshly-seen endpoint
    # reads as "decommissioning", not "online".
    tc, db = client_db
    tid = _seed(db, _ago(minutes=2), decommission_requested_at=_ago(minutes=1))
    assert _endpoint_status_in_detail(tc, tid) == "decommissioning"


def test_planted_on_missing_endpoint(client_db):
    # Deployment outlived its endpoint (host removed): no endpoint row -> inactive,
    # not a 500.
    tc, db = client_db
    tid = _seed(db, None, with_endpoint=False)
    assert _endpoint_status_in_detail(tc, tid) == "inactive"
