"""The server must normalize the agent callback timestamp to a canonical UTC
form before storing, so 24h counts (string compare) and list ordering don't
break on offset/fractional formats (#31)."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper.db import Alert, Base, Deployment, get_db
from thumper.main import app
from thumper.services.signing import sign


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


def test_callback_timestamp_is_normalized(client_db, monkeypatch):
    tc, db = client_db
    db.add(Deployment(id="dp_1", tripwire_id="tw_1", endpoint_id="ep_1", path="/x",
                      content="b", hmac_secret="s", state="planted",
                      created_at="2026-01-01T00:00:00Z"))
    db.commit()
    monkeypatch.setattr("thumper.api.routes.deliver_alert", lambda e: None)

    # Fresh, but in a non-canonical format: explicit +00:00 offset + fractional secs.
    now = datetime.now(timezone.utc).replace(microsecond=0)
    weird = now.strftime("%Y-%m-%dT%H:%M:%S") + ".500+00:00"
    body = f"deployment_id=dp_1\nprocess=cat\ntimestamp={weird}".encode()
    resp = tc.post("/api/trigger", content=body,
                   headers={"X-Thumper-Signature": sign("s", body)})
    assert resp.status_code == 200

    stored = db.query(Alert).filter(Alert.deployment_id == "dp_1").first().timestamp
    assert stored == now.strftime("%Y-%m-%dT%H:%M:%SZ"), f"not normalized: {stored!r}"
