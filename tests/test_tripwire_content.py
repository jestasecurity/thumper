"""Tripwire token is generated at creation time and stored in the tripwires table."""
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from thumper import store
from thumper.db import Base


@pytest.fixture
def db():
    engine = create_engine("sqlite://", echo=False)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def test_create_tripwire_stores_token(db):
    tripwire = store.create_tripwire(
        db, name="aws-bait", token_type="aws", path="~/.aws/credentials",
        source="template", token="[default]\naws_access_key_id = AKIAFAKEKEY\n",
    )
    assert tripwire.token == "[default]\naws_access_key_id = AKIAFAKEKEY\n"

    reloaded = store.get_tripwire(db, tripwire.id)
    assert reloaded.token == "[default]\naws_access_key_id = AKIAFAKEKEY\n"


def test_post_tripwire_generates_and_stores_token(client_db):
    tc, db = client_db
    resp = tc.post("/api/tripwires", json={
        "name": "aws-bait", "token_type": "aws",
        "path": "~/.aws/credentials", "source": "template",
    })
    assert resp.status_code == 200
    tid = resp.json()["id"]

    db.expire_all()
    row = store.get_tripwire(db, tid)
    assert row.token is not None
    assert "AKIA" in row.token


def test_post_tripwire_generates_npmrc_token(client_db):
    tc, db = client_db
    resp = tc.post("/api/tripwires", json={
        "name": "npm-bait", "token_type": "npm",
        "path": "~/.npmrc", "source": "template",
    })
    assert resp.status_code == 200
    tid = resp.json()["id"]

    db.expire_all()
    row = store.get_tripwire(db, tid)
    assert row.token is not None
    assert row.token.startswith("//registry.npmjs.org/:_authToken=npm_")


def test_enroll_uses_stored_tripwire_token(client_db):
    tc, db = client_db

    resp = tc.post("/api/tripwires", json={
        "name": "ssh-bait", "token_type": "ssh",
        "path": "~/.ssh/id_rsa", "source": "template",
    })
    tid = resp.json()["id"]
    db.expire_all()
    stored_token = store.get_tripwire(db, tid).token

    with patch("thumper.api.routes.render_content", side_effect=AssertionError("should not be called")):
        resp = tc.post("/api/enroll", data={
            "enroll_token": "dev-enroll-token",
            "hostname": "test-host",
            "machine_id": "abc123",
            "platform": "darwin",
            "tripwire_ids": tid,
        })

    assert resp.status_code == 200

    endpoint_id = resp.text.split("endpoint_id=")[1].split("\n")[0]
    db.expire_all()
    deployments = store.list_deployments_for_endpoint(db, endpoint_id)
    assert len(deployments) == 1
    assert deployments[0].content == stored_token
