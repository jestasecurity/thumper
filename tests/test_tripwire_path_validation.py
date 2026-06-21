"""Bait paths are planted by the root agent, so the create API must reject
traversal / relative paths that could become an arbitrary-write primitive (#76)."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper.db import Base, get_db
from thumper.main import app


@pytest.fixture
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app)
    del app.dependency_overrides[get_db]
    db.close()


def _create(client, path):
    return client.post("/api/tripwires",
                       json={"name": "t", "token_type": "aws", "path": path})


@pytest.mark.parametrize("bad", ["../../etc/passwd", "etc/passwd", "a/../b", "", "   "])
def test_rejects_traversal_and_relative_paths(client, bad):
    assert _create(client, bad).status_code == 400


# `~user/` passes a naive `startswith("~")` but the agent's expand_path only
# expands `~/`, so the root agent would use it literally (#76 review).
@pytest.mark.parametrize("bad", ["~postgres/.pgpass", "~root/.ssh/id_rsa", "~~/x"])
def test_rejects_other_user_home_paths(client, bad):
    assert _create(client, bad).status_code == 400


@pytest.mark.parametrize("ok", ["~/.aws/credentials", "/etc/ssh/ssh_host_ed25519_key"])
def test_accepts_absolute_and_home_paths(client, ok):
    resp = _create(client, ok)
    assert resp.status_code == 200
    assert resp.json()["path"] == ok
