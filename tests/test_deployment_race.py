"""materialize_deployment must be safe under a duplicate (tripwire, endpoint)
race: two requests both pass the existence check, both insert, and the second
violates the unique constraint. It should recover and return the existing row,
not raise (which surfaces as a 500)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper import store
from thumper.db import Base


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _materialize(db):
    return store.materialize_deployment(
        db, tripwire_id="tw_1", endpoint_id="ep_1", path="/x", content="bait")


def test_materialize_is_idempotent(db):
    first = _materialize(db)
    again = _materialize(db)
    assert again.id == first.id
    assert store.count_deployments(db) == 1


def test_materialize_recovers_from_duplicate_race(db, monkeypatch):
    """Simulate the race: the winner already inserted, but our existence check
    misses it (as if its commit hadn't landed yet), so we take the INSERT path
    and hit the unique constraint - and must return the winner's row, not raise."""
    winner = _materialize(db)

    real_find = store._find_deployment
    calls = {"n": 0}

    def flaky_find(session, tripwire_id, endpoint_id):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # first lookup misses -> forces the INSERT path
        return real_find(session, tripwire_id, endpoint_id)

    monkeypatch.setattr(store, "_find_deployment", flaky_find)

    result = _materialize(db)  # must NOT raise IntegrityError
    assert result.id == winner.id
    assert store.count_deployments(db) == 1
