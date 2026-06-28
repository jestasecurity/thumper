"""Shared test fixtures."""
import ipaddress

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from thumper.db import Base, get_db
from thumper.main import app


@pytest.fixture(autouse=True)
def _allow_local_integration_hosts(monkeypatch):
    """Integration tests point plugins at localhost/private stub servers - exactly
    what the SSRF guard (#74) blocks by default. Mirror a real operator and
    allowlist local/private ranges for the test session. The dedicated SSRF tests
    pass an explicit empty allowlist, so they still verify blocking."""
    from thumper.services import ssrf
    monkeypatch.setattr(ssrf, "ALLOWED_HOOK_CIDRS", [
        ipaddress.ip_network(c) for c in
        ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    ])


@pytest.fixture(autouse=True)
def _bypass_admin_auth():
    """Admin-token auth (#20) gates the whole management API. Existing tests
    exercise other behavior, so bypass the gate by default via a dependency
    override. The dedicated test_admin_auth.py removes this override to test the
    real gate."""
    from thumper.api.routes import require_admin
    app.dependency_overrides[require_admin] = lambda: None
    yield
    app.dependency_overrides.pop(require_admin, None)


@pytest.fixture
def client_db():
    """A TestClient wired to a fresh in-memory SQLite session, yielded together
    so tests can both drive the API and seed/inspect the same session."""
    engine = create_engine("sqlite://", echo=False,
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app), db
    del app.dependency_overrides[get_db]
    db.close()
