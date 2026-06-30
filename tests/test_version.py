"""GET /healthz and GET /api/version expose the package version."""
from thumper import __version__


def test_healthz_includes_version(client_db):
    tc, _ = client_db
    resp = tc.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": __version__}


def test_api_version_matches_healthz(client_db):
    tc, _ = client_db
    health = tc.get("/healthz").json()["version"]
    api = tc.get("/api/version").json()["version"]
    assert health == api == __version__
