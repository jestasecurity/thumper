"""CORS is restricted to an allow-list, not wide open (#23). Default allows the
Vite dev origin; operators override via THUMPER_ALLOWED_ORIGINS."""
from fastapi.testclient import TestClient

from thumper.main import app

client = TestClient(app)


def test_disallowed_origin_is_not_allowed():
    r = client.get("/healthz", headers={"Origin": "http://evil.example"})
    acao = r.headers.get("access-control-allow-origin")
    assert acao != "*"                     # not wide open
    assert acao != "http://evil.example"   # arbitrary origin not echoed


def test_allowed_origin_is_echoed():
    r = client.get("/healthz", headers={"Origin": "http://localhost:5173"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"
