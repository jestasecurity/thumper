"""Coverage for the token catalog API: GET /api/token-types and
POST /api/tokens/preview (#200)."""
from thumper.tokens.catalog import TOKEN_TYPES, TOKEN_TYPE_NAMES


def test_token_types_returns_full_catalog(client_db):
    tc, _ = client_db
    resp = tc.get("/api/token-types")
    assert resp.status_code == 200
    body = resp.json()
    assert {t["type"] for t in body} == TOKEN_TYPE_NAMES
    assert body == TOKEN_TYPES


def test_preview_template_source_generates_content(client_db):
    tc, _ = client_db
    resp = tc.post("/api/tokens/preview", json={"token_type": "npm", "source": "template"})
    assert resp.status_code == 200
    assert resp.json()["content"].startswith("//registry.npmjs.org/:_authToken=npm_")


def test_preview_custom_source_returns_custom_content(client_db):
    tc, _ = client_db
    resp = tc.post("/api/tokens/preview", json={
        "token_type": "aws", "source": "custom", "custom_content": "hello-bait",
    })
    assert resp.status_code == 200
    assert resp.json()["content"] == "hello-bait"


def test_preview_custom_source_without_content_is_400(client_db):
    tc, _ = client_db
    resp = tc.post("/api/tokens/preview", json={"token_type": "aws", "source": "custom"})
    assert resp.status_code == 400


def test_preview_unknown_token_type_is_400(client_db):
    tc, _ = client_db
    resp = tc.post("/api/tokens/preview", json={"token_type": "not-a-real-type"})
    assert resp.status_code == 400
