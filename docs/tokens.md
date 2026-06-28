# Adding a honeytoken type

Thumper ships with five built-in token types (`aws`, `github`, `gcp`, `azure`, `ssh`). Adding a new one touches exactly two files and one test, and both files must stay in sync or the API will accept the type name but fail to generate content.

## The two touch points

```
server/thumper/tokens/
  catalog.py      # declares the type: name, paths, description
  generator.py    # returns the fake file content for the type
tests/
  test_tripwire_content.py  # asserts the generated content looks right
```

## Step 1 — catalog.py

`catalog.py` holds `TOKEN_TYPES`, a list of dicts that drives the UI dropdown and the `GET /api/token-types` endpoint. Add one entry:

```python
{
    "type": "github",                          # must be unique, lowercase, no spaces
    "display_name": "GitHub PAT",              # shown in the UI
    "default_path": "~/.config/gh/hosts.yml", # top recommendation shown first
    "suggested_paths": [                       # shown as quick-fill options
        "~/.config/gh/hosts.yml",
        "~/.netrc",
        "~/.git-credentials",
        "~/.npmrc",
        "~/.env",
    ],
    "description": "Fake fine-grained GitHub personal access token. "
                   "Shai-Hulud exfiltrates these to self-replicate via the API.",
},
```

`TOKEN_TYPE_NAMES` at the bottom of the file is derived automatically, you do not touch it.

## Step 2 — generator.py

`generator.py` exports a single function `generate_token(token_type: str) -> str` that returns the full content of the fake credential file. Add a branch for your type:

```python
if token_type == "github":
    return (
        "github.com:\n"
        f"  oauth_token: github_pat_{rand_b64(22)}_{rand_b64(59)}\n"
        "  user: ci-deploy-bot\n"
    )
```

**The "correct shape, garbage material" philosophy** (from the module docstring):

> Each output is correct in *shape* (real prefixes like `AKIA`, `github_pat_`,
> the `eyJ` JWT header; correct file format) so a scanner believes it, while
> the key material is cryptographically random garbage that authenticates to
> nothing.

In practice this means:
- Use the real prefix an attacker or scanner expects (`AKIA` for AWS, `github_pat_` for GitHub, 
  etc.)
- Keep the format identical to a real credential file so the scanner doesn't skip it
- Generate all random bytes with `secrets.choice` via the `rand_hex` / `rand_b64` helpers, **never 
  use `random`**
- The token must not work. That is the whole point.

## Step 3 — test

Add a case in `tests/test_tripwire_content.py` that posts a tripwire of the new type and asserts the generated content contains a recognisable marker:

```python
def test_post_tripwire_generates_github_token(client_db):
    tc, db = client_db
    resp = tc.post("/api/tripwires", json={
        "name": "github-bait", "token_type": "github",
        "path": "~/.config/gh/hosts.yml", "source": "template",
    })
    assert resp.status_code == 200
    tid = resp.json()["id"]

    db.expire_all()
    row = store.get_tripwire(db, tid)
    assert row.token is not None
    assert "github_pat_" in row.token
```

Pick a string that is **specific to your type** (the prefix, a key name, a file format marker) rather than something generic.

## Keeping both files in sync

`catalog.py` declares what types exist. `generator.py` must have a matching `if token_type == 
"<type>":` branch for every entry in `TOKEN_TYPES`. If you add one without the other, 
`generate_token()` falls through to:

```python
raise ValueError(f"unknown token type: {token_type!r}")
```

and every tripwire creation for that type will return a 500. Run the full suite before submitting:

```bash
pytest -v
```

## Checklist

- [ ] `catalog.py` — new entry added to `TOKEN_TYPES`
- [ ] `generator.py` — matching `if token_type == "..."` branch added
- [ ] `tests/test_tripwire_content.py` — new test added
- [ ] `pytest -v` passes
