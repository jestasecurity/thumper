"""Honeytoken generators - fake but realistic credential file bodies.

The trick: each output is correct in *shape* (real prefixes like ``AKIA``,
``github_pat_``, the ``eyJ`` JWT header; correct file format) so a scanner
believes it, while the key material is cryptographically random garbage that
authenticates to nothing. When something reads the planted file, the tripwire
fires.

This is the Python port of the original ui/src/api/mock.ts generators. Token
generation lives on the SERVER (not the browser) because creating a tripwire
also mints a per-token HMAC secret and callback binding - security-relevant work
the client must not do.
"""
import json
import secrets

_HEX = "0123456789abcdef"
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def rand_hex(n: int) -> str:
    return _rand(_HEX, n)


def rand_b64(n: int) -> str:
    return _rand(_B64, n)


def generate_token(token_type: str) -> str:
    if token_type == "aws":
        key = rand_b64(16).upper().replace("+", "X").replace("/", "X")
        return (
            "[default]\n"
            f"aws_access_key_id = AKIA{key}\n"
            f"aws_secret_access_key = {rand_b64(40)}\n"
        )

    if token_type == "github":
        return (
            "github.com:\n"
            f"  oauth_token: github_pat_{rand_b64(22)}_{rand_b64(59)}\n"
            "  user: ci-deploy-bot\n"
        )

    if token_type == "gcp":
        return json.dumps(
            {
                "type": "service_account",
                "project_id": "prod-infra-2481",
                "private_key_id": rand_hex(40),
                "private_key": f"-----BEGIN PRIVATE KEY-----\n{rand_b64(64)}\n-----END PRIVATE KEY-----\n",
                "client_email": "deploy@prod-infra-2481.iam.gserviceaccount.com",
            },
            indent=2,
        )

    if token_type == "azure":
        return json.dumps(
            {"accessToken": f"eyJ0eXAiOi{rand_b64(120)}", "expiresOn": "2026-12-31 23:59:59"},
            indent=2,
        )

    if token_type == "ssh":
        return (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{rand_b64(64)}\n{rand_b64(64)}\n{rand_b64(40)}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )

    if token_type == "gitlab":
        pat = f"glpat-{rand_hex(20)}"
        return (
            "# GitLab Personal Access Token\n"
            f"GITLAB_TOKEN={pat}\n"
            f"GITLAB_API_URL=https://gitlab.com/api/v4\n"
        )

    if token_type == "npm":
        token = f"npm_{rand_hex(36)}"
        return f"//registry.npmjs.org/:_authToken={token}\n"

    raise ValueError(f"unknown token type: {token_type!r}")
