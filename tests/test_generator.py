"""Unit tests for honeytoken generators (server/thumper/tokens/generator.py).

Pure functions — no DB, no async, no fixtures needed.
"""
import json

import pytest

from thumper.tokens.generator import generate_token, rand_b64, rand_hex


class TestRandHex:
    def test_returns_requested_length(self):
        for n in (1, 8, 16, 32):
            result = rand_hex(n)
            assert len(result) == n

    def test_only_hex_alphabet(self):
        result = rand_hex(100)
        assert all(c in "0123456789abcdef" for c in result)

    def test_zero_returns_empty(self):
        assert rand_hex(0) == ""


class TestRandB64:
    def test_returns_requested_length(self):
        for n in (1, 8, 22, 64):
            result = rand_b64(n)
            assert len(result) == n

    def test_only_b64_alphabet(self):
        result = rand_b64(200)
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        assert all(c in allowed for c in result)

    def test_zero_returns_empty(self):
        assert rand_b64(0) == ""


class TestGenerateToken:
    def test_aws_contains_default_section_and_akia(self):
        token = generate_token("aws")
        assert "[default]" in token
        assert "AKIA" in token
        assert "aws_secret_access_key" in token

    def test_github_contains_github_pat(self):
        token = generate_token("github")
        assert "github_pat_" in token
        assert "oauth_token" in token

    def test_gcp_is_valid_json_with_service_account(self):
        token = generate_token("gcp")
        data = json.loads(token)
        assert data["type"] == "service_account"
        assert "private_key" in data
        assert "client_email" in data

    def test_azure_is_valid_json_with_eyj_token(self):
        token = generate_token("azure")
        data = json.loads(token)
        assert "accessToken" in data
        assert data["accessToken"].startswith("eyJ")

    def test_ssh_contains_openssh_private_key(self):
        token = generate_token("ssh")
        assert "BEGIN OPENSSH PRIVATE KEY" in token
        assert "END OPENSSH PRIVATE KEY" in token

    def test_gitlab_contains_glpat(self):
        token = generate_token("gitlab")
        assert "glpat-" in token
        assert "GITLAB_TOKEN" in token

    def test_npm_contains_auth_token(self):
        token = generate_token("npm")
        assert "_authToken=npm_" in token
        assert "//registry.npmjs.org/" in token

    def test_invalid_type_raises_valueerror(self):
        with pytest.raises(ValueError, match="nope"):
            generate_token("nope")
        with pytest.raises(ValueError, match="unknown"):
            generate_token("invalid_type")
