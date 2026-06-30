import json

import pytest

from thumper.tokens.generator import generate_token, rand_b64, rand_hex


HEX_ALPHABET = set("0123456789abcdef")
B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


@pytest.mark.parametrize("length", [0, 1, 32])
def test_rand_hex_returns_requested_length_and_hex_alphabet(length):
    value = rand_hex(length)

    assert len(value) == length
    assert set(value) <= HEX_ALPHABET


@pytest.mark.parametrize("length", [0, 1, 32])
def test_rand_b64_returns_requested_length_and_base64_alphabet(length):
    value = rand_b64(length)

    assert len(value) == length
    assert set(value) <= B64_ALPHABET


def test_generate_aws_token_has_credentials_file_shape():
    token = generate_token("aws")

    assert "[default]" in token
    assert "aws_access_key_id = AKIA" in token
    assert "aws_secret_access_key = " in token


def test_generate_github_token_has_oauth_file_shape():
    token = generate_token("github")

    assert "github.com:" in token
    assert "oauth_token: github_pat_" in token
    assert "user: ci-deploy-bot" in token


def test_generate_gcp_token_has_service_account_json_shape():
    token = generate_token("gcp")
    data = json.loads(token)

    assert data["type"] == "service_account"
    assert data["project_id"] == "prod-infra-2481"
    assert len(data["private_key_id"]) == 40
    assert set(data["private_key_id"]) <= HEX_ALPHABET
    assert data["private_key"].startswith("-----BEGIN PRIVATE KEY-----\n")


def test_generate_azure_token_has_access_token_json_shape():
    token = generate_token("azure")
    data = json.loads(token)

    assert data["accessToken"].startswith("eyJ")
    assert data["expiresOn"] == "2026-12-31 23:59:59"


def test_generate_ssh_token_has_private_key_shape():
    token = generate_token("ssh")

    assert token.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    assert token.endswith("-----END OPENSSH PRIVATE KEY-----\n")


def test_generate_unknown_token_type_raises_value_error():
    with pytest.raises(ValueError, match="unknown token type"):
        generate_token("nope")
