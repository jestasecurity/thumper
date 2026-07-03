"""insecure_default_tokens() flags shared tokens left at the built-in dev
defaults, so startup can warn loudly instead of silently shipping guessable
credentials (#22)."""
from thumper.config import insecure_default_tokens


def test_both_defaults_flagged():
    assert insecure_default_tokens("dev-enroll-token", "dev-install-token") == [
        "THUMPER_ENROLL_TOKEN", "THUMPER_INSTALL_TOKEN"]


def test_no_defaults_when_overridden():
    assert insecure_default_tokens("s3cr3t-enroll", "s3cr3t-install") == []


def test_only_install_default():
    assert insecure_default_tokens("s3cr3t-enroll", "dev-install-token") == [
        "THUMPER_INSTALL_TOKEN"]


def test_admin_dev_default_flagged():
    # The value .env.example ships is publicly known; a prod deploy that copies
    # it must be warned even though ADMIN_TOKEN has no code default (fail-closed).
    assert insecure_default_tokens(
        "s3cr3t-enroll", "s3cr3t-install", "dev-admin-token") == [
        "THUMPER_ADMIN_TOKEN"]


def test_admin_secret_not_flagged():
    assert insecure_default_tokens(
        "s3cr3t-enroll", "s3cr3t-install", "s3cr3t-admin") == []


def test_all_three_defaults_flagged():
    assert insecure_default_tokens(
        "dev-enroll-token", "dev-install-token", "dev-admin-token") == [
        "THUMPER_ENROLL_TOKEN", "THUMPER_INSTALL_TOKEN", "THUMPER_ADMIN_TOKEN"]
