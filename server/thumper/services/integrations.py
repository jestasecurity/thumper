"""Helpers for reading/merging integration config and masking secrets."""
from sqlalchemy.orm import Session

from .. import store
from .secrets_crypto import unpack_config


MAX_CONFIG_VALUE_LENGTH = 4096


class ConfigValidationError(Exception):
    """Raised when incoming integration config fails schema validation."""


def validate_config(manifest: dict, incoming: dict) -> None:
    """Reject config keys the plugin's manifest doesn't declare, and cap value
    length. save_integration previously merged any caller-supplied dict with no
    allowlist. This mirrors mask_config's config_schema iteration to build the
    allowlist instead of an echo-list."""
    allowed = {field["key"] for field in manifest.get("config_schema", [])}
    unknown = set(incoming) - allowed
    if unknown:
        raise ConfigValidationError(
            f"unknown config key(s) for {manifest['name']!r}: {', '.join(sorted(unknown))}"
        )
    for key, value in incoming.items():
        if isinstance(value, str) and len(value) > MAX_CONFIG_VALUE_LENGTH:
            raise ConfigValidationError(
                f"{key!r} exceeds max length of {MAX_CONFIG_VALUE_LENGTH} characters"
            )


def mask_config(manifest: dict, config: dict) -> dict:
    """Echo non-secret config back for display; replace secrets with bullets."""
    masked: dict = {}
    for field in manifest.get("config_schema", []):
        value = config.get(field["key"])
        if value in (None, ""):
            continue
        masked[field["key"]] = "••••••••" if field["type"] == "secret" else value
    return masked


def saved_config(db: Session, plugin: str) -> dict:
    row = store.get_integration(db, plugin)
    return unpack_config(row.config_json) if row else {}


def merge_config(existing: dict, incoming: dict) -> dict:
    """Apply non-empty incoming values over existing. Blank secret fields left
    untouched so re-saving a form without re-typing secrets doesn't wipe them."""
    return {**existing, **{k: v for k, v in incoming.items() if v not in (None, "")}}


def redact_secrets(text: str, config: dict) -> str:
    """Strip credential material from an error string before it's stored/logged.
    Replaces each non-trivial config value (tokens, and full URLs that may embed
    a token in their path/query, e.g. a Slack webhook) with a placeholder (#33).
    Over-redaction is acceptable - never leak a secret into a delivery error.

    Matching is verbatim only, not encoding-aware: it catches the secret exactly
    as configured (the documented case - httpx echoes the URL as given), but not
    transformed forms (percent-/JSON-/basic-auth-encoded), where a layer has
    re-encoded the value. The residual risk is under-redaction of an encoded
    secret; fine for the current threat model, but worth knowing before relying
    on this for anything that round-trips the value through another encoder."""
    if not text:
        return text
    # Longest first so a URL containing a token redacts as one unit.
    for value in sorted((v for v in config.values() if isinstance(v, str)),
                        key=len, reverse=True):
        if len(value) >= 6:
            text = text.replace(value, "•••")
    return text
