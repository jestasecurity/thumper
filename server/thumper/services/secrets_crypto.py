"""Encrypt integration config (plugin credentials) at rest (#24).

The whole serialized config blob is encrypted with Fernet when THUMPER_SECRET_KEY
is set; otherwise it's stored as plaintext (zero-config dev). Reads are
decrypt-or-passthrough, so existing plaintext rows keep working and become
encrypted the next time they're saved with a key configured.

Key rotation is not yet supported: there is a single active key, so changing
THUMPER_SECRET_KEY makes every existing encrypted row undecryptable
(ConfigDecryptError) until each integration's secrets are re-entered and saved.
A future version can decrypt-old/encrypt-new transparently with
cryptography.fernet.MultiFernet. Until then, treat a key change as a manual
re-enrollment of every integration secret.
"""
import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

from .. import config

_PREFIX = "fernet:"


class ConfigDecryptError(Exception):
    """Stored config is encrypted but can't be decrypted (key unset/changed)."""


def encryption_enabled() -> bool:
    return bool(config.SECRET_KEY)


def _fernet():
    if not config.SECRET_KEY:
        return None
    # Derive a valid 32-byte urlsafe-b64 Fernet key from any operator secret.
    key = base64.urlsafe_b64encode(hashlib.sha256(config.SECRET_KEY.encode()).digest())
    return Fernet(key)


def pack_config(cfg: dict) -> str:
    """Serialize config for storage, encrypting when a key is configured."""
    raw = json.dumps(cfg)
    fernet = _fernet()
    if fernet is None:
        return raw
    return _PREFIX + fernet.encrypt(raw.encode()).decode()


def unpack_config(stored: str) -> dict:
    """Inverse of pack_config. Plaintext (legacy / no-key) passes through."""
    if not stored:
        return {}
    if not stored.startswith(_PREFIX):
        return json.loads(stored)
    fernet = _fernet()
    if fernet is None:
        raise ConfigDecryptError(
            "integration config is encrypted but THUMPER_SECRET_KEY is not set")
    try:
        raw = fernet.decrypt(stored[len(_PREFIX):].encode()).decode()
    except InvalidToken as exc:
        raise ConfigDecryptError(
            "cannot decrypt integration config - wrong or changed "
            "THUMPER_SECRET_KEY") from exc
    return json.loads(raw)
