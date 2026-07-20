"""Load and serve canary secret templates from the templates/ directory.

A template describes a realistic-looking (but fake) credential for a popular
SaaS tool: its display name, category, the value format (prefix/length/charset),
and suggested vault paths. `generate_value` mints a fresh fake credential from a
template; the value authenticates to nothing - a read of it in a secrets manager
is the signal.
"""
import secrets
import string

import yaml

from ..config import REPO_ROOT

_TEMPLATES_DIR = REPO_ROOT / "templates"
_cache: list[dict] | None = None

_CHARSETS = {
    "alphanumeric": string.ascii_letters + string.digits,
    "alphanumeric_dash": string.ascii_letters + string.digits + "-",
    "alphanumeric_special": string.ascii_letters + string.digits + "-_",
    "hex": string.hexdigits[:16],
    "uppercase_alphanumeric": string.ascii_uppercase + string.digits,
}


def _load_all() -> list[dict]:
    global _cache
    if _cache is not None:
        return _cache
    templates: list[dict] = []
    for path in sorted(_TEMPLATES_DIR.glob("*.yaml")):
        with open(path) as f:
            templates.append(yaml.safe_load(f))
    templates.sort(key=lambda t: (t.get("category", ""), t.get("name", "")))
    _cache = templates
    return _cache


def reset_cache() -> None:
    """Drop the cached template list (mainly for tests)."""
    global _cache
    _cache = None


def list_templates() -> list[dict]:
    """Every parsed template, sorted by category then name."""
    return _load_all()


def get_template(slug: str) -> dict | None:
    """Return the template with the given slug, or None."""
    for t in _load_all():
        if t["slug"] == slug:
            return t
    return None


def generate_value(template: dict) -> str:
    """Mint a fresh fake credential matching the template's format spec."""
    fmt = template["format"]
    prefix = fmt.get("prefix", "")
    total_length = fmt["length"]
    charset = _CHARSETS.get(fmt.get("charset", "alphanumeric"),
                            _CHARSETS["alphanumeric"])
    suffix_length = total_length - len(prefix)
    suffix = "".join(secrets.choice(charset) for _ in range(suffix_length))
    return prefix + suffix
