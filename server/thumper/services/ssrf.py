"""SSRF guard for operator-configured outbound integration URLs (#74).

Integration targets (webhook / loki / splunk / jamf) are fetched server-side, so
an attacker-set URL could reach internal services or cloud metadata. Block any
non-globally-routable destination by default (private / loopback / link-local /
CGNAT / reserved); operators opt-in real internal hosts via
THUMPER_ALLOWED_HOOK_CIDRS. The host is resolved and every resolved IP is
checked, so a hostname pointing at an internal address is caught.

Known gap (TOCTOU / DNS rebinding): we validate the IPs resolved here, but httpx
re-resolves the host when it sends the request, so a host that returns a public
IP now and an internal IP a moment later still gets through. Acceptable for
operator-set URLs as v1; the real fix is to pin a validated IP for the actual
connection. Tracked alongside the SSH-tunnel follow-up.
"""
import ipaddress
import socket
from urllib.parse import urlparse

from ..config import ALLOWED_HOOK_CIDRS

# Which config fields hold an outbound URL, per plugin (for save-time validation).
INTEGRATION_URL_FIELDS = {
    "webhook": ("url",),
    "loki": ("loki_url",),
    "splunk": ("hec_url",),
    "mdm": ("base_url",),
}


class SsrfError(Exception):
    """An outbound URL targets a blocked (internal) address or is malformed."""


def _ip_blocked(ip: str, allowlist) -> bool:
    addr = ipaddress.ip_address(ip)
    # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) so the embedded IPv4 is
    # classified directly. is_global only handles these correctly on CPython
    # 3.12.4+, and unwrapping also lets IPv4 allowlist CIDRs match.
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if any(addr in net for net in allowlist):
        return False
    # Block anything not globally routable: covers private, loopback,
    # link-local, CGNAT (100.64/10), reserved (240/4) and unspecified ranges
    # that a hand-maintained net list is easy to leave incomplete.
    return not addr.is_global


def assert_url_allowed(url: str, *, allowlist=None) -> None:
    """Raise SsrfError unless `url` is an http(s) URL whose every resolved IP is
    public (or explicitly allowlisted)."""
    allowlist = ALLOWED_HOOK_CIDRS if allowlist is None else allowlist
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SsrfError(f"unsupported URL scheme: {parsed.scheme or '(none)'!r}")
    host = parsed.hostname
    if not host:
        raise SsrfError("URL has no host")
    try:
        infos = socket.getaddrinfo(host, parsed.port, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SsrfError(f"cannot resolve host {host!r}") from exc
    for info in infos:
        ip = info[4][0]
        if _ip_blocked(ip, allowlist):
            raise SsrfError(
                f"blocked outbound target {host} -> {ip} (private/loopback/"
                "link-local; allow it via THUMPER_ALLOWED_HOOK_CIDRS)")


def assert_config_urls_allowed(plugin: str, config: dict) -> None:
    """Validate every URL field in a plugin's config (save-time check)."""
    for key in INTEGRATION_URL_FIELDS.get(plugin, ()):
        val = (config.get(key) or "").strip()
        if val:
            assert_url_allowed(val)
