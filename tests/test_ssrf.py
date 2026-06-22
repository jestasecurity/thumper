"""SSRF guard for outbound integration URLs (#74)."""
import ipaddress

import pytest

from thumper.services import ssrf
from thumper.services.ssrf import SsrfError, assert_url_allowed


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/hook",
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://10.0.0.5:9000/x",
    "http://192.168.1.1/x",
    "http://172.16.0.9/x",
    "http://[::1]/x",
    "http://100.64.0.1/x",          # CGNAT (100.64/10) - missed by a basic list
    "http://240.0.0.1/x",           # reserved (240/4)
    "http://[::ffff:127.0.0.1]/x",  # IPv4-mapped IPv6 loopback
    "http://0.0.0.0/x",             # unspecified
])
def test_blocks_internal_targets(url):
    with pytest.raises(SsrfError):
        assert_url_allowed(url, allowlist=[])


def test_blocks_ipv4_mapped_metadata(monkeypatch):
    # A host resolving to an IPv4-mapped IPv6 form of the metadata IP must
    # still be blocked, regardless of CPython's version-dependent is_global.
    def fake_getaddrinfo(host, port, *a, **k):
        return [(10, 1, 6, "", ("::ffff:169.254.169.254", port or 80, 0, 0))]
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(SsrfError):
        assert_url_allowed("http://evil.example.com/x", allowlist=[])


@pytest.mark.parametrize("url", ["http://8.8.8.8/hook", "https://1.1.1.1/x"])
def test_allows_public_ips(url):
    assert_url_allowed(url, allowlist=[])  # no raise


def test_non_http_scheme_blocked():
    with pytest.raises(SsrfError):
        assert_url_allowed("file:///etc/passwd", allowlist=[])
    with pytest.raises(SsrfError):
        assert_url_allowed("gopher://10.0.0.1", allowlist=[])


def test_allowlist_permits_internal():
    allow = [ipaddress.ip_network("10.0.0.0/8")]
    assert_url_allowed("http://10.1.2.3/x", allowlist=allow)  # no raise


def test_hostname_resolving_to_internal_is_blocked(monkeypatch):
    # A public-looking hostname that resolves to the metadata IP must be caught.
    def fake_getaddrinfo(host, port, *a, **k):
        return [(2, 1, 6, "", ("169.254.169.254", port or 80))]
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(SsrfError):
        assert_url_allowed("http://evil.example.com/x", allowlist=[])


def test_assert_config_urls_allowed_checks_right_field():
    with pytest.raises(SsrfError):
        ssrf.assert_config_urls_allowed("webhook", {"url": "http://169.254.169.254/x"})
    # unrelated field is ignored
    ssrf.assert_config_urls_allowed("webhook", {"signing_secret": "s"})


def test_save_integration_blocks_metadata_url(client_db):
    # 169.254.x is not in the test allowlist, so saving it must 400.
    tc, _ = client_db
    resp = tc.post("/api/integrations/webhook",
                   json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert resp.status_code == 400


def test_save_integration_allows_public_url(client_db):
    tc, _ = client_db
    resp = tc.post("/api/integrations/webhook", json={"url": "http://8.8.8.8/hook"})
    assert resp.status_code == 200
