"""insecure_base_url() flags a plaintext, non-loopback BASE_URL, and startup
fails closed on it (MITM -> root RCE) unless THUMPER_ALLOW_INSECURE_BASE_URL is
set (#75). http://localhost (dev) is not flagged."""
import pytest

from thumper.config import base_url_fail_closed, insecure_base_url


@pytest.mark.parametrize("url", [
    "http://thumper.example.com",
    "http://thumper.example.com:8000",
    "http://10.0.0.5:8000",
])
def test_plaintext_non_loopback_is_flagged(url):
    assert insecure_base_url(url) is True


@pytest.mark.parametrize("url", [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://[::1]:8000",
    "https://thumper.example.com",
    "https://localhost:8000",
])
def test_https_or_loopback_not_flagged(url):
    assert insecure_base_url(url) is False


def test_insecure_base_url_fails_closed_without_optout():
    # The dangerous config refuses to start when the operator hasn't opted in.
    assert base_url_fail_closed("http://thumper.example.com", allow_insecure=False) is True


def test_optout_downgrades_to_allowed():
    # Explicit opt-out lets it start (with a warning) - e.g. an isolated network.
    assert base_url_fail_closed("http://thumper.example.com", allow_insecure=True) is False


@pytest.mark.parametrize("url", ["https://thumper.example.com", "http://localhost:8000"])
def test_secure_or_loopback_never_fails_closed(url):
    # A safe BASE_URL starts regardless of the opt-out flag.
    assert base_url_fail_closed(url, allow_insecure=False) is False


def test_app_refuses_to_start_on_insecure_base_url(monkeypatch):
    from fastapi.testclient import TestClient

    from thumper import config, main
    monkeypatch.setattr(config, "BASE_URL", "http://thumper.example.com")
    monkeypatch.setattr(config, "ALLOW_INSECURE_BASE_URL", False)
    monkeypatch.setattr(main, "init_db", lambda: None)   # no DB side effects
    with pytest.raises(RuntimeError, match="Refusing to start"):
        with TestClient(main.app):
            pass


def test_app_starts_with_optout(monkeypatch):
    from fastapi.testclient import TestClient

    from thumper import config, main
    monkeypatch.setattr(config, "BASE_URL", "http://thumper.example.com")
    monkeypatch.setattr(config, "ALLOW_INSECURE_BASE_URL", True)
    monkeypatch.setattr(main, "init_db", lambda: None)
    with TestClient(main.app) as c:                       # startup must not raise
        assert c.get("/healthz").status_code == 200
