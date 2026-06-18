"""insecure_base_url() flags a plaintext, non-loopback BASE_URL so startup can
warn about the MITM/RCE exposure (#75). http://localhost (dev) is not flagged."""
import pytest

from thumper.config import insecure_base_url


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
