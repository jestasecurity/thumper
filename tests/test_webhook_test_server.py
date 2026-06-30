import importlib.util
import hashlib
import hmac
from pathlib import Path

TOOL_FILE = Path(__file__).resolve().parents[1] / "tools" / "webhook_test_server.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("webhook_test_server", TOOL_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _good_sig(secret, ts, body):
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def test_check_signature_accepts_valid_fresh():
    tool = load_tool()
    body = b'{"x":1}'
    ok, reason = tool.check_signature("s", ts=1000, body=body,
                                      signature=_good_sig("s", 1000, body), now=1100)
    assert ok is True
    assert reason == "ok"


def test_check_signature_rejects_stale():
    tool = load_tool()
    body = b'{"x":1}'
    ok, reason = tool.check_signature("s", ts=1000, body=body,
                                      signature=_good_sig("s", 1000, body), now=1400)
    assert ok is False
    assert "stale" in reason


def test_check_signature_rejects_future_timestamp():
    tool = load_tool()
    body = b'{"x":1}'
    # 120s ahead: past the 60s forward cap -> rejected even though the MAC is valid.
    ok, reason = tool.check_signature("s", ts=1120, body=body,
                                      signature=_good_sig("s", 1120, body), now=1000)
    assert ok is False
    assert "future" in reason


def test_check_signature_allows_small_forward_drift():
    tool = load_tool()
    body = b'{"x":1}'
    ok, reason = tool.check_signature("s", ts=1060, body=body,
                                      signature=_good_sig("s", 1060, body), now=1000)
    assert ok is True


def test_check_signature_rejects_bad_mac():
    tool = load_tool()
    ok, reason = tool.check_signature("s", ts=1000, body=b"x",
                                      signature="sha256=dead", now=1000)
    assert ok is False
    assert "signature" in reason


def test_check_signature_no_secret_accepts_anything():
    tool = load_tool()
    ok, reason = tool.check_signature(None, ts=None, body=b"x", signature=None, now=1000)
    assert ok is True


def test_receiver_accepts_production_signer_output():
    # The reference receiver and the production signer must agree byte-for-byte:
    # a signature produced by services.signing.sign_timestamped must be accepted
    # by this server, and a tampered body must be rejected. Guards against the two
    # implementations' "<ts>." + body construction silently drifting apart.
    from thumper.services.signing import sign_timestamped

    tool = load_tool()
    secret, ts, body = "s3cr3t", 1749369600, b'{"tripwire_name":"aws-creds"}'
    sig = sign_timestamped(secret, ts, body)

    ok, reason = tool.check_signature(secret, ts=ts, body=body, signature=sig, now=ts)
    assert ok is True, reason

    ok, _ = tool.check_signature(secret, ts=ts, body=body + b"x", signature=sig, now=ts)
    assert ok is False  # tampered body no longer matches the production signature
