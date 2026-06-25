"""Generic webhook alert plugin: POST the event JSON, optionally signed with a
replay-resistant timestamped HMAC.

When `signing_secret` is set, the body is signed together with a send-time unix
timestamp. Two headers travel with the request:
  X-Thumper-Timestamp: <unix seconds>
  X-Thumper-Signature: sha256=<hex of hmac(secret, "<ts>." + body)>
The receiver recomputes the HMAC and rejects requests whose timestamp is too old
(see tools/webhook_test_server.py for a reference verifier).
"""
import json
import time

import httpx

from thumper.plugins.base import AlertPlugin, PluginError
from thumper.services.signing import sign_timestamped
from thumper.services.ssrf import assert_url_allowed


def _now_unix() -> int:
    """Send-time, as a seam tests can monkeypatch."""
    return int(time.time())


class Plugin(AlertPlugin):
    def alert(self, event: dict) -> None:
        url = self.config.get("url")
        if not url:
            raise PluginError("webhook: url is required")
        assert_url_allowed(url)  # SSRF guard (#74)

        # Stamp send-time before serializing so the signed timestamp reflects when
        # the alert fired, not when JSON encoding happened to finish.
        ts = _now_unix()
        body = json.dumps(event).encode()
        headers = {"content-type": "application/json"}
        secret = self.config.get("signing_secret")
        if secret:
            headers["X-Thumper-Timestamp"] = str(ts)
            headers["X-Thumper-Signature"] = sign_timestamped(secret, ts, body)

        resp = httpx.post(url, content=body, headers=headers, timeout=10)
        resp.raise_for_status()
