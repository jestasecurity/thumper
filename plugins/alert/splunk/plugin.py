"""Splunk HEC alert plugin: report a fired tripwire as suspicious credential
access to a SIEM via the HTTP Event Collector."""
import httpx

from thumper.plugins.base import AlertPlugin, PluginError
from thumper.services.ssrf import assert_url_allowed


class Plugin(AlertPlugin):
    def alert(self, event: dict) -> None:
        url = self.config.get("hec_url")
        token = self.config.get("hec_token")
        if not url or not token:
            raise PluginError("splunk: hec_url and hec_token are required")
        assert_url_allowed(url)  # SSRF guard (#74)

        payload = {
            "event": {"signature": "thumper_honeytoken_access", **event},
            "sourcetype": self.config.get("sourcetype") or "thumper:alert",
        }
        if self.config.get("index"):
            payload["index"] = self.config["index"]

        resp = httpx.post(url, json=payload,
                          headers={"Authorization": f"Splunk {token}"}, timeout=10)
        resp.raise_for_status()
