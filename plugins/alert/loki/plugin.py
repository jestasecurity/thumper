"""Loki alert plugin: push the fired-tripwire event to a Loki stream."""
import json
import time

import httpx

from thumper.plugins.base import AlertPlugin, PluginError
from thumper.services.ssrf import assert_url_allowed


class Plugin(AlertPlugin):
    def alert(self, event: dict) -> None:
        url = self.config.get("loki_url")
        if not url:
            raise PluginError("loki: loki_url is required")
        assert_url_allowed(url)  # SSRF guard (#74)

        labels = {"app": "thumper", "tripwire": event.get("tripwire_name", "")}
        for pair in (self.config.get("labels") or "").split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                labels[k.strip()] = v.strip()

        payload = {
            "streams": [{
                "stream": labels,
                "values": [[str(time.time_ns()), json.dumps(event)]],
            }]
        }
        headers = {"content-type": "application/json"}
        if self.config.get("api_key"):
            headers["Authorization"] = f"Bearer {self.config['api_key']}"

        resp = httpx.post(url, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()
