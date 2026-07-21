"""Datadog honeytoken plugin: create Datadog API keys as canaries and detect use.

Datadog's v2 API-keys endpoint reports `used_in_last_24_hours` / `date_last_used`
per key, so poll_usage checks each canary key and emits an event when it has been
used - no separate audit-log scrape needed. Uses httpx (the thumper HTTP client).
"""
import logging
from datetime import datetime, timezone

import httpx

from thumper.plugins.base import HoneytokenPlugin, PluginError, TokenUsageEvent

log = logging.getLogger("thumper.plugin.datadog")

TIMEOUT = 10


class Plugin(HoneytokenPlugin):
    def __init__(self, config: dict):
        super().__init__(config)
        self._site = None
        self._headers = None

    def _base_url(self) -> str:
        return f"https://api.{self._site}/api"

    def connect(self) -> None:
        site = self.config.get("site")
        api_key = self.config.get("api_key")
        app_key = self.config.get("app_key")
        if not site:
            raise PluginError("datadog: site is required")
        if not api_key or not app_key:
            raise PluginError("datadog: api_key and app_key are required")
        self._site = site
        self._headers = {
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "Content-Type": "application/json",
        }
        resp = httpx.get(f"{self._base_url()}/v1/validate",
                         headers=self._headers, timeout=TIMEOUT)
        if resp.status_code != 200:
            raise PluginError(
                f"Datadog authentication failed: {resp.status_code} {resp.text}")

    def _ensure_connected(self) -> None:
        if self._site is None:
            self.connect()

    def create_token(self, name: str, options: dict | None = None) -> dict:
        self._ensure_connected()
        resp = httpx.post(
            f"{self._base_url()}/v2/api_keys",
            headers=self._headers, timeout=TIMEOUT,
            json={"data": {"type": "api_keys", "attributes": {"name": name}}},
        )
        if resp.status_code not in (200, 201):
            raise PluginError(
                f"Failed to create Datadog API key: {resp.status_code} {resp.text}")
        data = resp.json()["data"]
        return {
            "token_id": data["id"],
            "token_type": "api_key",
            "key_name": data["attributes"]["name"],
            "key_value": data["attributes"].get("key", ""),
        }

    def revoke_token(self, token_id: str) -> None:
        self._ensure_connected()
        resp = httpx.delete(f"{self._base_url()}/v2/api_keys/{token_id}",
                            headers=self._headers, timeout=TIMEOUT)
        # 404 = already gone; treat as success (idempotent revoke).
        if resp.status_code not in (200, 204, 404):
            raise PluginError(
                f"Failed to delete Datadog API key: {resp.status_code} {resp.text}")

    def poll_usage(self, token_ids: list[str],
                   since: str | None = None) -> list[TokenUsageEvent]:
        self._ensure_connected()
        now = datetime.now(timezone.utc)
        events: list[TokenUsageEvent] = []
        for tid in token_ids:
            try:
                resp = httpx.get(f"{self._base_url()}/v2/api_keys/{tid}",
                                 headers=self._headers, timeout=TIMEOUT)
            except httpx.HTTPError as exc:
                log.warning("Datadog poll error for key %s: %s", tid, exc)
                continue
            if resp.status_code != 200:
                log.warning("Datadog key lookup failed for %s: %s", tid, resp.status_code)
                continue
            attrs = resp.json()["data"]["attributes"]
            if attrs.get("used_in_last_24_hours"):
                last_used = attrs.get("date_last_used") or now.isoformat()
                # event_id keys off the last-used timestamp so each distinct use
                # records once; the same reading across poll cycles dedups.
                events.append(TokenUsageEvent(
                    token_id=tid,
                    timestamp=last_used,
                    action="api_key_used",
                    extra={"event_id": f"usage_{tid}_{last_used}"},
                ))
        return events
