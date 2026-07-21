"""Salesforce honeytoken plugin: create a canary Connected App and detect use.

Authenticates via the OAuth 2.0 JWT Bearer flow (RS256-signed assertion), creates
a Connected App as the canary, and polls LoginHistory + OAuthToken for any use of
it. Uses httpx (the thumper HTTP client) and PyJWT for the assertion.
"""
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt

from thumper.plugins.base import HoneytokenPlugin, PluginError, TokenUsageEvent

log = logging.getLogger("thumper.plugin.salesforce")

TOKEN_ENDPOINT = "/services/oauth2/token"
API_VERSION = "v60.0"
TIMEOUT = 15


class Plugin(HoneytokenPlugin):
    def __init__(self, config: dict):
        super().__init__(config)
        self._access_token: str | None = None
        self._instance_url: str | None = None

    def _jwt_assertion(self) -> str:
        now = int(time.time())
        instance_url = self.config["instance_url"].rstrip("/")
        payload = {
            "iss": self.config["consumer_key"],
            "sub": self.config["username"],
            "aud": instance_url,
            "exp": now + 300,
        }
        return jwt.encode(payload, self.config["private_key"], algorithm="RS256")

    def connect(self) -> None:
        instance_url = self.config.get("instance_url", "").rstrip("/")
        if not all([instance_url, self.config.get("consumer_key"),
                    self.config.get("username"), self.config.get("private_key")]):
            raise PluginError(
                "salesforce: instance_url, consumer_key, username, and private_key "
                "are required")
        try:
            resp = httpx.post(
                f"{instance_url}{TOKEN_ENDPOINT}",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": self._jwt_assertion(),
                },
                timeout=TIMEOUT,
            )
        except httpx.HTTPError as exc:
            raise PluginError(f"Salesforce connection failed: {exc}") from exc
        if resp.status_code != 200:
            ct = resp.headers.get("content-type", "")
            body = resp.json() if ct.startswith("application/json") else {}
            raise PluginError(
                f"Salesforce JWT auth failed: {body.get('error_description', resp.text)}")
        data = resp.json()
        self._access_token = data["access_token"]
        self._instance_url = data.get("instance_url", instance_url)

    def _ensure_connected(self) -> None:
        if self._access_token is None:
            self.connect()

    def _api(self, method: str, path: str, **kwargs) -> httpx.Response:
        self._ensure_connected()
        return httpx.request(
            method, f"{self._instance_url}{path}",
            headers={"Authorization": f"Bearer {self._access_token}"},
            timeout=TIMEOUT, **kwargs)

    def create_token(self, name: str, options: dict | None = None) -> dict:
        app_name = f"Thumper_Canary_{name.replace(' ', '_')}"
        resp = self._api(
            "POST",
            f"/services/data/{API_VERSION}/tooling/sobjects/ConnectedApplication",
            json={
                "FullName": app_name,
                "Metadata": {
                    "label": app_name,
                    "contactEmail": self.config.get("username"),
                    "oauthConfig": {
                        "callbackUrl": "https://localhost/callback",
                        "isAdminApproved": False,
                        "scopes": ["Api", "RefreshToken"],
                    },
                },
            },
        )
        if resp.status_code not in (200, 201):
            raise PluginError(
                f"Failed to create Connected App: {resp.status_code} {resp.text}")
        app_id = resp.json().get("id", app_name)
        # Resolve the durable record Id (the create response id may be the tooling
        # object id); fall back to the create result if the lookup can't find it.
        lookup = self._api(
            "GET", f"/services/data/{API_VERSION}/tooling/query",
            params={"q": f"SELECT Id, Name FROM ConnectedApplication "
                         f"WHERE Name = '{app_name}' LIMIT 1"},
        )
        if lookup.status_code == 200:
            records = lookup.json().get("records", [])
            if records:
                app_id = records[0]["Id"]
        return {"token_id": app_id, "token_type": "connected_app", "app_name": app_name}

    def revoke_token(self, token_id: str) -> None:
        resp = self._api(
            "DELETE",
            f"/services/data/{API_VERSION}/tooling/sobjects/ConnectedApplication/{token_id}",
        )
        if resp.status_code not in (200, 204, 404):
            raise PluginError(
                f"Failed to delete Connected App: {resp.status_code} {resp.text}")

    def poll_usage(self, token_ids: list[str],
                   since: str | None = None) -> list[TokenUsageEvent]:
        now = datetime.now(timezone.utc)
        if since:
            start = datetime.fromisoformat(since) - timedelta(minutes=10)
        else:
            start = now - timedelta(hours=1)
        start_str = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        events: list[TokenUsageEvent] = []
        for token_id in token_ids:
            events.extend(self._login_history(token_id, start_str, now))
            events.extend(self._oauth_usage(token_id, start_str, now))
        return events

    def _login_history(self, token_id, start_str, now) -> list[TokenUsageEvent]:
        try:
            resp = self._api(
                "GET", f"/services/data/{API_VERSION}/query",
                params={"q": (
                    "SELECT Id, UserId, LoginTime, SourceIp, Application, LoginType "
                    "FROM LoginHistory "
                    f"WHERE LoginTime > {start_str} AND Application = '{token_id}' "
                    "ORDER BY LoginTime DESC LIMIT 50"
                )},
            )
        except httpx.HTTPError as exc:
            log.warning("Salesforce LoginHistory query failed for %s: %s", token_id, exc)
            return []
        if resp.status_code != 200:
            return []
        return [
            TokenUsageEvent(
                token_id=token_id,
                timestamp=r.get("LoginTime", now.isoformat()),
                actor=r.get("UserId"), source_ip=r.get("SourceIp"),
                action=r.get("LoginType", "login"),
                extra={"event_id": r.get("Id")},
            )
            for r in resp.json().get("records", [])
        ]

    def _oauth_usage(self, token_id, start_str, now) -> list[TokenUsageEvent]:
        try:
            resp = self._api(
                "GET", f"/services/data/{API_VERSION}/query",
                params={"q": (
                    "SELECT Id, AppName, LastUsedDate, UseCount, UserId "
                    "FROM OAuthToken "
                    f"WHERE AppName = '{token_id}' AND LastUsedDate > {start_str} "
                    "LIMIT 50"
                )},
            )
        except httpx.HTTPError as exc:
            log.warning("Salesforce OAuthToken query failed for %s: %s", token_id, exc)
            return []
        if resp.status_code != 200:
            return []
        return [
            TokenUsageEvent(
                token_id=token_id,
                timestamp=r.get("LastUsedDate", now.isoformat()),
                actor=r.get("UserId"), source_ip=None,
                action=f"oauth_usage (count: {r.get('UseCount', 0)})",
                extra={"event_id": f"oauth_{r.get('Id')}"},
            )
            for r in resp.json().get("records", [])
        ]
