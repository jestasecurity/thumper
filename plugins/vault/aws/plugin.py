import json
import logging
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

from thumper.plugins.base import AccessEvent, PluginError, VaultPlugin

log = logging.getLogger("thumper.plugin.aws")


class Plugin(VaultPlugin):
    def __init__(self, config: dict):
        super().__init__(config)
        self._sm_client = None
        self._ct_client = None
        self._last_poll_time: str | None = None

    def connect(self) -> None:
        region = self.config.get("region")
        if not region:
            raise PluginError("region is required")
        access_key = self.config.get("access_key_id")
        secret_key = self.config.get("secret_access_key")
        if not access_key or not secret_key:
            raise PluginError("access_key_id and secret_access_key are required")
        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
            )
            self._sm_client = session.client("secretsmanager")
            self._ct_client = session.client("cloudtrail")
            self._sm_client.list_secrets(MaxResults=1)
        except ClientError as exc:
            raise PluginError(f"AWS authentication failed: {exc}") from exc
        except Exception as exc:
            raise PluginError(f"AWS connection failed: {exc}") from exc

    def _ensure_connected(self) -> None:
        if self._sm_client is None:
            self.connect()

    def plant(self, path: str, value: str, metadata: dict) -> None:
        self._ensure_connected()
        prefix = self.config.get("prefix", "")
        full_name = f"{prefix}{path}" if prefix else path
        tags = [{"Key": k, "Value": str(v)} for k, v in metadata.items()]
        try:
            self._sm_client.create_secret(
                Name=full_name,
                SecretString=value,
                Description="Thumper canary secret",
                Tags=tags,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceExistsException":
                try:
                    self._sm_client.put_secret_value(
                        SecretId=full_name, SecretString=value)
                except ClientError as update_exc:
                    raise PluginError(
                        f"Failed to update secret {full_name}: {update_exc}"
                    ) from update_exc
            else:
                raise PluginError(
                    f"Failed to create secret {full_name}: {exc}"
                ) from exc

    def delete(self, path: str) -> None:
        self._ensure_connected()
        prefix = self.config.get("prefix", "")
        full_name = f"{prefix}{path}" if prefix else path
        try:
            self._sm_client.delete_secret(
                SecretId=full_name,
                ForceDeleteWithoutRecovery=True,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise PluginError(
                    f"Failed to delete secret {full_name}: {exc}"
                ) from exc

    def poll(self, paths: list[str], since: str | None = None) -> list[AccessEvent]:
        self._ensure_connected()
        prefix = self.config.get("prefix", "")
        watched = {}
        for p in paths:
            full_name = f"{prefix}{p}" if prefix else p
            watched[full_name] = p

        now = datetime.now(timezone.utc)
        # CloudTrail delivers events 5-15 min after they occur, but timestamps
        # reflect the original event time. Look back an extra 20 min so we
        # don't miss events that arrived after our last poll window closed.
        # Deduplication via event_id prevents double-processing.
        lookback = timedelta(minutes=20)
        if since:
            start = datetime.fromisoformat(since) - lookback
        elif self._last_poll_time:
            start = datetime.fromisoformat(self._last_poll_time) - lookback
        else:
            start = now - timedelta(minutes=30)

        events = []
        try:
            paginator = self._ct_client.get_paginator("lookup_events")
            pages = paginator.paginate(
                LookupAttributes=[{
                    "AttributeKey": "EventName",
                    "AttributeValue": "GetSecretValue",
                }],
                StartTime=start,
                EndTime=now,
            )
            for page in pages:
                for event in page.get("Events", []):
                    resources = event.get("Resources", [])
                    secret_name = None
                    for r in resources:
                        if r.get("ResourceType") == "AWS::SecretsManager::Secret":
                            secret_name = r.get("ResourceName")
                            break
                    if not secret_name:
                        ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                        req_params = ct_event.get("requestParameters", {})
                        secret_name = req_params.get("secretId")
                    if secret_name and secret_name not in watched and ":secret:" in secret_name:
                        short = secret_name.split(":secret:")[-1].rsplit("-", 1)[0]
                        if short in watched:
                            secret_name = short
                    if secret_name and secret_name in watched:
                        ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                        events.append(AccessEvent(
                            path=watched[secret_name],
                            timestamp=event.get("EventTime", now).isoformat()
                            if isinstance(event.get("EventTime"), datetime)
                            else str(event.get("EventTime", "")),
                            accessor=event.get("Username"),
                            source_ip=ct_event.get("sourceIPAddress"),
                            policy=None,
                            extra={"event_id": event.get("EventId")},
                        ))
        except ClientError as exc:
            log.warning("CloudTrail lookup failed: %s", exc)

        self._last_poll_time = now.isoformat()
        return events
