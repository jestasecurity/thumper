"""AWS honeytoken plugin: create canary IAM access keys and detect use.

Each canary is a dedicated IAM user (`thumper-canary-*`) with a deny-all inline
policy, so the key can do nothing even if leaked - but any USE of it is recorded
in CloudTrail, which poll_usage looks up by AccessKeyId.
"""
import json
import logging
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

from thumper.plugins.base import HoneytokenPlugin, PluginError, TokenUsageEvent

log = logging.getLogger("thumper.plugin.aws")

CANARY_PREFIX = "thumper-canary-"
DENY_ALL_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
})


class Plugin(HoneytokenPlugin):
    def __init__(self, config: dict):
        super().__init__(config)
        self._session = None

    def _get_session(self):
        if self._session is None:
            self._session = boto3.Session(
                aws_access_key_id=self.config["access_key_id"],
                aws_secret_access_key=self.config["secret_access_key"],
                region_name=self.config.get("region", "us-east-1"),
            )
        return self._session

    def connect(self) -> None:
        if not self.config.get("access_key_id") or not self.config.get("secret_access_key"):
            raise PluginError("aws: access_key_id and secret_access_key are required")
        try:
            identity = self._get_session().client("sts").get_caller_identity()
            log.info("AWS honeytoken connected as %s", identity.get("Arn"))
        except ClientError as exc:
            raise PluginError(f"AWS connection failed: {exc}") from exc

    def create_token(self, name: str, options: dict | None = None) -> dict:
        iam = self._get_session().client("iam")
        username = f"{CANARY_PREFIX}{name.replace(' ', '-').lower()}"
        try:
            iam.create_user(UserName=username, Tags=[
                {"Key": "thumper", "Value": "canary"},
                {"Key": "canary-name", "Value": name},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityAlreadyExists":
                raise PluginError(f"Failed to create IAM user: {exc}") from exc
        try:
            # Deny-all so a leaked canary key is inert; only its USE matters (logged
            # in CloudTrail even when the call is denied).
            iam.put_user_policy(UserName=username, PolicyName="thumper-deny-all",
                                PolicyDocument=DENY_ALL_POLICY)
            key = iam.create_access_key(UserName=username)["AccessKey"]
        except ClientError as exc:
            raise PluginError(f"Failed to provision canary key: {exc}") from exc
        return {
            "token_id": key["AccessKeyId"],
            "token_type": "access_key",
            "username": username,
            "access_key_id": key["AccessKeyId"],
            "secret_access_key": key["SecretAccessKey"],
        }

    def revoke_token(self, token_id: str) -> None:
        iam = self._get_session().client("iam")
        try:
            for page in iam.get_paginator("list_users").paginate(PathPrefix="/"):
                for user in page["Users"]:
                    if not user["UserName"].startswith(CANARY_PREFIX):
                        continue
                    keys = iam.list_access_keys(UserName=user["UserName"])
                    if any(km["AccessKeyId"] == token_id
                           for km in keys["AccessKeyMetadata"]):
                        self._cleanup_user(iam, user["UserName"])
                        return
        except ClientError as exc:
            if "NoSuchEntity" not in str(exc):
                raise PluginError(f"Failed to delete access key: {exc}") from exc

    def _cleanup_user(self, iam, username: str) -> None:
        """Remove a canary user's keys + inline policies, then the user itself.
        (IAM refuses to delete a user that still has keys/policies attached.)"""
        try:
            for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
                iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"])
            for policy in iam.list_user_policies(UserName=username).get("PolicyNames", []):
                iam.delete_user_policy(UserName=username, PolicyName=policy)
            iam.delete_user(UserName=username)
        except ClientError:
            log.warning("Partial cleanup of canary user %s", username)

    def poll_usage(self, token_ids: list[str],
                   since: str | None = None) -> list[TokenUsageEvent]:
        ct = self._get_session().client("cloudtrail")
        now = datetime.now(timezone.utc)
        start = (datetime.fromisoformat(since) - timedelta(minutes=5)
                 if since else now - timedelta(hours=1))
        events: list[TokenUsageEvent] = []
        for tid in token_ids:
            try:
                resp = ct.lookup_events(
                    LookupAttributes=[{"AttributeKey": "AccessKeyId",
                                       "AttributeValue": tid}],
                    StartTime=start, EndTime=now, MaxResults=50,
                )
            except ClientError as exc:
                log.warning("CloudTrail lookup failed for key %s: %s", tid, exc)
                continue
            for event in resp.get("Events", []):
                resources = event.get("Resources") or []
                events.append(TokenUsageEvent(
                    token_id=tid,
                    timestamp=event["EventTime"].isoformat(),
                    actor=event.get("Username"),
                    source_ip=resources[0].get("ResourceName") if resources else None,
                    action=event.get("EventName"),
                    extra={"event_id": event.get("EventId")},
                ))
        return events
