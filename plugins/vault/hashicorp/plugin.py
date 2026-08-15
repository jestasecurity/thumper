import json
import logging

import hvac

from thumper.plugins.base import AccessEvent, PluginError, VaultPlugin

log = logging.getLogger("thumper.plugin.hashicorp")


class Plugin(VaultPlugin):
    def __init__(self, config: dict):
        super().__init__(config)
        self._client: hvac.Client | None = None
        self._last_audit_time: str | None = None

    def connect(self) -> None:
        url = self.config.get("url")
        if not url:
            raise PluginError("url is required")
        role_id = self.config.get("role_id")
        secret_id = self.config.get("secret_id")
        if not role_id or not secret_id:
            raise PluginError("role_id and secret_id are required")
        namespace = self.config.get("namespace") or None
        self._client = hvac.Client(url=url, namespace=namespace)
        try:
            resp = self._client.auth.approle.login(
                role_id=role_id, secret_id=secret_id)
            self._client.token = resp["auth"]["client_token"]
        except Exception as exc:
            raise PluginError(f"Vault authentication failed: {exc}") from exc
        if not self._client.is_authenticated():
            raise PluginError("Vault authentication failed: not authenticated")

    def _ensure_connected(self) -> None:
        if self._client is None:
            self.connect()

    def plant(self, path: str, value: str, metadata: dict) -> None:
        self._ensure_connected()
        mount = self.config.get("mount", "secret")
        secret_data = {"value": value, **metadata}
        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=path, secret=secret_data, mount_point=mount)
        except Exception as exc:
            raise PluginError(f"Failed to plant secret at {path}: {exc}") from exc

    def delete(self, path: str) -> None:
        self._ensure_connected()
        mount = self.config.get("mount", "secret")
        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path, mount_point=mount)
        except Exception as exc:
            raise PluginError(f"Failed to delete secret at {path}: {exc}") from exc

    def poll(self, paths: list[str], since: str | None = None) -> list[AccessEvent]:
        self._ensure_connected()
        # Seed the audit cutoff from the caller's `since` (the connection's last
        # poll time) on the first poll, so we don't re-scan the whole log.
        if since and not self._last_audit_time:
            self._last_audit_time = since
        mount = self.config.get("mount", "secret")
        entries = self._fetch_audit_entries()
        watched = {f"{mount}/data/{p}" for p in paths}
        events = []
        for entry in entries:
            if entry.get("type") != "response":
                continue
            req = entry.get("request", {})
            if req.get("operation") != "read":
                continue
            entry_path = req.get("path", "")
            if entry_path not in watched:
                continue
            auth = entry.get("auth", {})
            req_meta = entry.get("request_metadata", {})
            clean_path = entry_path.removeprefix(f"{mount}/data/")
            events.append(AccessEvent(
                path=clean_path,
                timestamp=entry.get("time", ""),
                accessor=auth.get("display_name"),
                source_ip=req_meta.get("remote_address"),
                policy=",".join(auth.get("policies", [])),
            ))
        if entries:
            last = entries[-1].get("time")
            if last:
                self._last_audit_time = last
        return events

    def _fetch_audit_entries(self) -> list[dict]:
        """Read audit log entries. This implementation reads from the file-based
        audit device. Override or extend for syslog/socket audit devices."""
        try:
            devices = self._client.sys.list_enabled_audit_devices()
        except Exception as exc:
            log.warning("Failed to list audit devices: %s", exc)
            return []
        for _name, device in devices.get("data", {}).items():
            if device.get("type") == "file":
                file_path = device.get("options", {}).get("file_path")
                if file_path:
                    return self._read_audit_file(file_path)
        return []

    def _read_audit_file(self, file_path: str) -> list[dict]:
        """Read the NDJSON audit log file, returning entries newer than the last
        poll."""
        entries = []
        try:
            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ts = entry.get("time", "")
                    if self._last_audit_time and ts <= self._last_audit_time:
                        continue
                    entries.append(entry)
        except FileNotFoundError:
            log.warning("Audit log file not found: %s", file_path)
        except PermissionError:
            log.warning("Cannot read audit log file: %s", file_path)
        return entries
