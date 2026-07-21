"""Background poller: checks each secrets manager's audit log for canary reads.

A configured VaultConnection knows how to poll its manager (via its plugin); a
read of any planted canary secret becomes an alert. Runs on an interval so a read
fires without operator action. Dedup is by the manager's own event id (see
`store.record_canary_access`), so re-polling the same audit window is safe.
"""
import asyncio
import json
import logging

from sqlalchemy.orm import Session

from .. import store
from ..config import VAULT_POLL_INTERVAL
from ..db import SessionLocal
from ..models import iso_now
from ..plugins.registry import load_plugin
from .alerting import deliver_alert

log = logging.getLogger("thumper.vault_poller")


def poll_once(db: Session) -> int:
    """Run one poll cycle across all configured vault connections. Returns the
    number of newly-recorded access events (already-seen events are skipped)."""
    total = 0
    for vc in store.list_vault_connections(db):
        if not vc.configured:
            continue
        config = json.loads(vc.config_json)
        try:
            plugin = load_plugin(vc.plugin, config)
        except Exception as exc:
            log.warning("Failed to load plugin for %s: %s", vc.name, exc)
            continue
        secrets = store.list_planted_canary_secrets_for_connection(db, vc.id)
        if not secrets:
            continue
        paths = [cs.path for cs in secrets]
        path_to_secret = {cs.path: cs for cs in secrets}
        try:
            events = plugin.poll(paths, since=vc.last_poll_at)
        except Exception as exc:
            log.warning("Poll failed for %s: %s", vc.name, exc)
            continue
        for event in events:
            cs = path_to_secret.get(event.path)
            if cs is None:
                continue
            event_id = event.extra.get("event_id") if event.extra else None
            logged = store.record_canary_access(
                db, csid=cs.id, event_id=event_id, accessor=event.accessor,
                source_ip=event.source_ip, timestamp=event.timestamp or iso_now(),
            )
            if not logged:
                continue  # already recorded this exact read - do not re-alert
            alert = store.create_alert(
                db,
                deployment_id=cs.id,
                tripwire_id=cs.id,
                endpoint_id=vc.id,
                tripwire_name=f"{cs.template} canary ({cs.path})",
                endpoint_hostname=vc.name,
                token_type="vault_secret",
                timestamp=event.timestamp or iso_now(),
                triggered_by=event.accessor,
                accessed_path=cs.path,
                event_type="vault_read",
                os_user=event.accessor,
            )
            deliver_alert({
                "alert_id": alert.id,
                "event_type": "vault_read",
                "tripwire_name": alert.tripwire_name,
                "endpoint_hostname": vc.name,
                "vault_connection": vc.name,
                "template": cs.template,
                "path": cs.path,
                "accessor": event.accessor,
                "source_ip": event.source_ip,
                "policy": event.policy,
                "timestamp": event.timestamp,
                "message": (
                    f"Canary secret read detected: {cs.template} at "
                    f"{cs.path} in {vc.name} by {event.accessor}"
                ),
            })
            store.mark_canary_secret_accessed(db, cs.id)
            total += 1
        store.update_vault_last_poll(db, vc.id)
    return total


async def _poll_loop() -> None:
    """Async loop that calls poll_once on a regular interval."""
    log.info("Vault poller started (interval=%ds)", VAULT_POLL_INTERVAL)
    while True:
        db = SessionLocal()
        try:
            count = poll_once(db)
            if count:
                log.info("Vault poller detected %d access event(s)", count)
        except Exception:
            log.exception("Vault poller error")
        finally:
            db.close()
        await asyncio.sleep(VAULT_POLL_INTERVAL)


def start_poller() -> asyncio.Task:
    """Start the background poller as an asyncio task."""
    return asyncio.create_task(_poll_loop())
