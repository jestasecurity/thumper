"""Background poller: checks each SaaS platform's audit log for honeytoken use.

A configured HoneytokenConnection knows how to poll its platform (via its
plugin); a use of any active honeytoken becomes an alert. Runs on an interval so
a use fires without operator action. Dedup is by the platform's own event id (see
`store.record_honeytoken_usage`), so re-polling the same audit window is safe.
"""
import asyncio
import json
import logging

from sqlalchemy.orm import Session

from .. import store
from ..config import HONEYTOKEN_POLL_INTERVAL
from ..db import SessionLocal
from ..models import iso_now
from ..plugins.registry import load_plugin
from .alerting import deliver_alert

log = logging.getLogger("thumper.honeytoken_poller")


def poll_once(db: Session) -> int:
    """Run one poll cycle across all configured honeytoken connections. Returns
    the number of newly-recorded usage events (already-seen events are skipped)."""
    total = 0
    for conn in store.list_honeytoken_connections(db):
        if not conn.configured:
            continue
        config = json.loads(conn.config_json)
        try:
            plugin = load_plugin(conn.plugin, config)
        except Exception as exc:
            log.warning("Failed to load plugin for %s: %s", conn.name, exc)
            continue
        tokens = store.list_active_honeytokens_for_connection(db, conn.id)
        if not tokens:
            continue
        token_id_map = {ht.token_id: ht for ht in tokens}
        try:
            events = plugin.poll_usage(list(token_id_map.keys()), since=conn.last_poll_at)
        except Exception as exc:
            log.warning("Poll failed for %s: %s", conn.name, exc)
            continue
        for event in events:
            ht = token_id_map.get(event.token_id)
            if ht is None:
                continue
            event_id = event.extra.get("event_id") if event.extra else None
            logged = store.record_honeytoken_usage(
                db, htid=ht.id, event_id=event_id, actor=event.actor,
                source_ip=event.source_ip, action=event.action,
                timestamp=event.timestamp or iso_now(),
            )
            if not logged:
                continue  # already recorded this exact use - do not re-alert
            store.mark_honeytoken_used(db, ht.id)
            alert = store.create_alert(
                db,
                deployment_id=ht.id,
                tripwire_id=ht.id,
                endpoint_id=conn.id,
                tripwire_name=f"{ht.name} ({conn.name})",
                endpoint_hostname=conn.name,
                token_type=ht.token_type,
                timestamp=event.timestamp or iso_now(),
                triggered_by=event.actor,
                accessed_path=None,
                event_type="honeytoken_usage",
                os_user=event.actor,
            )
            deliver_alert({
                "alert_id": alert.id,
                "event_type": "honeytoken_usage",
                "tripwire_name": alert.tripwire_name,
                "endpoint_hostname": conn.name,
                "platform": conn.plugin,
                "token_name": ht.name,
                "token_type": ht.token_type,
                "actor": event.actor,
                "source_ip": event.source_ip,
                "action": event.action,
                "timestamp": event.timestamp,
                "message": (
                    f"Honeytoken usage detected: {ht.name} on "
                    f"{conn.name} ({conn.plugin}) by {event.actor}"
                ),
            })
            total += 1
        store.update_honeytoken_last_poll(db, conn.id)
    return total


async def _poll_loop() -> None:
    """Async loop that calls poll_once on a regular interval."""
    log.info("Honeytoken poller started (interval=%ds)", HONEYTOKEN_POLL_INTERVAL)
    while True:
        db = SessionLocal()
        try:
            count = poll_once(db)
            if count:
                log.info("Honeytoken poller detected %d usage event(s)", count)
        except Exception:
            log.exception("Honeytoken poller error")
        finally:
            db.close()
        await asyncio.sleep(HONEYTOKEN_POLL_INTERVAL)


def start_poller() -> asyncio.Task:
    """Start the background poller as an asyncio task."""
    return asyncio.create_task(_poll_loop())
