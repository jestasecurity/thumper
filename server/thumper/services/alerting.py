"""Route a fired-tripwire event to every configured alert plugin. Best-effort:
one plugin failing must never drop the alert or break the trigger response. Each
plugin's outcome is recorded in delivery_attempts so failures are visible instead
of silently logged.

The trigger endpoint schedules `deliver_alert` as a background task; it owns its
own session because the request-scoped one is closed once the response is sent.
"""
import json
import logging

from sqlalchemy.orm import Session

from .. import store
from ..db import SessionLocal
from .secrets_crypto import unpack_config
from ..plugins.registry import load_plugin

log = logging.getLogger("thumper.alerting")


def route_alert(db: Session, event: dict) -> None:
    alert_id = event.get("alert_id", "")
    for integration in store.list_integrations(db):
        if integration.kind != "alert" or not integration.configured:
            continue
        plugin_name = integration.plugin
        try:
            plugin = load_plugin(plugin_name, unpack_config(integration.config_json))
            plugin.alert(event)
            status, error = "ok", None
        except Exception as exc:  # noqa: BLE001 - best-effort fan-out
            log.warning("alert plugin %s failed: %s", plugin_name, exc)
            status, error = "failed", str(exc)
        try:
            store.record_delivery(db, alert_id=alert_id, plugin=plugin_name,
                                  status=status, error=error)
        except Exception:  # noqa: BLE001 - recording must not break fan-out
            db.rollback()
            log.exception("failed to record delivery for plugin %s", plugin_name)


def deliver_alert(event: dict) -> None:
    """Background-task entry point: open a fresh session, fan out, close."""
    db = SessionLocal()
    try:
        route_alert(db, event)
    except Exception:  # noqa: BLE001 - never let the background task raise
        log.exception("deliver_alert failed for alert %s", event.get("alert_id"))
    finally:
        db.close()
