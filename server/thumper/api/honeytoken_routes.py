"""API routes for honeytoken connections and tokens (third-party SaaS canaries)."""
import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import store
from ..db import get_db
from ..models import (
    CreateHoneytokenConnectionIn, CreateHoneytokenIn, HoneytokenConnectionOut,
    HoneytokenOut, HoneytokenUsageLogOut, UpdateHoneytokenConnectionIn,
)
from ..plugins.registry import get_manifest, load_plugin
from ..services.integrations import mask_config, merge_config

log = logging.getLogger("thumper.honeytokens")

honeytoken_router = APIRouter(prefix="/honeytokens", tags=["honeytokens"])


def _connection_out(row, manifest) -> dict:
    config = json.loads(row.config_json)
    masked = mask_config(manifest, config) if manifest else config
    return HoneytokenConnectionOut(
        id=row.id, name=row.name, plugin=row.plugin,
        configured=row.configured, config=masked,
        last_poll_at=row.last_poll_at, created_at=row.created_at,
    ).model_dump()


def _token_out(row, connection_name: str = "") -> dict:
    return HoneytokenOut(
        id=row.id, connection_id=row.connection_id,
        connection_name=connection_name, name=row.name,
        token_id=row.token_id, token_type=row.token_type,
        state=row.state, created_at=row.created_at,
        last_used_at=row.last_used_at,
    ).model_dump()


# ── connections ──────────────────────────────────────────────────────────────

@honeytoken_router.get("/connections")
def list_connections(db: Session = Depends(get_db)):
    return [_connection_out(row, get_manifest(row.plugin))
            for row in store.list_honeytoken_connections(db)]


@honeytoken_router.post("/connections")
def create_connection(body: CreateHoneytokenConnectionIn,
                      db: Session = Depends(get_db)):
    manifest = get_manifest(body.plugin)
    if manifest is None or manifest.get("kind") != "honeytoken":
        raise HTTPException(400, f"Unknown honeytoken plugin: {body.plugin}")
    row = store.create_honeytoken_connection(
        db, name=body.name, plugin=body.plugin, config=body.config)
    return _connection_out(row, manifest)


@honeytoken_router.put("/connections/{hid}")
def update_connection(hid: str, body: UpdateHoneytokenConnectionIn,
                      db: Session = Depends(get_db)):
    row = store.get_honeytoken_connection(db, hid)
    if row is None:
        raise HTTPException(404, "Honeytoken connection not found")
    # merge_config keeps a masked/blank secret untouched (per mask_config).
    merged = merge_config(json.loads(row.config_json), body.config)
    updated = store.update_honeytoken_connection(db, hid, name=body.name, config=merged)
    return _connection_out(updated, get_manifest(updated.plugin))


@honeytoken_router.delete("/connections/{hid}")
def delete_connection(hid: str, db: Session = Depends(get_db)):
    row = store.get_honeytoken_connection(db, hid)
    if row:
        tokens = store.list_honeytokens_for_connection(db, hid)
        if tokens:
            # Best-effort: revoke live tokens on the platform before dropping the
            # connection, so we don't leave real (if fake) credentials behind.
            try:
                plugin = load_plugin(row.plugin, json.loads(row.config_json))
                for ht in tokens:
                    if ht.state in ("active", "triggered"):
                        try:
                            plugin.revoke_token(ht.token_id)
                        except Exception:
                            log.warning("Failed to revoke honeytoken %s", ht.token_id)
            except Exception:
                log.warning("Failed to load plugin to revoke tokens for %s", hid)
    if not store.delete_honeytoken_connection(db, hid):
        raise HTTPException(404, "Honeytoken connection not found")
    return {"status": "ok"}


@honeytoken_router.post("/connections/{hid}/test")
def test_connection(hid: str, db: Session = Depends(get_db)):
    row = store.get_honeytoken_connection(db, hid)
    if row is None:
        raise HTTPException(404, "Honeytoken connection not found")
    try:
        plugin = load_plugin(row.plugin, json.loads(row.config_json))
        plugin.test()
        store.set_honeytoken_connection_test(db, hid=hid, configured=True)
        return {"ok": True, "error": None}
    except Exception as exc:
        store.set_honeytoken_connection_test(db, hid=hid, configured=False)
        return {"ok": False, "error": str(exc)}


# ── tokens ───────────────────────────────────────────────────────────────────

@honeytoken_router.get("/tokens")
def list_tokens(db: Session = Depends(get_db)):
    conn_map = {c.id: c.name for c in store.list_honeytoken_connections(db)}
    return [_token_out(row, conn_map.get(row.connection_id, ""))
            for row in store.list_honeytokens(db)]


@honeytoken_router.post("/tokens")
def create_token(body: CreateHoneytokenIn, db: Session = Depends(get_db)):
    conn = store.get_honeytoken_connection(db, body.connection_id)
    if conn is None:
        raise HTTPException(404, "Honeytoken connection not found")
    if not conn.configured:
        raise HTTPException(400, "Connection not tested/configured yet")
    try:
        plugin = load_plugin(conn.plugin, json.loads(conn.config_json))
        result = plugin.create_token(body.name, options=body.options or None)
    except Exception as exc:
        raise HTTPException(400, f"Failed to create token: {exc}") from exc
    metadata = {k: v for k, v in result.items()
                if k not in ("token_id", "token_type")}
    ht = store.create_honeytoken(
        db, connection_id=conn.id, name=body.name,
        token_id=result["token_id"], token_type=result["token_type"],
        metadata=metadata)
    store.set_honeytoken_state(db, ht.id, "active")
    db.expire_all()
    out = _token_out(store.get_honeytoken(db, ht.id), conn.name)
    out["metadata"] = metadata
    return out


@honeytoken_router.delete("/tokens/{htid}")
def delete_token(htid: str, db: Session = Depends(get_db)):
    ht = store.get_honeytoken(db, htid)
    if ht is None:
        raise HTTPException(404, "Honeytoken not found")
    if ht.state in ("active", "triggered"):
        conn = store.get_honeytoken_connection(db, ht.connection_id)
        if conn:
            try:
                plugin = load_plugin(conn.plugin, json.loads(conn.config_json))
                plugin.revoke_token(ht.token_id)
            except Exception:
                log.warning("Failed to revoke honeytoken %s on delete", ht.token_id)
    store.delete_honeytoken(db, htid)
    return {"status": "ok"}


@honeytoken_router.get("/tokens/{htid}/usage")
def list_usage_logs(htid: str, db: Session = Depends(get_db)):
    ht = store.get_honeytoken(db, htid)
    if ht is None:
        raise HTTPException(404, "Honeytoken not found")
    return [
        HoneytokenUsageLogOut(
            id=entry.id, event_id=entry.event_id, actor=entry.actor,
            source_ip=entry.source_ip, action=entry.action,
            timestamp=entry.timestamp,
        ).model_dump()
        for entry in store.list_honeytoken_usage_logs(db, htid)
    ]
