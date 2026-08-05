"""API routes for vault connections, canary secret templates, and canary secrets.

Mounted under the admin-gated /api router (see routes.py), so every path here is
/api/vault/... and inherits the management-API admin-token gate.
"""
import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import store
from ..db import get_db
from ..models import (
    CanarySecretOut, CreateCanarySecretIn, CreateVaultConnectionIn,
    UpdateVaultConnectionIn, VaultConnectionOut,
)
from ..plugins.registry import get_manifest, load_plugin
from ..services.integrations import mask_config, merge_config
from ..services.templates import generate_value, get_template, list_templates

log = logging.getLogger("thumper.vault")

vault_router = APIRouter(prefix="/vault", tags=["vault"])


def _connection_out(row, manifest) -> dict:
    config = json.loads(row.config_json)
    masked = mask_config(manifest, config) if manifest else config
    return VaultConnectionOut(
        id=row.id, name=row.name, plugin=row.plugin,
        configured=row.configured, config=masked,
        last_poll_at=row.last_poll_at, created_at=row.created_at,
    ).model_dump()


def _secret_out(row) -> dict:
    tpl = get_template(row.template)
    tpl_name = tpl["name"] if tpl else row.template
    return CanarySecretOut(
        id=row.id, vault_connection_id=row.vault_connection_id,
        vault_connection_name="", template=row.template,
        template_name=tpl_name, path=row.path, state=row.state,
        created_at=row.created_at, last_accessed_at=row.last_accessed_at,
    ).model_dump()


# ── vault connections ───────────────────────────────────────────────────────

@vault_router.get("/connections")
def list_connections(db: Session = Depends(get_db)):
    return [_connection_out(row, get_manifest(row.plugin))
            for row in store.list_vault_connections(db)]


@vault_router.post("/connections")
def create_connection(body: CreateVaultConnectionIn,
                      db: Session = Depends(get_db)):
    manifest = get_manifest(body.plugin)
    if manifest is None:
        raise HTTPException(400, f"Unknown vault plugin: {body.plugin}")
    row = store.create_vault_connection(
        db, name=body.name, plugin=body.plugin, config=body.config)
    return _connection_out(row, manifest)


@vault_router.put("/connections/{vid}")
def update_connection(vid: str, body: UpdateVaultConnectionIn,
                      db: Session = Depends(get_db)):
    row = store.get_vault_connection(db, vid)
    if row is None:
        raise HTTPException(404, "Vault connection not found")
    # Merge so a masked secret field the UI didn't re-enter keeps its stored value.
    merged = merge_config(json.loads(row.config_json), body.config)
    updated = store.update_vault_connection(db, vid, name=body.name,
                                            config=merged)
    return _connection_out(updated, get_manifest(updated.plugin))


@vault_router.delete("/connections/{vid}")
def delete_connection(vid: str, db: Session = Depends(get_db)):
    secrets = store.list_canary_secrets_for_connection(db, vid)
    if secrets:
        row = store.get_vault_connection(db, vid)
        if row:
            try:
                plugin = load_plugin(row.plugin, json.loads(row.config_json))
                for cs in secrets:
                    if cs.state == "planted":
                        try:
                            plugin.delete(cs.path)
                        except Exception:
                            log.warning(
                                "Failed to delete canary secret %s from vault",
                                cs.path)
            except Exception:
                log.warning("Failed to load plugin to clean up secrets")
    if not store.delete_vault_connection(db, vid):
        raise HTTPException(404, "Vault connection not found")
    return {"status": "ok"}


@vault_router.post("/connections/{vid}/test")
def test_connection(vid: str, db: Session = Depends(get_db)):
    row = store.get_vault_connection(db, vid)
    if row is None:
        raise HTTPException(404, "Vault connection not found")
    try:
        plugin = load_plugin(row.plugin, json.loads(row.config_json))
        plugin.test()
        store.set_vault_connection_test(db, vid=vid, configured=True)
        return {"ok": True, "error": None}
    except Exception as exc:
        store.set_vault_connection_test(db, vid=vid, configured=False)
        return {"ok": False, "error": str(exc)}


# ── templates ───────────────────────────────────────────────────────────────

@vault_router.get("/templates")
def get_templates():
    return list_templates()


# ── canary secrets ──────────────────────────────────────────────────────────

@vault_router.get("/secrets")
def list_secrets(db: Session = Depends(get_db)):
    vc_map = {vc.id: vc.name for vc in store.list_vault_connections(db)}
    result = []
    for row in store.list_canary_secrets(db):
        out = _secret_out(row)
        out["vault_connection_name"] = vc_map.get(row.vault_connection_id, "")
        result.append(out)
    return result


@vault_router.post("/secrets")
def create_secret(body: CreateCanarySecretIn, db: Session = Depends(get_db)):
    vc = store.get_vault_connection(db, body.vault_connection_id)
    if vc is None:
        raise HTTPException(404, "Vault connection not found")
    if not vc.configured:
        raise HTTPException(400, "Vault connection not tested/configured yet")
    tpl = get_template(body.template)
    if tpl is None:
        raise HTTPException(400, f"Unknown template: {body.template}")
    value = generate_value(tpl)
    metadata = tpl.get("metadata", {})
    cs = store.create_canary_secret(
        db, vault_connection_id=vc.id, template=body.template,
        path=body.path, value=value)
    plant_error = None
    try:
        plugin = load_plugin(vc.plugin, json.loads(vc.config_json))
        plugin.plant(body.path, value, metadata)
        store.set_canary_secret_state(db, cs.id, "planted")
    except Exception as exc:
        store.set_canary_secret_state(db, cs.id, "failed")
        plant_error = str(exc)
        log.warning("Failed to plant canary secret: %s", exc)
    db.expire_all()
    out = _secret_out(store.get_canary_secret(db, cs.id))
    out["vault_connection_name"] = vc.name
    if plant_error:
        out["error"] = plant_error
    return out


@vault_router.delete("/secrets/{csid}")
def delete_secret(csid: str, db: Session = Depends(get_db)):
    cs = store.get_canary_secret(db, csid)
    if cs is None:
        raise HTTPException(404, "Canary secret not found")
    if cs.state in ("planted", "triggered"):
        vc = store.get_vault_connection(db, cs.vault_connection_id)
        if vc:
            try:
                plugin = load_plugin(vc.plugin, json.loads(vc.config_json))
                plugin.delete(cs.path)
            except Exception:
                log.warning("Failed to delete secret %s from vault", cs.path)
    store.delete_canary_secret(db, csid)
    return {"status": "ok"}


@vault_router.get("/secrets/{csid}/access-logs")
def list_access_logs(csid: str, db: Session = Depends(get_db)):
    cs = store.get_canary_secret(db, csid)
    if cs is None:
        raise HTTPException(404, "Canary secret not found")
    return [
        {
            "id": entry.id,
            "event_id": entry.event_id,
            "accessor": entry.accessor,
            "source_ip": entry.source_ip,
            "timestamp": entry.timestamp,
        }
        for entry in store.list_canary_access_logs(db, csid)
    ]
