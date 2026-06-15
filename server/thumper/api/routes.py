"""All HTTP endpoints.

Two distinct contracts live here:
  • UI-facing endpoints (/stats, /tripwires, /endpoints, /alerts, …) speak JSON
    and mirror ui/src/api/types.ts - that's the contract the UI is built against.
  • Agent-facing endpoints (/enroll, /agent/*, /trigger) speak a plain-text,
    line-based protocol so the endpoint agent can be pure Bash (curl + openssl,
    no JSON parser). See docs/architecture.md.
"""
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import store
from ..config import AGENT_PATH, BASE_URL, DASHBOARD_REFRESH, DB_URL, ENROLL_TOKEN, INSTALL_TOKEN
from ..db import get_db, get_engine
from ..models import (
    AlertOut,
    AppSettingsOut,
    AssignTripwireIn,
    CreateTripwireIn,
    DashboardStats,
    DeliveryOut,
    DeploymentOut,
    EndpointOut,
    IntegrationOut,
    IntegrationTestResult,
    InstallCommandOut,
    InstallSpecOut,
    TokenPreviewIn,
    TokenPreviewOut,
    TripwireDetailOut,
    TripwireOut,
    UpdateTripwireIn,
    iso_now,
)
from ..plugins.base import PluginError
from ..plugins.registry import get_manifest, load_plugin, public_manifests
from ..services.alerting import deliver_alert
from ..services.content import render_content
from ..services.deploy import build_install, build_install_command, distribute
from ..services.integrations import mask_config, merge_config, saved_config
from ..services.signing import verify
from ..tokens import TOKEN_TYPES

router = APIRouter(prefix="/api")

_STALE_WINDOW = timedelta(minutes=15)
_INACTIVE_WINDOW = timedelta(hours=12)


# ── helpers ──────────────────────────────────────────────────────────────────
def _parse_ts(timestamp: str | None):
    if not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None


def _endpoint_status(last_seen: str | None) -> str:
    parsed = _parse_ts(last_seen)
    if not parsed:
        return "inactive"
    age = datetime.now(timezone.utc) - parsed
    if age < _STALE_WINDOW:
        return "online"
    if age < _INACTIVE_WINDOW:
        return "stale"
    return "inactive"


def _tripwire_out(db, tripwire, *, deployed_count=None, triggered_count=None) -> TripwireOut:
    if deployed_count is None:
        deployed_count = len(store.list_deployments_for_tripwire(db, tripwire.id))
    if triggered_count is None:
        triggered_count = store.count_alerts_for_tripwire(db, tripwire.id)
    return TripwireOut(
        id=tripwire.id, name=tripwire.name, token_type=tripwire.token_type,
        path=tripwire.path, source=tripwire.source, token=tripwire.token,
        created_at=tripwire.created_at, active=bool(tripwire.active),
        deployed_count=deployed_count,
        triggered_count=triggered_count,
    )


def _deployment_out(db, deployment) -> DeploymentOut:
    endpoint = store.get_endpoint(db, deployment.endpoint_id)
    return DeploymentOut(
        id=deployment.id, tripwire_id=deployment.tripwire_id,
        endpoint_id=deployment.endpoint_id,
        endpoint_hostname=endpoint.hostname if endpoint else "(removed)",
        state=deployment.state, created_at=deployment.created_at,
        last_triggered=deployment.last_triggered,
        triggered_count=store.count_alerts_for_deployment(db, deployment.id),
    )


def _endpoint_out(db, endpoint, *, deployment_count=None, triggered_count=None) -> EndpointOut:
    endpoint_id = endpoint.id
    if deployment_count is None:
        deployment_count = len(store.list_deployments_for_endpoint(db, endpoint_id))
    if triggered_count is None:
        triggered_count = store.count_alerts_for_endpoint(db, endpoint_id)
    return EndpointOut(
        id=endpoint_id, hostname=endpoint.hostname, platform=endpoint.platform,
        enrolled_at=endpoint.enrolled_at, last_seen=endpoint.last_seen,
        status=_endpoint_status(endpoint.last_seen),
        deployment_count=deployment_count,
        triggered_count=triggered_count,
    )


def _alert_out(alert) -> AlertOut:
    return AlertOut(
        id=alert.id, deployment_id=alert.deployment_id, tripwire_id=alert.tripwire_id,
        tripwire_name=alert.tripwire_name, endpoint_id=alert.endpoint_id,
        endpoint_hostname=alert.endpoint_hostname, token_type=alert.token_type,
        accessed_path=alert.accessed_path, process=alert.process, pid=alert.pid,
        os_user=alert.os_user, event_type=alert.event_type,
        timestamp=alert.timestamp, triggered_by=alert.triggered_by,
    )


def _delivery_out(d) -> DeliveryOut:
    return DeliveryOut(
        id=d.id, alert_id=d.alert_id, plugin=d.plugin,
        status=d.status, error=d.error, created_at=d.created_at,
    )


# ── dashboard ────────────────────────────────────────────────────────────────
@router.get("/stats", response_model=DashboardStats)
def get_stats(db: Session = Depends(get_db)):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return DashboardStats(
        tripwires=len(store.list_tripwires(db)),
        endpoints=len(store.list_endpoints(db)),
        alerts_24h=store.count_alerts_since(db, cutoff),
        active_triggers=store.count_distinct_alert_deployments(db),
    )


# ── tripwires (definitions) ──────────────────────────────────────────────────
@router.get("/tripwires", response_model=list[TripwireOut])
def list_tripwires(db: Session = Depends(get_db)):
    deployed = store.deployment_counts_by_tripwire(db)
    triggered = store.alert_counts_by_tripwire(db)
    return [_tripwire_out(db, tripwire,
                          deployed_count=deployed.get(tripwire.id, 0),
                          triggered_count=triggered.get(tripwire.id, 0))
            for tripwire in store.list_tripwires(db)]


@router.post("/tripwires", response_model=TripwireOut)
def create_tripwire(body: CreateTripwireIn, db: Session = Depends(get_db)):
    if body.source == "custom" and not body.custom_content:
        raise HTTPException(400, "custom source requires custom_content")
    token = body.token or render_content(
        token_type=body.token_type, source=body.source,
        custom_content=body.custom_content,
    )
    tripwire = store.create_tripwire(
        db, name=body.name, token_type=body.token_type, path=body.path,
        source=body.source, custom_content=body.custom_content, token=token,
    )
    return _tripwire_out(db, tripwire)


@router.get("/tripwires/{tid}", response_model=TripwireDetailOut)
def get_tripwire(tid: str, db: Session = Depends(get_db)):
    tripwire = store.get_tripwire(db, tid)
    if tripwire is None:
        raise HTTPException(404, "tripwire not found")
    base = _tripwire_out(db, tripwire)
    install = build_install(tid)
    deployments = []
    for deployment in store.list_deployments_for_tripwire(db, tid):
        deployments.append(_deployment_out(db, deployment))
    return TripwireDetailOut(
        **base.model_dump(),
        deployments=deployments,
        install=InstallSpecOut(**install.model_dump()),
    )


@router.patch("/tripwires/{tid}", response_model=TripwireOut)
def update_tripwire(tid: str, body: UpdateTripwireIn,
                    db: Session = Depends(get_db)):
    """Rename a tripwire. (Path/type/content are immutable - delete + recreate to
    change those, so live bait never silently diverges from the definition.)"""
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "name is required")
    # Single call + check the return (no separate get_tripwire 404 check): avoids
    # a TOCTOU where a concurrent delete between the two would make _tripwire_out
    # crash on None, and saves a redundant SELECT. Mirrors the delete route.
    tripwire = store.rename_tripwire(db, tid, name)
    if tripwire is None:
        raise HTTPException(404, "tripwire not found")
    return _tripwire_out(db, tripwire)


@router.delete("/tripwires/{tid}")
def delete_tripwire(tid: str, db: Session = Depends(get_db)):
    """Hard-delete a tripwire and its deployments; live agents unplant the bait on
    their next re-pull. Alert history survives (alerts keep their own name)."""
    if not store.delete_tripwire(db, tid):
        raise HTTPException(404, "tripwire not found")
    return {"status": "ok"}


@router.post("/tripwires/{tid}/distribute")
def distribute_tripwire(tid: str, db: Session = Depends(get_db)):
    tripwire = store.get_tripwire(db, tid)
    if tripwire is None:
        raise HTTPException(404, "tripwire not found")
    try:
        return distribute(db, tid)
    except PluginError as exc:
        raise HTTPException(400, str(exc))


# ── install command builder (multi-tripwire) ─────────────────────────────────
@router.get("/install", response_model=InstallCommandOut)
def build_install_for_set(tripwire: list[str] = Query(default=[]),
                          db: Session = Depends(get_db)):
    """Build ONE install command for a chosen set of tripwires (the UI's
    multi-select 'Build install command' flow). One agent enrolls for and watches
    the whole set. Validates the ids so the operator gets clear feedback rather
    than a command that silently plants nothing."""
    if not tripwire:
        raise HTTPException(400, "select at least one tripwire")
    tripwire = list(dict.fromkeys(tripwire))  # dedup, preserve order
    bad = [tid for tid in tripwire
           if (tw := store.get_tripwire(db, tid)) is None or not tw.active]
    if bad:
        raise HTTPException(400, f"unknown or inactive tripwire(s): {', '.join(bad)}")
    return build_install_command(tripwire)


# ── endpoints ────────────────────────────────────────────────────────────────
@router.get("/endpoints", response_model=list[EndpointOut])
def list_endpoints(db: Session = Depends(get_db)):
    deployed = store.deployment_counts_by_endpoint(db)
    triggered = store.alert_counts_by_endpoint(db)
    return [_endpoint_out(db, endpoint,
                          deployment_count=deployed.get(endpoint.id, 0),
                          triggered_count=triggered.get(endpoint.id, 0))
            for endpoint in store.list_endpoints(db)]


@router.get("/endpoints/{eid}")
def get_endpoint(eid: str, db: Session = Depends(get_db)):
    endpoint = store.get_endpoint(db, eid)
    if endpoint is None:
        raise HTTPException(404, "endpoint not found")
    out = _endpoint_out(db, endpoint).model_dump()
    out["deployments"] = [_deployment_out(db, deployment).model_dump()
                          for deployment in store.list_deployments_for_endpoint(db, eid)]
    return out


@router.post("/endpoints/{eid}/tripwires", response_model=DeploymentOut)
def assign_tripwire(eid: str, body: AssignTripwireIn,
                    db: Session = Depends(get_db)):
    endpoint = store.get_endpoint(db, eid)
    if endpoint is None:
        raise HTTPException(404, "endpoint not found")
    tripwire = store.get_tripwire(db, body.tripwire_id)
    if tripwire is None or not tripwire.active:
        raise HTTPException(400, "unknown or inactive tripwire")
    deployment = store.materialize_deployment(
        db, tripwire_id=tripwire.id, endpoint_id=eid,
        path=tripwire.path, content=tripwire.token)
    return _deployment_out(db, deployment)


@router.delete("/endpoints/{eid}/tripwires/{tid}")
def unassign_tripwire(eid: str, tid: str, db: Session = Depends(get_db)):
    if store.get_endpoint(db, eid) is None:
        raise HTTPException(404, "endpoint not found")
    deployment = next((d for d in store.list_deployments_for_endpoint(db, eid)
                       if d.tripwire_id == tid), None)
    if deployment is None:
        raise HTTPException(404, "tripwire not assigned to this endpoint")
    store.delete_deployment(db, deployment.id)
    return {"status": "ok"}


# ── alerts ───────────────────────────────────────────────────────────────────
@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(db: Session = Depends(get_db)):
    return [_alert_out(alert) for alert in store.list_alerts(db)]


@router.get("/alerts/{aid}/deliveries", response_model=list[DeliveryOut])
def list_alert_deliveries(aid: str, db: Session = Depends(get_db)):
    # A sub-collection: an unknown alert id yields an empty list (200), not 404.
    return [_delivery_out(d) for d in store.list_deliveries(db, aid)]


# ── token catalog + preview ──────────────────────────────────────────────────
@router.get("/token-types")
def token_types():
    return TOKEN_TYPES


@router.post("/tokens/preview", response_model=TokenPreviewOut)
def preview_token(body: TokenPreviewIn):
    try:
        return TokenPreviewOut(content=render_content(
            token_type=body.token_type, source=body.source, custom_content=body.custom_content))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


# ── plugins / integrations ───────────────────────────────────────────────────
@router.get("/manifests")
def list_manifests():
    return public_manifests()


@router.get("/integrations", response_model=list[IntegrationOut])
def list_integrations(db: Session = Depends(get_db)):
    saved = {row.plugin: row for row in store.list_integrations(db)}
    out = []
    for manifest in public_manifests():
        rec = saved.get(manifest["name"])
        config = mask_config(manifest, json.loads(rec.config_json)) if rec else {}
        out.append(IntegrationOut(
            plugin=manifest["name"], kind=manifest["kind"],
            configured=bool(rec and rec.configured), config=config,
            last_test_status=rec.last_test_status if rec else None,
            last_test_at=rec.last_test_at if rec else None,
            last_test_error=rec.last_test_error if rec else None,
        ))
    return out


@router.post("/integrations/{plugin}", response_model=IntegrationOut)
def save_integration(plugin: str, config: dict, db: Session = Depends(get_db)):
    manifest = get_manifest(plugin)
    if manifest is None:
        raise HTTPException(404, "unknown plugin")
    merged = merge_config(saved_config(db, plugin), config)
    store.upsert_integration(db, plugin=plugin, kind=manifest["kind"], config=merged)
    return IntegrationOut(plugin=plugin, kind=manifest["kind"], configured=True,
                          config=mask_config(manifest, merged))


@router.post("/integrations/{plugin}/test", response_model=IntegrationTestResult)
def test_integration(plugin: str, db: Session = Depends(get_db)):
    """Actively exercise the saved integration's connection. A failed test is a
    200 with ok=false (the test ran; failure is a result, not a bad request)."""
    manifest = get_manifest(plugin)
    if manifest is None:
        raise HTTPException(404, "unknown plugin")
    # Only alert plugins implement test(); guard here rather than trust the UI,
    # so a direct call for a deploy integration returns a clean 400 instead of an
    # AttributeError surfaced as a (persisted) "failed" result.
    if manifest["kind"] != "alert":
        raise HTTPException(400, "connection test is only supported for alert integrations")
    cfg = saved_config(db, plugin)
    if not cfg:
        raise HTTPException(400, "integration is not configured")
    try:
        load_plugin(plugin, cfg).test()
    except Exception as exc:  # noqa: BLE001 - surface any failure as a test result
        error = str(exc)[:500] or exc.__class__.__name__
        store.set_integration_test_result(db, plugin=plugin, status="failed", error=error)
        return IntegrationTestResult(ok=False, error=error, tested_at=iso_now())
    store.set_integration_test_result(db, plugin=plugin, status="ok", error=None)
    return IntegrationTestResult(ok=True, error=None, tested_at=iso_now())


@router.delete("/integrations/{plugin}")
def delete_integration(plugin: str, db: Session = Depends(get_db)):
    if get_manifest(plugin) is None:
        raise HTTPException(404, "unknown plugin")
    store.delete_integration(db, plugin)
    return {"status": "ok"}


# ── settings (read-only) ────────────────────────────────────────────────────
@router.get("/settings", response_model=AppSettingsOut)
def get_settings():
    dialect = get_engine().dialect.name
    if dialect == "sqlite":
        location = DB_URL.removeprefix("sqlite:///")
    else:
        parsed = urlparse(DB_URL)
        host = parsed.hostname or "localhost"
        port = f":{parsed.port}" if parsed.port else ""
        location = f"{host}{port}/{parsed.path.lstrip('/')}"
    return AppSettingsOut(
        database={"backend": dialect, "location": location},
        thresholds={
            "stale_minutes": int(_STALE_WINDOW.total_seconds() / 60),
            "inactive_hours": int(_INACTIVE_WINDOW.total_seconds() / 3600),
        },
        dashboard={"refresh_seconds": DASHBOARD_REFRESH},
    )


# ── agent bootstrap: serve the agent + a self-installing script ──────────────
@router.get("/agent/thumper_agent.sh", response_class=PlainTextResponse)
def serve_agent():
    try:
        return PlainTextResponse(AGENT_PATH.read_text(), media_type="text/x-shellscript")
    except OSError:
        raise HTTPException(500, "agent script unavailable on the server")


@router.get("/install.sh", response_class=PlainTextResponse)
def install_script(tripwire: list[str] = Query(default=[]), token: str = Query(default="")):
    """A self-bootstrapping installer. The tripwire's deploy command pipes this
    into `sudo sh`: it downloads the Bash agent and starts it watching as root
    (so fs_usage works). Distribute it via MDM/SSH or paste it on the endpoint.

    The script embeds ENROLL_TOKEN, so it is gated behind INSTALL_TOKEN - only
    the server-generated deploy command (which carries the token) can fetch it.
    """
    if token != INSTALL_TOKEN:
        raise HTTPException(401, "invalid install token")
    tw_args = " ".join(f"--tripwire {t}" for t in tripwire)
    script = f"""#!/bin/sh
set -e
SERVER="{BASE_URL}"
ENROLL_TOKEN="{ENROLL_TOKEN}"
DIR="${{THUMPER_DIR:-/usr/local/thumper}}"
for tool in curl openssl; do
  command -v "$tool" >/dev/null 2>&1 || {{ echo "thumper: $tool is required"; exit 1; }}
done
mkdir -p "$DIR"
curl -fsSL "$SERVER/api/agent/thumper_agent.sh" -o "$DIR/thumper_agent.sh"
chmod +x "$DIR/thumper_agent.sh"
# Start watching in the background. Runs as root (for fs_usage); the agent plants
# bait in the real user's home and chowns it to that user.
nohup sh "$DIR/thumper_agent.sh" run \\
  --server "$SERVER" --enroll-token "$ENROLL_TOKEN" {tw_args} \\
  --heartbeat 60 --state-file "$DIR/agent.json" >"$DIR/agent.log" 2>&1 &
echo "thumper: agent installed in $DIR and watching (logs: $DIR/agent.log)"
"""
    return PlainTextResponse(script, media_type="text/x-shellscript")


# ── agent: pre-enroll bait-path preview ──────────────────────────────────────
# The bait path is a property of the tripwire, so the agent can learn its paths
# WITHOUT enrolling. It uses this to abort an install on a path conflict BEFORE
# registering - so a refused install leaves no endpoint in the dashboard. Returns
# the paths one-per-line and creates nothing; gated by the enroll token like
# /enroll. (The agent still gets its UNIQUE content/secret only after enroll.)
@router.post("/agent/tripwire-paths", response_class=PlainTextResponse)
async def agent_tripwire_paths(request: Request, db: Session = Depends(get_db)):
    form = parse_qs((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)

    def field(key: str) -> str:
        return (form.get(key) or [""])[0]

    if field("enroll_token") != ENROLL_TOKEN:
        raise HTTPException(401, "invalid enroll token")
    lines = []
    for tid in [t.strip() for t in field("tripwire_ids").split(",") if t.strip()]:
        tripwire = store.get_tripwire(db, tid)
        if tripwire is None or not tripwire.active:
            continue
        lines.append(tripwire.path)
    return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""))


# ── agent: enroll ────────────────────────────────────────────────────────────
# Agent endpoints speak plain text (key=value / TSV) so the Bash agent needs no
# JSON parser. enroll accepts a form-encoded body (curl --data-urlencode).
@router.post("/enroll", response_class=PlainTextResponse)
async def enroll(request: Request, db: Session = Depends(get_db)):
    form = parse_qs((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)

    def field(key: str) -> str:
        return (form.get(key) or [""])[0]

    if field("enroll_token") != ENROLL_TOKEN:
        raise HTTPException(401, "invalid enroll token")
    endpoint = store.enroll_endpoint(db, hostname=field("hostname"),
                                     platform=field("platform") or None,
                                     machine_id=field("machine_id"))
    # Materialize a unique instance for each tripwire this install is scoped to.
    for tid in [t.strip() for t in field("tripwire_ids").split(",") if t.strip()]:
        tripwire = store.get_tripwire(db, tid)
        if tripwire is None or not tripwire.active:
            continue
        store.materialize_deployment(db, tripwire_id=tid, endpoint_id=endpoint.id,
                                     path=tripwire.path, content=tripwire.token)
    return PlainTextResponse(
        f"endpoint_id={endpoint.id}\nagent_token={endpoint.agent_token}\n")


def _authed_endpoint(db, authorization: str):
    token = authorization.removeprefix("Bearer ").strip()
    endpoint = store.get_endpoint_by_token(db, token) if token else None
    if endpoint is None:
        raise HTTPException(401, "invalid agent token")
    return endpoint


# ── agent: heartbeat (liveness only) ─────────────────────────────────────────
@router.post("/agent/heartbeat", response_class=PlainTextResponse)
def agent_heartbeat(authorization: str = Header(default=""),
                    db: Session = Depends(get_db)):
    endpoint = _authed_endpoint(db, authorization)
    store.touch_endpoint(db, endpoint.id)
    return PlainTextResponse("ok\n")


# ── agent: pull deployments ──────────────────────────────────────────────────
# One tab-separated record per deployment. Bait `content` is NOT inlined (it can
# be multi-line) - the agent fetches it raw from the per-deployment content URL.
@router.get("/agent/deployments", response_class=PlainTextResponse)
def agent_deployments(authorization: str = Header(default=""),
                      db: Session = Depends(get_db)):
    endpoint = _authed_endpoint(db, authorization)
    store.touch_endpoint(db, endpoint.id)
    lines = []
    for deployment in store.list_deployments_for_endpoint(db, endpoint.id):
        content_url = f"{BASE_URL}/api/agent/deployments/{deployment.id}/content"
        callback_url = f"{BASE_URL}/api/trigger"
        # Fields are single-line-safe: id (hex), path (no tabs), hmac_secret (hex),
        # content_url, callback_url. Tab-delimited so the agent reads with `read`.
        lines.append("\t".join([deployment.id, deployment.path,
                                deployment.hmac_secret, content_url, callback_url]))
    return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""))


# ── agent: raw bait content for one deployment ───────────────────────────────
@router.get("/agent/deployments/{deployment_id}/content", response_class=PlainTextResponse)
def agent_deployment_content(deployment_id: str, authorization: str = Header(default=""),
                             db: Session = Depends(get_db)):
    endpoint = _authed_endpoint(db, authorization)
    deployment = store.get_deployment(db, deployment_id)
    if deployment is None or deployment.endpoint_id != endpoint.id:
        raise HTTPException(404, "deployment not found")
    return PlainTextResponse(deployment.content, media_type="text/plain")


# ── agent: report a deployment's plant outcome ───────────────────────────────
@router.post("/agent/deployments/{deployment_id}/state", response_class=PlainTextResponse)
async def agent_deployment_state(deployment_id: str, request: Request,
                                 authorization: str = Header(default=""),
                                 db: Session = Depends(get_db)):
    endpoint = _authed_endpoint(db, authorization)
    form = parse_qs((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)
    state = (form.get("state") or [""])[0]
    if state not in ("planted", "failed"):
        raise HTTPException(400, "state must be 'planted' or 'failed'")
    deployment = store.get_deployment(db, deployment_id)
    if deployment is None or deployment.endpoint_id != endpoint.id:
        raise HTTPException(404, "deployment not found")
    store.set_deployment_state(db, deployment_id, state)
    return PlainTextResponse("ok\n")


# ── agent: public trigger callback (HMAC-verified, keyed on deployment) ───────
def _parse_kv(raw: bytes) -> dict:
    """Parse the agent's key=value line body (one pair per line)."""
    data: dict[str, str] = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            data[key.strip()] = value
    return data


@router.post("/trigger")
async def trigger(request: Request, background: BackgroundTasks,
                  db: Session = Depends(get_db)):
    body = await request.body()
    data = _parse_kv(body)

    deployment = store.get_deployment(db, data.get("deployment_id", ""))
    signature = request.headers.get("X-Thumper-Signature")
    # Same 401 for unknown deployment and bad signature - don't leak which exist.
    # verify() signs the EXACT body bytes, so the text format needs no agreement
    # beyond "the agent and server hash the same bytes".
    if deployment is None or not verify(deployment.hmac_secret, body, signature):
        raise HTTPException(401, "invalid signature")

    tripwire = store.get_tripwire(db, deployment.tripwire_id)
    endpoint = store.get_endpoint(db, deployment.endpoint_id)
    pid = data.get("pid")
    alert = store.create_alert(
        db, deployment_id=deployment.id, tripwire_id=deployment.tripwire_id,
        endpoint_id=deployment.endpoint_id,
        tripwire_name=tripwire.name if tripwire else "(removed)",
        endpoint_hostname=endpoint.hostname if endpoint else (data.get("endpoint") or "unknown"),
        token_type=tripwire.token_type if tripwire else "unknown",
        accessed_path=data.get("accessed_path") or deployment.path,
        process=data.get("process"),
        pid=int(pid) if pid and str(pid).isdigit() else None,
        os_user=data.get("os_user"),
        event_type=data.get("event_type"),
        timestamp=data.get("timestamp") or iso_now(),
        triggered_by=data.get("triggered_by"),
    )
    # Only a pending deployment becomes planted. A failed one stays failed.
    if deployment.state == "pending":
        store.set_deployment_state(db, deployment.id, "planted")
    store.mark_deployment_triggered(db, deployment.id)

    background.add_task(deliver_alert, {
        "alert_id": alert.id, "deployment_id": deployment.id,
        "tripwire_id": deployment.tripwire_id,
        "tripwire_name": alert.tripwire_name, "endpoint_id": deployment.endpoint_id,
        "endpoint_hostname": alert.endpoint_hostname, "token_type": alert.token_type,
        "accessed_path": alert.accessed_path, "process": alert.process,
        "pid": alert.pid, "os_user": alert.os_user, "event_type": alert.event_type,
        "timestamp": alert.timestamp, "triggered_by": alert.triggered_by,
    })
    return {"status": "ok", "alert_id": alert.id}
