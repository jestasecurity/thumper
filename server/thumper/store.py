"""Repository layer over SQLAlchemy ORM. All queries live here so the rest of
the app deals in ORM model instances (attribute access: row.id, row.name, …).
"""
import hmac
import json
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import distinct, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import (
    Alert, Deployment, DeliveryAttempt, Endpoint, Honeytoken,
    HoneytokenConnection, HoneytokenUsageLog, Integration, Tripwire,
)
from .models import iso_now
from .services.secrets_crypto import pack_config


def _id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


# ── tripwires (definitions) ──────────────────────────────────────────────────
def create_tripwire(db: Session, *, name: str, token_type: str, path: str,
                    source: str = "template", custom_content: Optional[str] = None,
                    token: Optional[str] = None) -> Tripwire:
    row = Tripwire(id=_id("tw"), name=name, token_type=token_type, path=path,
                   source=source, custom_content=custom_content, token=token,
                   created_at=iso_now(), active=True)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_tripwires(db: Session) -> list[Tripwire]:
    return db.query(Tripwire).order_by(Tripwire.created_at.desc()).all()


def get_tripwire(db: Session, tid: str) -> Optional[Tripwire]:
    return db.query(Tripwire).filter(Tripwire.id == tid).first()


def rename_tripwire(db: Session, tid: str, name: str) -> Optional[Tripwire]:
    row = get_tripwire(db, tid)
    if row is None:
        return None
    row.name = name
    db.commit()
    db.refresh(row)
    return row


def delete_tripwire(db: Session, tid: str) -> bool:
    """Hard-delete a tripwire and all its deployments (so live agents unplant on
    re-pull). Deployments go first to leave no orphan instances. Returns whether
    a tripwire row existed."""
    row = get_tripwire(db, tid)
    if row is None:
        return False
    db.query(Deployment).filter(Deployment.tripwire_id == tid).delete()
    db.delete(row)
    db.commit()
    return True


# ── endpoints ────────────────────────────────────────────────────────────────
class MachineIdConflictError(Exception):
    """Raised when a client re-enrolls an existing machine_id without proving
    ownership via its current agent_token. The API turns this into a 409."""


def enroll_endpoint(db: Session, *, hostname: str, platform: Optional[str],
                    machine_id: str, agent_token: str = "",
                    ephemeral: bool = False) -> Endpoint:
    """Upsert by machine_id. Returns the endpoint row (incl. agent_token).

    Re-enrolling an EXISTING machine_id requires the caller to already hold
    that endpoint's current agent_token, otherwise anyone holding the
    shared ENROLL_TOKEN who learns or guesses a machine_id could hijack that
    endpoint's identity and read back its agent_token. A genuinely new agent
    always generates a fresh random machine_id (see gen_machine_id in
    agent/thumper_agent.sh, uuidgen/kernel-random - never hardware-derived),
    so this never blocks first-time enrollment or recovery after a lost
    local state file: a lost state file means a fresh machine_id too.

    ephemeral=True marks a short-lived CI endpoint (issue #3): enrolled by the
    GitHub Action on job start and removed/pruned when the job ends.
    """
    existing = db.query(Endpoint).filter(Endpoint.machine_id == machine_id).first()
    now = iso_now()
    if existing:
        if not hmac.compare_digest(agent_token, existing.agent_token):
            raise MachineIdConflictError()
        existing.hostname = hostname
        existing.platform = platform
        existing.last_seen = now
        existing.ephemeral = 1 if ephemeral else 0
        db.commit()
        db.refresh(existing)
        return existing
    row = Endpoint(id=_id("ep"), hostname=hostname, platform=platform,
                   machine_id=machine_id, agent_token=secrets.token_hex(16),
                   enrolled_at=now, last_seen=now, ephemeral=1 if ephemeral else 0)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_endpoints(db: Session) -> list[Endpoint]:
    return db.query(Endpoint).order_by(Endpoint.enrolled_at.desc()).all()


def get_endpoint(db: Session, eid: str) -> Optional[Endpoint]:
    return db.query(Endpoint).filter(Endpoint.id == eid).first()


def get_endpoint_by_token(db: Session, agent_token: str) -> Optional[Endpoint]:
    return db.query(Endpoint).filter(Endpoint.agent_token == agent_token).first()


def touch_endpoint(db: Session, eid: str) -> None:
    db.query(Endpoint).filter(Endpoint.id == eid).update(
        {Endpoint.last_seen: iso_now()})
    db.commit()


def request_decommission(db: Session, eid: str) -> Optional[Endpoint]:
    """Flag an endpoint for self-destruct and return it (so the caller has the row
    without a second query). Idempotent; None if the id is unknown. The agent
    picks up the kill signal on its next heartbeat."""
    ep = db.query(Endpoint).filter(Endpoint.id == eid).first()
    if ep is None:
        return None
    if ep.decommission_requested_at is None:
        ep.decommission_requested_at = iso_now()
        db.commit()
    return ep


def prune_stale_ephemeral(db: Session, older_than_seconds: int = 3600) -> int:
    """Delete ephemeral endpoints not seen within older_than_seconds. Sweeps
    CI per-job endpoints left behind by cancelled jobs that skipped cleanup.
    Non-ephemeral endpoints are never touched. Returns the count removed."""
    cutoff = datetime.now(timezone.utc).timestamp() - older_than_seconds
    candidates = db.query(Endpoint).filter(Endpoint.ephemeral == 1).all()
    _FMT = "%Y-%m-%dT%H:%M:%SZ"
    removed = 0
    for ep in candidates:
        raw = ep.last_seen or ep.enrolled_at
        if not raw:
            # No timestamp at all — treat as infinitely old; prune it.
            delete_endpoint(db, ep.id)
            removed += 1
            continue
        try:
            ts = datetime.strptime(raw, _FMT).replace(tzinfo=timezone.utc)
        except ValueError:
            # Unparseable timestamp: skip rather than silently prune everything.
            continue
        if ts.timestamp() < cutoff:
            delete_endpoint(db, ep.id)
            removed += 1
    return removed


def delete_endpoint(db: Session, eid: str) -> bool:
    """Remove an endpoint and its deployments. Alert history is kept (it carries
    a denormalized hostname, so it stands alone). Returns whether a row existed.
    Deployments are deleted explicitly (not relying on the FK cascade, which
    SQLite only honors with foreign_keys=ON), mirroring delete_tripwire."""
    ep = db.query(Endpoint).filter(Endpoint.id == eid).first()
    if ep is None:
        return False
    db.query(Deployment).filter(Deployment.endpoint_id == eid).delete()
    db.delete(ep)
    db.commit()
    return True


# ── deployments (instances) ──────────────────────────────────────────────────
def _find_deployment(db: Session, tripwire_id: str, endpoint_id: str) -> Optional[Deployment]:
    return db.query(Deployment).filter(
        Deployment.tripwire_id == tripwire_id,
        Deployment.endpoint_id == endpoint_id,
    ).first()


def materialize_deployment(db: Session, *, tripwire_id: str, endpoint_id: str,
                           path: str, content: str) -> Deployment:
    """Create the per-(tripwire,endpoint) instance if absent; else return existing.

    Concurrency-safe: two requests for the same (tripwire, endpoint) can both pass
    the existence check and both try to insert. The unique constraint lets exactly
    one win; the loser catches the IntegrityError and returns the winner's row
    instead of surfacing a 500 (e.g. an agent retrying on a flaky network)."""
    existing = _find_deployment(db, tripwire_id, endpoint_id)
    if existing:
        return existing
    row = Deployment(id=_id("dp"), tripwire_id=tripwire_id, endpoint_id=endpoint_id,
                     path=path, content=content, hmac_secret=secrets.token_hex(32),
                     state="pending", created_at=iso_now())
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Another request won the race between our check and insert.
        return _find_deployment(db, tripwire_id, endpoint_id)
    db.refresh(row)
    return row


def get_deployment(db: Session, did: str) -> Optional[Deployment]:
    return db.query(Deployment).filter(Deployment.id == did).first()


def list_deployments_for_endpoint(db: Session, endpoint_id: str) -> list[Deployment]:
    return db.query(Deployment).filter(Deployment.endpoint_id == endpoint_id).all()


def delete_deployment(db: Session, did: str) -> int:
    count = db.query(Deployment).filter(Deployment.id == did).delete()
    db.commit()
    return count


def list_deployments_for_tripwire(db: Session, tripwire_id: str) -> list[Deployment]:
    return db.query(Deployment).filter(Deployment.tripwire_id == tripwire_id).all()


def set_deployment_state(db: Session, did: str, state: str) -> None:
    db.query(Deployment).filter(Deployment.id == did).update(
        {Deployment.state: state})
    db.commit()


def mark_deployment_triggered(db: Session, did: str) -> None:
    db.query(Deployment).filter(Deployment.id == did).update(
        {Deployment.last_triggered: iso_now()})
    db.commit()


def count_deployments(db: Session) -> int:
    return db.query(Deployment).count()


# ── alerts ───────────────────────────────────────────────────────────────────
def create_alert(db: Session, *, deployment_id: str, tripwire_id: str,
                 endpoint_id: str, tripwire_name: str, endpoint_hostname: str,
                 token_type: str, timestamp: str, triggered_by: Optional[str],
                 accessed_path: Optional[str] = None, process: Optional[str] = None,
                 pid: Optional[int] = None, os_user: Optional[str] = None,
                 event_type: Optional[str] = None) -> Alert:
    row = Alert(id=_id("al"), deployment_id=deployment_id, tripwire_id=tripwire_id,
                endpoint_id=endpoint_id, tripwire_name=tripwire_name,
                endpoint_hostname=endpoint_hostname, token_type=token_type,
                accessed_path=accessed_path, process=process, pid=pid,
                os_user=os_user, event_type=event_type, timestamp=timestamp,
                triggered_by=triggered_by)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_alerts(db: Session, status: Optional[str] = None) -> list[Alert]:
    """All alerts, newest first. `status` optionally filters to "open"
    (unresolved) or "resolved". An unrecognized value is a caller bug, not a
    silent "return everything" - so it raises."""
    q = db.query(Alert)
    if status == "open":
        q = q.filter(Alert.resolved_at.is_(None))
    elif status == "resolved":
        q = q.filter(Alert.resolved_at.isnot(None))
    elif status is not None:
        raise ValueError(f"invalid alert status filter: {status!r}")
    return q.order_by(Alert.timestamp.desc()).all()


def get_alert(db: Session, aid: str) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.id == aid).first()


def resolve_alert(db: Session, aid: str) -> Optional[Alert]:
    """Mark one alert resolved and return it. Idempotent; returns None if the id
    is unknown (so the caller has the row without a second query)."""
    alert = db.query(Alert).filter(Alert.id == aid).first()
    if alert is None:
        return None
    if alert.resolved_at is None:
        alert.resolved_at = iso_now()
        db.commit()
    return alert


def resolve_deployment_alerts(db: Session, did: str) -> int:
    """Resolve every open alert for a deployment. Returns how many were newly
    resolved (already-resolved alerts are left untouched and not counted)."""
    n = db.query(Alert).filter(
        Alert.deployment_id == did, Alert.resolved_at.is_(None),
    ).update({Alert.resolved_at: iso_now()})
    db.commit()
    return n


def resolve_all_alerts(db: Session) -> int:
    """Resolve every open alert in one statement. Returns the count resolved."""
    n = db.query(Alert).filter(Alert.resolved_at.is_(None)) \
        .update({Alert.resolved_at: iso_now()})
    db.commit()
    return n


# The alert rollups below all count only OPEN (unresolved) alerts, so every
# "triggered" badge and the 24h count across the UI clear in lockstep with the
# dashboard's active count once an operator resolves them.
def count_alerts_for_tripwire(db: Session, tripwire_id: str) -> int:
    return db.query(Alert).filter(
        Alert.tripwire_id == tripwire_id, Alert.resolved_at.is_(None)).count()


def count_alerts_for_endpoint(db: Session, endpoint_id: str) -> int:
    return db.query(Alert).filter(
        Alert.endpoint_id == endpoint_id, Alert.resolved_at.is_(None)).count()


def count_alerts_for_deployment(db: Session, deployment_id: str) -> int:
    return db.query(Alert).filter(
        Alert.deployment_id == deployment_id, Alert.resolved_at.is_(None)).count()


def count_alerts_since(db: Session, cutoff_iso: str) -> int:
    """Open alerts fired since the cutoff. Resolving one drops it from the count."""
    return db.query(Alert).filter(
        Alert.timestamp >= cutoff_iso, Alert.resolved_at.is_(None)).count()


def count_distinct_alert_deployments(db: Session) -> int:
    """Deployments with at least one OPEN alert - i.e. still-active triggers.
    Resolving a deployment's alerts removes it from this count."""
    return db.query(func.count(distinct(Alert.deployment_id))).filter(
        Alert.resolved_at.is_(None)).scalar() or 0


# ── batched counts (avoid N+1 in list endpoints) ─────────────────────────────
def deployment_counts_by_tripwire(db: Session) -> dict[str, int]:
    rows = db.query(Deployment.tripwire_id, func.count(Deployment.id)) \
        .group_by(Deployment.tripwire_id).all()
    return {tid: n for tid, n in rows}


def deployment_counts_by_endpoint(db: Session) -> dict[str, int]:
    rows = db.query(Deployment.endpoint_id, func.count(Deployment.id)) \
        .group_by(Deployment.endpoint_id).all()
    return {eid: n for eid, n in rows}


def alert_counts_by_tripwire(db: Session) -> dict[str, int]:
    rows = db.query(Alert.tripwire_id, func.count(Alert.id)) \
        .filter(Alert.resolved_at.is_(None)).group_by(Alert.tripwire_id).all()
    return {tid: n for tid, n in rows}


def alert_counts_by_endpoint(db: Session) -> dict[str, int]:
    rows = db.query(Alert.endpoint_id, func.count(Alert.id)) \
        .filter(Alert.resolved_at.is_(None)).group_by(Alert.endpoint_id).all()
    return {eid: n for eid, n in rows}


# ── delivery attempts (per-plugin alert fan-out outcome) ─────────────────────
def record_delivery(db: Session, *, alert_id: str, plugin: str, status: str,
                    error: Optional[str]) -> DeliveryAttempt:
    row = DeliveryAttempt(id=_id("dl"), alert_id=alert_id, plugin=plugin,
                          status=status, error=error, created_at=iso_now())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_deliveries(db: Session, alert_id: str) -> list[DeliveryAttempt]:
    return db.query(DeliveryAttempt).filter(
        DeliveryAttempt.alert_id == alert_id,
    ).order_by(DeliveryAttempt.created_at).all()


# ── integrations ─────────────────────────────────────────────────────────────
def get_integration(db: Session, plugin: str) -> Optional[Integration]:
    return db.query(Integration).filter(Integration.plugin == plugin).first()


def list_integrations(db: Session) -> list[Integration]:
    return db.query(Integration).all()


def upsert_integration(db: Session, *, plugin: str, kind: str,
                       config: dict) -> Integration:
    row = db.query(Integration).filter(Integration.plugin == plugin).first()
    if row is None:
        try:
            row = Integration(plugin=plugin, kind=kind, configured=True,
                              config_json=pack_config(config))
            db.add(row)
            db.commit()
            db.refresh(row)
            return row
        except IntegrityError:
            # A concurrent request inserted the same plugin first; fall through
            # to update the now-existing row instead of failing.
            db.rollback()
            row = db.query(Integration).filter(Integration.plugin == plugin).first()
    row.configured = True
    row.config_json = pack_config(config)
    db.commit()
    db.refresh(row)
    return row


def delete_integration(db: Session, plugin: str) -> None:
    db.query(Integration).filter(Integration.plugin == plugin).delete()
    db.commit()


def set_integration_test_result(db: Session, *, plugin: str, status: str,
                                error: Optional[str]) -> None:
    row = db.query(Integration).filter(Integration.plugin == plugin).first()
    if row:
        row.last_test_status = status
        row.last_test_at = iso_now()
        row.last_test_error = error
        db.commit()


# ── honeytoken connections ───────────────────────────────────────────────────
def create_honeytoken_connection(db: Session, *, name: str, plugin: str,
                                 config: dict) -> HoneytokenConnection:
    row = HoneytokenConnection(id=_id("htc"), name=name, plugin=plugin,
                               config_json=json.dumps(config), configured=False,
                               created_at=iso_now())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_honeytoken_connections(db: Session) -> list[HoneytokenConnection]:
    return db.query(HoneytokenConnection).order_by(
        HoneytokenConnection.created_at.desc()).all()


def get_honeytoken_connection(db: Session, hid: str) -> Optional[HoneytokenConnection]:
    return db.query(HoneytokenConnection).filter(
        HoneytokenConnection.id == hid).first()


def update_honeytoken_connection(db: Session, hid: str, *, name: str,
                                 config: dict) -> Optional[HoneytokenConnection]:
    row = get_honeytoken_connection(db, hid)
    if row is None:
        return None
    row.name = name
    row.config_json = json.dumps(config)
    db.commit()
    db.refresh(row)
    return row


def delete_honeytoken_connection(db: Session, hid: str) -> bool:
    row = get_honeytoken_connection(db, hid)
    if row is None:
        return False
    # SQLite doesn't enforce ON DELETE CASCADE unless the FK pragma is on, so
    # remove the children explicitly (their usage logs cascade off the tokens).
    for ht in db.query(Honeytoken).filter(Honeytoken.connection_id == hid).all():
        db.query(HoneytokenUsageLog).filter(
            HoneytokenUsageLog.honeytoken_id == ht.id).delete()
        db.delete(ht)
    db.delete(row)
    db.commit()
    return True


def set_honeytoken_connection_test(db: Session, *, hid: str,
                                   configured: bool) -> None:
    row = get_honeytoken_connection(db, hid)
    if row:
        row.configured = configured
        db.commit()


def update_honeytoken_last_poll(db: Session, hid: str) -> None:
    db.query(HoneytokenConnection).filter(
        HoneytokenConnection.id == hid).update(
        {HoneytokenConnection.last_poll_at: iso_now()})
    db.commit()


# ── honeytokens ──────────────────────────────────────────────────────────────
def create_honeytoken(db: Session, *, connection_id: str, name: str,
                      token_id: str, token_type: str,
                      metadata: dict) -> Honeytoken:
    row = Honeytoken(id=_id("ht"), connection_id=connection_id, name=name,
                     token_id=token_id, token_type=token_type,
                     metadata_json=json.dumps(metadata), state="pending",
                     created_at=iso_now())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_honeytokens(db: Session) -> list[Honeytoken]:
    return db.query(Honeytoken).order_by(Honeytoken.created_at.desc()).all()


def get_honeytoken(db: Session, htid: str) -> Optional[Honeytoken]:
    return db.query(Honeytoken).filter(Honeytoken.id == htid).first()


def list_honeytokens_for_connection(db: Session, hid: str) -> list[Honeytoken]:
    return db.query(Honeytoken).filter(Honeytoken.connection_id == hid).all()


def list_active_honeytokens_for_connection(db: Session,
                                           hid: str) -> list[Honeytoken]:
    return db.query(Honeytoken).filter(
        Honeytoken.connection_id == hid,
        Honeytoken.state.in_(["active", "triggered"])).all()


def set_honeytoken_state(db: Session, htid: str, state: str) -> None:
    db.query(Honeytoken).filter(Honeytoken.id == htid).update(
        {Honeytoken.state: state})
    db.commit()


def mark_honeytoken_used(db: Session, htid: str) -> None:
    db.query(Honeytoken).filter(Honeytoken.id == htid).update(
        {Honeytoken.last_used_at: iso_now(), Honeytoken.state: "triggered"})
    db.commit()


def delete_honeytoken(db: Session, htid: str) -> bool:
    row = get_honeytoken(db, htid)
    if row is None:
        return False
    db.query(HoneytokenUsageLog).filter(
        HoneytokenUsageLog.honeytoken_id == htid).delete()
    db.delete(row)
    db.commit()
    return True


def record_honeytoken_usage(db: Session, htid: str, event_id: Optional[str],
                            actor: Optional[str], source_ip: Optional[str],
                            action: Optional[str],
                            timestamp: str) -> Optional[HoneytokenUsageLog]:
    """Record one use of a honeytoken. Returns None (recording nothing) when
    `event_id` is set and already logged for this token, so a re-poll of the
    same audit window neither double-records nor re-alerts a single use."""
    if event_id:
        existing = db.query(HoneytokenUsageLog).filter(
            HoneytokenUsageLog.honeytoken_id == htid,
            HoneytokenUsageLog.event_id == event_id,
        ).first()
        if existing:
            return None
    row = HoneytokenUsageLog(
        id=_id("hul"), honeytoken_id=htid, event_id=event_id, actor=actor,
        source_ip=source_ip, action=action, timestamp=timestamp,
        created_at=iso_now(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_honeytoken_usage_logs(db: Session, htid: str) -> list[HoneytokenUsageLog]:
    return db.query(HoneytokenUsageLog).filter(
        HoneytokenUsageLog.honeytoken_id == htid,
    ).order_by(HoneytokenUsageLog.timestamp.desc()).all()
