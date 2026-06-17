"""Repository layer over SQLAlchemy ORM. All queries live here so the rest of
the app deals in ORM model instances (attribute access: row.id, row.name, …).
"""
import json
import secrets
from typing import Optional

from sqlalchemy import distinct, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import (
    Alert, Deployment, DeliveryAttempt, Endpoint, Integration, Tripwire,
)
from .models import iso_now


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
def enroll_endpoint(db: Session, *, hostname: str, platform: Optional[str],
                    machine_id: str) -> Endpoint:
    """Upsert by machine_id. Returns the endpoint row (incl. agent_token)."""
    existing = db.query(Endpoint).filter(Endpoint.machine_id == machine_id).first()
    now = iso_now()
    if existing:
        existing.hostname = hostname
        existing.platform = platform
        existing.last_seen = now
        db.commit()
        db.refresh(existing)
        return existing
    row = Endpoint(id=_id("ep"), hostname=hostname, platform=platform,
                   machine_id=machine_id, agent_token=secrets.token_hex(16),
                   enrolled_at=now, last_seen=now)
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
                              config_json=json.dumps(config))
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
    row.config_json = json.dumps(config)
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
