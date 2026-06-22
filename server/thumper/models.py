"""Pydantic API schemas. These mirror ui/src/api/types.ts - keep them in sync;
this is the contract between the UI and the server.
"""
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel


def iso_now() -> str:
    """UTC timestamp in the Z-suffixed ISO form the UI expects."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── tripwires (definitions) ──────────────────────────────────────────────────
class CreateTripwireIn(BaseModel):
    name: str
    token_type: str
    path: str
    source: str = "template"            # template | custom | managed
    custom_content: Optional[str] = None  # required when source == "custom" (future)
    token: Optional[str] = None           # pre-generated honeytoken from preview; server generates if absent


class UpdateTripwireIn(BaseModel):
    name: str


class TripwireOut(BaseModel):
    id: str
    name: str
    token_type: str
    path: str
    source: str
    token: str | None = None
    created_at: str
    active: bool
    deployed_count: int      # number of endpoints this tripwire is on
    triggered_count: int     # number of alerts across those endpoints


class AssignTripwireIn(BaseModel):
    tripwire_id: str


class DeploymentOut(BaseModel):
    id: str
    tripwire_id: str
    endpoint_id: str
    endpoint_hostname: str
    state: str
    created_at: str
    last_triggered: Optional[str] = None
    triggered_count: int
    endpoint_status: str = "inactive"   # online | stale | inactive | decommissioning


class InstallSpecOut(BaseModel):
    """What the operator distributes (via MDM/SSH/etc) to put this tripwire on
    machines. Each machine that runs it self-enrolls and gets its own instance."""
    tripwire_id: str
    server_url: str
    enroll_token: str
    command: str


class InstallCommandOut(BaseModel):
    """One install command for a chosen SET of tripwires (the multi-select build
    flow). The agent enrolls for all of them and a single watcher serves the set.
    server_url/enroll_token are already embedded in `command`, so they aren't
    surfaced as separate fields."""
    tripwire_ids: list[str]
    command: str


class TripwireDetailOut(TripwireOut):
    deployments: list[DeploymentOut]
    install: InstallSpecOut


# ── endpoints ────────────────────────────────────────────────────────────────
class EndpointOut(BaseModel):
    id: str
    hostname: str
    platform: Optional[str] = None
    enrolled_at: str
    last_seen: Optional[str] = None
    status: str               # online | stale | inactive
    deployment_count: int
    triggered_count: int


# ── alerts ───────────────────────────────────────────────────────────────────
class AlertOut(BaseModel):
    id: str
    deployment_id: str
    tripwire_id: str
    tripwire_name: str
    endpoint_id: str
    endpoint_hostname: str    # the endpoint's hostname, for display
    token_type: str
    accessed_path: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    os_user: Optional[str] = None
    event_type: Optional[str] = None
    timestamp: str
    triggered_by: Optional[str] = None
    status: str                              # "open" | "resolved"
    resolved_at: Optional[str] = None


class ResolveAlertsIn(BaseModel):
    deployment_id: str


class DeliveryOut(BaseModel):
    id: str
    alert_id: str
    plugin: str
    status: str               # ok | failed
    error: Optional[str] = None
    created_at: str


class DashboardStats(BaseModel):
    tripwires: int
    endpoints: int
    alerts_24h: int
    active_triggers: int


# ── integrations / token preview ─────────────────────────────────────────────
class IntegrationOut(BaseModel):
    plugin: str
    kind: str
    configured: bool
    config: dict
    last_test_status: Optional[str] = None   # ok | failed | None (never tested)
    last_test_at: Optional[str] = None
    last_test_error: Optional[str] = None


class IntegrationTestResult(BaseModel):
    ok: bool
    error: Optional[str] = None
    tested_at: str


class DatabaseSettingsOut(BaseModel):
    backend: str
    location: str


class ThresholdSettingsOut(BaseModel):
    stale_minutes: int
    inactive_hours: int


class DashboardSettingsOut(BaseModel):
    refresh_seconds: int


class AppSettingsOut(BaseModel):
    database: DatabaseSettingsOut
    thresholds: ThresholdSettingsOut
    dashboard: DashboardSettingsOut


class TokenPreviewIn(BaseModel):
    token_type: str
    source: str = "template"
    custom_content: Optional[str] = None


class TokenPreviewOut(BaseModel):
    content: str


# Agent-facing endpoints (/enroll, /agent/*, /trigger) speak a plain-text
# protocol (key=value / tab-separated), not JSON, so the Bash agent needs no
# JSON parser - see api/routes.py. They therefore have no Pydantic schemas here.
