"""Database engine, ORM models, and session management.

Supports SQLite (default), PostgreSQL, and MySQL - selected by the THUMPER_DB
env var (a SQLAlchemy URL). SQLite-specific PRAGMAs are applied via an event
listener; everything else is engine-agnostic.
"""
from sqlalchemy import (
    Boolean, Column, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint, create_engine, event, inspect,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import DB_URL


class Base(DeclarativeBase):
    pass


# ── ORM models ──────────────────────────────────────────────────────────────

class Tripwire(Base):
    __tablename__ = "tripwires"
    id = Column(String(255), primary_key=True)
    name = Column(String(255), nullable=False)
    token_type = Column(String(255), nullable=False)
    path = Column(String(255), nullable=False)
    source = Column(String(255), nullable=False, default="template")
    custom_content = Column(Text)
    token = Column(Text)
    created_at = Column(String(255), nullable=False)
    active = Column(Boolean, nullable=False, default=True)


class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(String(255), primary_key=True)
    hostname = Column(String(255), nullable=False)
    platform = Column(String(255))
    machine_id = Column(String(255), unique=True)
    agent_token = Column(String(255), nullable=False)
    enrolled_at = Column(String(255), nullable=False)
    last_seen = Column(String(255))


class Deployment(Base):
    __tablename__ = "deployments"
    id = Column(String(255), primary_key=True)
    tripwire_id = Column(String(255), ForeignKey("tripwires.id", ondelete="CASCADE"), nullable=False)
    endpoint_id = Column(String(255), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    path = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    hmac_secret = Column(String(255), nullable=False)
    state = Column(String(255), nullable=False, default="pending")
    created_at = Column(String(255), nullable=False)
    last_triggered = Column(String(255))
    __table_args__ = (
        UniqueConstraint("tripwire_id", "endpoint_id"),
        Index("ix_deploy_tripwire", "tripwire_id"),
        Index("ix_deploy_endpoint", "endpoint_id"),
    )


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String(255), primary_key=True)
    deployment_id = Column(String(255), nullable=False)
    tripwire_id = Column(String(255), nullable=False)
    endpoint_id = Column(String(255), nullable=False)
    tripwire_name = Column(String(255), nullable=False)
    endpoint_hostname = Column(String(255), nullable=False)
    token_type = Column(String(255), nullable=False)
    accessed_path = Column(String(255))
    process = Column(String(255))
    pid = Column(Integer)
    os_user = Column(String(255))
    event_type = Column(String(255))
    timestamp = Column(String(255), nullable=False)
    triggered_by = Column(String(255))
    # NULL = open (unresolved). Set to an ISO timestamp when a user resolves it.
    resolved_at = Column(String(255))
    __table_args__ = (
        Index("ix_alert_deployment", "deployment_id"),
        Index("ix_alert_tripwire", "tripwire_id"),
        # Every active-count query filters resolved_at IS NULL; index it so those
        # don't table-scan as alert history grows.
        Index("ix_alert_resolved_at", "resolved_at"),
    )


class Integration(Base):
    __tablename__ = "integrations"
    plugin = Column(String(255), primary_key=True)
    kind = Column(String(255), nullable=False)
    configured = Column(Boolean, nullable=False, default=False)
    config_json = Column(Text, nullable=False, default="{}")
    last_test_status = Column(String(255))
    last_test_at = Column(String(255))
    last_test_error = Column(String(255))


class DeliveryAttempt(Base):
    __tablename__ = "delivery_attempts"
    id = Column(String(255), primary_key=True)
    alert_id = Column(String(255), nullable=False)
    plugin = Column(String(255), nullable=False)
    status = Column(String(255), nullable=False)
    error = Column(String(255))
    created_at = Column(String(255), nullable=False)
    __table_args__ = (
        Index("ix_delivery_alert", "alert_id"),
    )


# ── engine + session ────────────────────────────────────────────────────────
# Created lazily on first use rather than at import time, so a THUMPER_DB / dotenv
# override applied after this module is imported (CLI, tests) still takes effect.

_engine = None
_sessionmaker = None


def _set_sqlite_pragmas(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(DB_URL)
        if _engine.dialect.name == "sqlite":
            event.listen(_engine, "connect", _set_sqlite_pragmas)
    return _engine


def SessionLocal():
    """A new ORM session bound to the (lazily-created) engine."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = sessionmaker(bind=get_engine())
    return _sessionmaker()


def get_db():
    """FastAPI dependency: a per-request session that always closes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Run Alembic migrations to bring the schema to head.

    For existing SQLite databases (pre-Alembic): if tables exist but there is no
    alembic_version table, stamp the baseline migration as applied without
    re-running it.
    """
    from alembic import command
    from alembic.config import Config

    alembic_cfg = Config()
    alembic_cfg.set_main_option("script_location", str(
        __import__("pathlib").Path(__file__).resolve().parent / "migrations"))
    alembic_cfg.set_main_option("sqlalchemy.url", DB_URL)

    insp = inspect(get_engine())
    has_tables = insp.has_table("tripwires")
    has_alembic = insp.has_table("alembic_version")

    if has_tables and not has_alembic:
        command.stamp(alembic_cfg, "head")
    else:
        command.upgrade(alembic_cfg, "head")
