"""Add honeytoken tables for third-party SaaS canary credentials.

Revision ID: honeytoken_tables_v1
Revises: endpoint_ephemeral_v1
Create Date: 2026-07-21
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "honeytoken_tables_v1"
down_revision: Union[str, None] = "endpoint_ephemeral_v1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "honeytoken_connections",
        sa.Column("id", sa.String(255), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("plugin", sa.String(255), nullable=False),
        sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("configured", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("last_poll_at", sa.String(255), nullable=True),
        sa.Column("created_at", sa.String(255), nullable=False),
    )
    op.create_table(
        "honeytokens",
        sa.Column("id", sa.String(255), primary_key=True),
        sa.Column("connection_id", sa.String(255),
                  sa.ForeignKey("honeytoken_connections.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("token_id", sa.String(255), nullable=False),
        sa.Column("token_type", sa.String(255), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("state", sa.String(255), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.String(255), nullable=False),
        sa.Column("last_used_at", sa.String(255), nullable=True),
    )
    op.create_index("ix_ht_connection", "honeytokens", ["connection_id"])
    op.create_table(
        "honeytoken_usage_logs",
        sa.Column("id", sa.String(255), primary_key=True),
        sa.Column("honeytoken_id", sa.String(255),
                  sa.ForeignKey("honeytokens.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("event_id", sa.String(255), nullable=True),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("source_ip", sa.String(255), nullable=True),
        sa.Column("action", sa.String(255), nullable=True),
        sa.Column("timestamp", sa.String(255), nullable=False),
        sa.Column("created_at", sa.String(255), nullable=False),
        sa.UniqueConstraint("honeytoken_id", "event_id",
                            name="uq_honeytoken_usage_event"),
    )
    op.create_index("ix_usage_log_honeytoken", "honeytoken_usage_logs",
                    ["honeytoken_id"])


def downgrade() -> None:
    op.drop_index("ix_usage_log_honeytoken", table_name="honeytoken_usage_logs")
    op.drop_table("honeytoken_usage_logs")
    op.drop_index("ix_ht_connection", table_name="honeytokens")
    op.drop_table("honeytokens")
    op.drop_table("honeytoken_connections")
