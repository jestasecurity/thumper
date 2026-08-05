"""Add canary_access_logs table for recorded canary-secret reads.

Revision ID: canary_access_logs_v1
Revises: vault_tables_v1
Create Date: 2026-07-21
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "canary_access_logs_v1"
down_revision: Union[str, None] = "vault_tables_v1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "canary_access_logs",
        sa.Column("id", sa.String(255), primary_key=True),
        sa.Column("canary_secret_id", sa.String(255),
                  sa.ForeignKey("canary_secrets.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("event_id", sa.String(255), nullable=True),
        sa.Column("accessor", sa.String(255), nullable=True),
        sa.Column("source_ip", sa.String(255), nullable=True),
        sa.Column("timestamp", sa.String(255), nullable=False),
        sa.Column("created_at", sa.String(255), nullable=False),
        sa.UniqueConstraint("canary_secret_id", "event_id",
                            name="uq_access_event"),
    )
    op.create_index("ix_access_log_secret", "canary_access_logs",
                    ["canary_secret_id"])


def downgrade() -> None:
    op.drop_index("ix_access_log_secret", table_name="canary_access_logs")
    op.drop_table("canary_access_logs")
