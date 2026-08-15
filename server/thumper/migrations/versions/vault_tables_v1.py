"""Add vault_connections and canary_secrets tables for secrets-manager integrations.

Revision ID: vault_tables_v1
Revises: endpoint_ephemeral_v1
Create Date: 2026-07-20
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "vault_tables_v1"
down_revision: Union[str, None] = "endpoint_ephemeral_v1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vault_connections",
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
        "canary_secrets",
        sa.Column("id", sa.String(255), primary_key=True),
        sa.Column("vault_connection_id", sa.String(255),
                  sa.ForeignKey("vault_connections.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("template", sa.String(255), nullable=False),
        sa.Column("path", sa.String(255), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("state", sa.String(255), nullable=False,
                  server_default="pending"),
        sa.Column("created_at", sa.String(255), nullable=False),
        sa.Column("last_accessed_at", sa.String(255), nullable=True),
    )
    op.create_index("ix_canary_vault_conn", "canary_secrets",
                    ["vault_connection_id"])


def downgrade() -> None:
    op.drop_index("ix_canary_vault_conn", table_name="canary_secrets")
    op.drop_table("canary_secrets")
    op.drop_table("vault_connections")
