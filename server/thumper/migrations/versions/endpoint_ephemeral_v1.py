"""Add endpoints.ephemeral for per-job CI tripwire endpoints.

Ephemeral endpoints are enrolled by a GitHub Action on job start and removed
(or pruned on stale) when the job ends. Non-ephemeral endpoints carry ephemeral=0.

Revision ID: endpoint_ephemeral_v1
Revises: merge_heads_v1
Create Date: 2026-06-25
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "endpoint_ephemeral_v1"
down_revision: Union[str, None] = "merge_heads_v1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("endpoints") as b:
        b.add_column(sa.Column("ephemeral", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("endpoints") as b:
        b.drop_column("ephemeral")
