"""Add endpoints.decommission_requested_at for remote self-destruct.

NULL = live. A timestamp means the operator asked the endpoint to decommission;
the agent gets a kill signal on its next heartbeat and the row is removed once it
confirms (or via force-remove).

Revision ID: endpoint_decommission_v1
Revises: deploy_fk_cascade_v1
Create Date: 2026-06-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "endpoint_decommission_v1"
down_revision: Union[str, None] = "deploy_fk_cascade_v1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("endpoints") as b:
        b.add_column(sa.Column("decommission_requested_at", sa.String(length=255), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("endpoints") as b:
        b.drop_column("decommission_requested_at")
