"""Add alerts.resolved_at for alert lifecycle (Open → Resolved).

NULL means the alert is open (unresolved); a timestamp means a user resolved it.
Existing rows migrate to NULL, i.e. all currently-open - matching prior behavior
where every fired alert counted as an active trigger.

Revision ID: alert_resolved_at_v1
Revises: deploy_fk_cascade_v1
Create Date: 2026-06-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "alert_resolved_at_v1"
down_revision: Union[str, None] = "deploy_fk_cascade_v1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("alerts") as b:
        b.add_column(sa.Column("resolved_at", sa.String(length=255), nullable=True))
    # Active-count queries all filter resolved_at IS NULL - index it.
    op.create_index("ix_alert_resolved_at", "alerts", ["resolved_at"])


def downgrade() -> None:
    op.drop_index("ix_alert_resolved_at", table_name="alerts")
    with op.batch_alter_table("alerts") as b:
        b.drop_column("resolved_at")
