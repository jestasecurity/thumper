"""Merge the two migration heads into one.

#56 (alert_resolved_at_v1) and #59 (endpoint_decommission_v1) both branched from
deploy_fk_cascade_v1 and merged independently, leaving Alembic with two heads -
so `alembic upgrade head` (run on every startup by init_db) failed with
"Multiple head revisions are present". This no-op merge revision rejoins them
into a single head; it's safe for databases that already applied either or both.

Revision ID: merge_heads_v1
Revises: alert_resolved_at_v1, endpoint_decommission_v1
Create Date: 2026-06-17
"""
from typing import Sequence, Union

revision: str = "merge_heads_v1"
down_revision: Union[str, Sequence[str], None] = (
    "alert_resolved_at_v1", "endpoint_decommission_v1")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
