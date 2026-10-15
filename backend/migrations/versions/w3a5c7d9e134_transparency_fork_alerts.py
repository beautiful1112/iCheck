"""route verified transparency forks into critical alerts

Revision ID: w3a5c7d9e134
Revises: v2f4a6b8c023
Create Date: 2026-10-06 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "w3a5c7d9e134"
down_revision: str | None = "v2f4a6b8c023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


TABLE = "capability_transparency_gossip_observations"


def upgrade() -> None:
    with op.batch_alter_table(TABLE) as batch:
        batch.add_column(
            sa.Column("alert_id", sa.String(length=36), nullable=True)
        )
        batch.create_foreign_key(
            "fk_transparency_gossip_alert",
            "alerts",
            ["alert_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_index(
            "ix_capability_transparency_gossip_observations_alert_id",
            ["alert_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_index(
            "ix_capability_transparency_gossip_observations_alert_id"
        )
        batch.drop_constraint(
            "fk_transparency_gossip_alert",
            type_="foreignkey",
        )
        batch.drop_column("alert_id")
