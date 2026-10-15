"""remote pack acquisition provenance

Revision ID: h8d0f2a4c679
Revises: g7c9e1f3b568
Create Date: 2026-09-30 00:20:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "h8d0f2a4c679"
down_revision: str | None = "g7c9e1f3b568"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("capability_pack_installations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "distribution_channel",
                sa.String(length=32),
                nullable=False,
                server_default="upload",
            )
        )
        batch_op.add_column(
            sa.Column(
                "distribution_snapshot",
                sa.JSON(),
                nullable=False,
                server_default="{}",
            )
        )
        batch_op.create_index(
            "ix_capability_pack_installations_distribution_channel",
            ["distribution_channel"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("capability_pack_installations") as batch_op:
        batch_op.drop_index(
            "ix_capability_pack_installations_distribution_channel"
        )
        batch_op.drop_column("distribution_snapshot")
        batch_op.drop_column("distribution_channel")
