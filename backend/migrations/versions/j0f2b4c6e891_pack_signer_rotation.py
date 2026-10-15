"""capability pack signer rotation evidence

Revision ID: j0f2b4c6e891
Revises: i9e1a3b5d780
Create Date: 2026-09-30 01:50:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "j0f2b4c6e891"
down_revision: str | None = "i9e1a3b5d780"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("capability_pack_installations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "signer_rotation_snapshot",
                sa.JSON(),
                nullable=False,
                server_default="{}",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("capability_pack_installations") as batch_op:
        batch_op.drop_column("signer_rotation_snapshot")
