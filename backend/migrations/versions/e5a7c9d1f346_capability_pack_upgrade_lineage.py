"""capability pack upgrade lineage

Revision ID: e5a7c9d1f346
Revises: d4f6a8c0e235
Create Date: 2026-09-29 23:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e5a7c9d1f346"
down_revision: str | None = "d4f6a8c0e235"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("capability_pack_installations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "operation",
                sa.String(length=32),
                nullable=False,
                server_default="install",
            )
        )
        batch_op.add_column(
            sa.Column(
                "predecessor_installation_id",
                sa.String(length=36),
                nullable=True,
            )
        )
        batch_op.create_foreign_key(
            "fk_capability_pack_installation_predecessor",
            "capability_pack_installations",
            ["predecessor_installation_id"],
            ["id"],
            ondelete="RESTRICT",
        )
    op.create_index(
        "ix_capability_pack_installations_predecessor_installation_id",
        "capability_pack_installations",
        ["predecessor_installation_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_capability_pack_installations_predecessor_installation_id",
        table_name="capability_pack_installations",
    )
    with op.batch_alter_table("capability_pack_installations") as batch_op:
        batch_op.drop_constraint(
            "fk_capability_pack_installation_predecessor",
            type_="foreignkey",
        )
        batch_op.drop_column("predecessor_installation_id")
        batch_op.drop_column("operation")
