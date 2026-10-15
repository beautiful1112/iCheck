"""capability pack uninstall lifecycle

Revision ID: f6b8d0e2a457
Revises: e5a7c9d1f346
Create Date: 2026-09-29 23:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "f6b8d0e2a457"
down_revision: str | None = "e5a7c9d1f346"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("capability_pack_installations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "lifecycle_status",
                sa.String(length=32),
                nullable=False,
                server_default="installed",
            )
        )
        batch_op.add_column(
            sa.Column("uninstall_reason", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "uninstalled_by",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "uninstalled_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "uninstall_summary",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch_op.create_check_constraint(
            "ck_capability_pack_lifecycle_status",
            "lifecycle_status IN ('installed', 'uninstalled')",
        )
    op.create_index(
        "ix_capability_pack_installations_lifecycle_status",
        "capability_pack_installations",
        ["lifecycle_status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_capability_pack_installations_lifecycle_status",
        table_name="capability_pack_installations",
    )
    with op.batch_alter_table("capability_pack_installations") as batch_op:
        batch_op.drop_constraint(
            "ck_capability_pack_lifecycle_status",
            type_="check",
        )
        batch_op.drop_column("uninstall_summary")
        batch_op.drop_column("uninstalled_at")
        batch_op.drop_column("uninstalled_by")
        batch_op.drop_column("uninstall_reason")
        batch_op.drop_column("lifecycle_status")
