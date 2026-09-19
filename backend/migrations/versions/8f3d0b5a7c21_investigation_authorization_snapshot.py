"""investigation_authorization_snapshot

Revision ID: 8f3d0b5a7c21
Revises: 7e2c9a4f6b10
Create Date: 2026-09-19 10:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8f3d0b5a7c21"
down_revision: Union[str, Sequence[str], None] = "7e2c9a4f6b10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "requested_by_principal_id",
                sa.String(length=36),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "permission_snapshot",
                sa.JSON(),
                server_default=sa.text("'[\"*\"]'"),
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "authorization_scope",
                sa.JSON(),
                server_default=sa.text("'{\"all\": true}'"),
                nullable=False,
            )
        )
        batch_op.create_foreign_key(
            "fk_investigation_requested_by_principal",
            "control_plane_principals",
            ["requested_by_principal_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            op.f("ix_investigations_requested_by_principal_id"),
            ["requested_by_principal_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_index(op.f("ix_investigations_requested_by_principal_id"))
        batch_op.drop_constraint(
            "fk_investigation_requested_by_principal", type_="foreignkey"
        )
        batch_op.drop_column("authorization_scope")
        batch_op.drop_column("permission_snapshot")
        batch_op.drop_column("requested_by_principal_id")
