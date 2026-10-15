"""skill-bound investigation runtime

Revision ID: d9a6c4e1f352
Revises: c8f5b3d0e241
Create Date: 2026-09-24 21:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d9a6c4e1f352"
down_revision: Union[str, Sequence[str], None] = "c8f5b3d0e241"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(
            sa.Column("skill_artifact_version_id", sa.String(length=36), nullable=True)
        )
        batch_op.add_column(
            sa.Column("skill_input", sa.JSON(), nullable=False, server_default="{}")
        )
        batch_op.add_column(
            sa.Column("skill_snapshot", sa.JSON(), nullable=False, server_default="{}")
        )
        batch_op.add_column(sa.Column("structured_output", sa.JSON(), nullable=True))
        batch_op.create_foreign_key(
            "fk_investigation_skill_artifact_version",
            "artifact_versions",
            ["skill_artifact_version_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            op.f("ix_investigations_skill_artifact_version_id"),
            ["skill_artifact_version_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_index(op.f("ix_investigations_skill_artifact_version_id"))
        batch_op.drop_constraint(
            "fk_investigation_skill_artifact_version",
            type_="foreignkey",
        )
        batch_op.drop_column("structured_output")
        batch_op.drop_column("skill_snapshot")
        batch_op.drop_column("skill_input")
        batch_op.drop_column("skill_artifact_version_id")
