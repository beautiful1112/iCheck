"""workflow-bound investigation runtime

Revision ID: e0b7d5f2a463
Revises: d9a6c4e1f352
Create Date: 2026-09-24 08:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e0b7d5f2a463"
down_revision: str | None = "d9a6c4e1f352"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(
            sa.Column("workflow_artifact_version_id", sa.String(length=36), nullable=True)
        )
        batch_op.add_column(
            sa.Column("workflow_input", sa.JSON(), nullable=False, server_default="{}")
        )
        batch_op.add_column(
            sa.Column("workflow_snapshot", sa.JSON(), nullable=False, server_default="{}")
        )
        batch_op.create_foreign_key(
            "fk_investigations_workflow_artifact_version_id",
            "artifact_versions",
            ["workflow_artifact_version_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_investigations_workflow_artifact_version_id",
            ["workflow_artifact_version_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_index("ix_investigations_workflow_artifact_version_id")
        batch_op.drop_constraint(
            "fk_investigations_workflow_artifact_version_id",
            type_="foreignkey",
        )
        batch_op.drop_column("workflow_snapshot")
        batch_op.drop_column("workflow_input")
        batch_op.drop_column("workflow_artifact_version_id")
