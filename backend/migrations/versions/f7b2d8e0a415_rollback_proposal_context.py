"""link rollback proposals to governed change plans

Revision ID: f7b2d8e0a415
Revises: f6a1c7d9e304
Create Date: 2026-09-29 14:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "f7b2d8e0a415"
down_revision: str | None = "f6a1c7d9e304"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("agent_action_proposals") as batch_op:
        batch_op.add_column(
            sa.Column(
                "rollback_of_change_plan_id",
                sa.String(length=36),
                nullable=True,
            )
        )
        batch_op.create_foreign_key(
            "fk_agent_action_proposal_rollback_change_plan",
            "governed_change_plans",
            ["rollback_of_change_plan_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_agent_action_proposals_rollback_of_change_plan_id",
            ["rollback_of_change_plan_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("agent_action_proposals") as batch_op:
        batch_op.drop_index(
            "ix_agent_action_proposals_rollback_of_change_plan_id"
        )
        batch_op.drop_constraint(
            "fk_agent_action_proposal_rollback_change_plan",
            type_="foreignkey",
        )
        batch_op.drop_column("rollback_of_change_plan_id")
