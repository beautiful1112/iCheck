"""agent_action_approvals

Revision ID: 9a4e1c6b8d32
Revises: 8f3d0b5a7c21
Create Date: 2026-09-19 11:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "9a4e1c6b8d32"
down_revision: Union[str, Sequence[str], None] = "8f3d0b5a7c21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_action_proposals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("tool_id", sa.String(length=36), nullable=False),
        sa.Column("tool_call_id", sa.String(length=36), nullable=True),
        sa.Column("iteration", sa.Integer(), nullable=False),
        sa.Column("arguments", sa.JSON(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_by_principal_id", sa.String(length=36), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("approved_by_principal_id", sa.String(length=36), nullable=True),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("result_hash", sa.String(length=64), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tool_id"], ["agent_tool_registrations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["tool_call_id"],
            ["investigation_tool_calls.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_principal_id"],
            ["control_plane_principals.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["approved_by_principal_id"],
            ["control_plane_principals.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tool_call_id"),
        sa.UniqueConstraint(
            "investigation_id",
            "plan_hash",
            name="uq_agent_action_proposal_plan",
        ),
    )
    for column in [
        "investigation_id",
        "tool_id",
        "plan_hash",
        "status",
        "requested_by_principal_id",
        "approved_by_principal_id",
        "requested_at",
    ]:
        op.create_index(
            op.f(f"ix_agent_action_proposals_{column}"),
            "agent_action_proposals",
            [column],
            unique=False,
        )


def downgrade() -> None:
    for column in [
        "requested_at",
        "approved_by_principal_id",
        "requested_by_principal_id",
        "status",
        "plan_hash",
        "tool_id",
        "investigation_id",
    ]:
        op.drop_index(
            op.f(f"ix_agent_action_proposals_{column}"),
            table_name="agent_action_proposals",
        )
    op.drop_table("agent_action_proposals")
