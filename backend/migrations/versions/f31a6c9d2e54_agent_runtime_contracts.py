"""agent_runtime_contracts

Revision ID: f31a6c9d2e54
Revises: e84b7a2d19c3
Create Date: 2026-09-18 22:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f31a6c9d2e54"
down_revision: Union[str, Sequence[str], None] = "e84b7a2d19c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_tool_registrations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("transport", sa.String(length=32), nullable=False),
        sa.Column("handler", sa.String(length=512), nullable=False),
        sa.Column("input_schema", sa.JSON(), nullable=False),
        sa.Column("output_schema", sa.JSON(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("read_only", sa.Boolean(), nullable=False),
        sa.Column("required_permissions", sa.JSON(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("max_result_bytes", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "max_result_bytes > 0", name="ck_agent_tool_result_bytes_positive"
        ),
        sa.CheckConstraint(
            "timeout_seconds > 0", name="ck_agent_tool_timeout_positive"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column, unique in [
        ("name", True),
        ("transport", False),
        ("risk_level", False),
        ("read_only", False),
        ("enabled", False),
    ]:
        op.create_index(
            op.f(f"ix_agent_tool_registrations_{column}"),
            "agent_tool_registrations",
            [column],
            unique=unique,
        )

    op.create_table(
        "investigations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("route_id", sa.String(length=36), nullable=False),
        sa.Column("model_id", sa.String(length=36), nullable=False),
        sa.Column("max_iterations", sa.Integer(), nullable=False),
        sa.Column("max_tool_calls", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("token_budget", sa.Integer(), nullable=False),
        sa.Column("iterations_used", sa.Integer(), nullable=False),
        sa.Column("tool_calls_used", sa.Integer(), nullable=False),
        sa.Column("tokens_used", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("conclusion", sa.Text(), nullable=True),
        sa.Column("uncertainty", sa.JSON(), nullable=False),
        sa.Column("escalation_reason", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "iterations_used >= 0", name="ck_investigation_iterations_used"
        ),
        sa.CheckConstraint(
            "max_iterations > 0", name="ck_investigation_iterations_positive"
        ),
        sa.CheckConstraint(
            "max_tool_calls > 0", name="ck_investigation_tools_positive"
        ),
        sa.CheckConstraint(
            "timeout_seconds > 0", name="ck_investigation_timeout_positive"
        ),
        sa.CheckConstraint(
            "token_budget > 0", name="ck_investigation_tokens_positive"
        ),
        sa.CheckConstraint("tokens_used >= 0", name="ck_investigation_tokens_used"),
        sa.CheckConstraint(
            "tool_calls_used >= 0", name="ck_investigation_tools_used"
        ),
        sa.ForeignKeyConstraint(
            ["model_id"], ["ai_model_configs.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["route_id"], ["ai_model_routes.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ["status", "route_id", "model_id"]:
        op.create_index(
            op.f(f"ix_investigations_{column}"),
            "investigations",
            [column],
            unique=False,
        )

    op.create_table(
        "investigation_checkpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("node", sa.String(length=128), nullable=False),
        sa.Column("state", sa.JSON(), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sequence > 0", name="ck_investigation_checkpoint_sequence"
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_id",
            "sequence",
            name="uq_investigation_checkpoint_sequence",
        ),
    )
    op.create_index(
        op.f("ix_investigation_checkpoints_investigation_id"),
        "investigation_checkpoints",
        ["investigation_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_investigation_checkpoints_node"),
        "investigation_checkpoints",
        ["node"],
        unique=False,
    )

    op.create_table(
        "investigation_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("evidence_id", sa.String(length=512), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_id",
            "evidence_type",
            "evidence_id",
            name="uq_investigation_evidence_reference",
        ),
    )
    for column in ["investigation_id", "evidence_type", "evidence_id"]:
        op.create_index(
            op.f(f"ix_investigation_evidence_{column}"),
            "investigation_evidence",
            [column],
            unique=False,
        )

    op.create_table(
        "investigation_tool_calls",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("tool_id", sa.String(length=36), nullable=False),
        sa.Column("iteration", sa.Integer(), nullable=False),
        sa.Column("call_hash", sa.String(length=64), nullable=False),
        sa.Column("arguments", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("result_hash", sa.String(length=64), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "iteration > 0", name="ck_investigation_tool_iteration"
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tool_id"], ["agent_tool_registrations.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_id",
            "call_hash",
            name="uq_investigation_tool_call_hash",
        ),
    )
    for column in ["investigation_id", "tool_id", "status"]:
        op.create_index(
            op.f(f"ix_investigation_tool_calls_{column}"),
            "investigation_tool_calls",
            [column],
            unique=False,
        )


def downgrade() -> None:
    for column in ["status", "tool_id", "investigation_id"]:
        op.drop_index(
            op.f(f"ix_investigation_tool_calls_{column}"),
            table_name="investigation_tool_calls",
        )
    op.drop_table("investigation_tool_calls")
    for column in ["evidence_id", "evidence_type", "investigation_id"]:
        op.drop_index(
            op.f(f"ix_investigation_evidence_{column}"),
            table_name="investigation_evidence",
        )
    op.drop_table("investigation_evidence")
    op.drop_index(
        op.f("ix_investigation_checkpoints_node"),
        table_name="investigation_checkpoints",
    )
    op.drop_index(
        op.f("ix_investigation_checkpoints_investigation_id"),
        table_name="investigation_checkpoints",
    )
    op.drop_table("investigation_checkpoints")
    for column in ["model_id", "route_id", "status"]:
        op.drop_index(
            op.f(f"ix_investigations_{column}"),
            table_name="investigations",
        )
    op.drop_table("investigations")
    for column in ["enabled", "read_only", "risk_level", "transport", "name"]:
        op.drop_index(
            op.f(f"ix_agent_tool_registrations_{column}"),
            table_name="agent_tool_registrations",
        )
    op.drop_table("agent_tool_registrations")
