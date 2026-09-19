"""agent_execution_queue

Revision ID: a47d8e5c1b90
Revises: f31a6c9d2e54
Create Date: 2026-09-19 05:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a47d8e5c1b90"
down_revision: Union[str, Sequence[str], None] = "f31a6c9d2e54"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_workers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("auth_token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "token_issued_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "state",
            sa.Enum(
                "ONLINE",
                "DRAINING",
                "OFFLINE",
                name="agentworkerstate",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column(
            "last_heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_agent_workers_name"),
        "agent_workers",
        ["name"],
        unique=True,
    )
    op.create_index(
        op.f("ix_agent_workers_state"),
        "agent_workers",
        ["state"],
        unique=False,
    )
    op.create_index(
        op.f("ix_agent_workers_last_heartbeat_at"),
        "agent_workers",
        ["last_heartbeat_at"],
        unique=False,
    )

    op.create_table(
        "agent_executions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED",
                "RUNNING",
                "WAITING_APPROVAL",
                "SUCCEEDED",
                "FAILED",
                "CANCELLED",
                name="agentexecutionstatus",
                native_enum=False,
                length=24,
            ),
            nullable=False,
        ),
        sa.Column("worker_id", sa.String(length=36), nullable=True),
        sa.Column("lease_token_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "lease_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column(
            "cancellation_requested_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "cancellation_requested_by",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column("cancellation_reason", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "last_heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_agent_execution_attempt_count",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["agent_workers.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_agent_executions_investigation_id"),
        "agent_executions",
        ["investigation_id"],
        unique=True,
    )
    for column in [
        "status",
        "worker_id",
        "lease_expires_at",
        "cancellation_requested_at",
    ]:
        op.create_index(
            op.f(f"ix_agent_executions_{column}"),
            "agent_executions",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_agent_execution_claim",
        "agent_executions",
        ["status", "lease_expires_at", "created_at"],
        unique=False,
    )

    op.create_table(
        "agent_execution_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("execution_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sequence > 0",
            name="ck_agent_execution_event_sequence",
        ),
        sa.ForeignKeyConstraint(
            ["execution_id"],
            ["agent_executions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_id",
            "sequence",
            name="uq_agent_execution_event_sequence",
        ),
    )
    for column in ["execution_id", "event_type", "created_at"]:
        op.create_index(
            op.f(f"ix_agent_execution_events_{column}"),
            "agent_execution_events",
            [column],
            unique=False,
        )


def downgrade() -> None:
    for column in ["created_at", "event_type", "execution_id"]:
        op.drop_index(
            op.f(f"ix_agent_execution_events_{column}"),
            table_name="agent_execution_events",
        )
    op.drop_table("agent_execution_events")

    op.drop_index(
        "ix_agent_execution_claim",
        table_name="agent_executions",
    )
    for column in [
        "cancellation_requested_at",
        "lease_expires_at",
        "worker_id",
        "status",
        "investigation_id",
    ]:
        op.drop_index(
            op.f(f"ix_agent_executions_{column}"),
            table_name="agent_executions",
        )
    op.drop_table("agent_executions")

    for column in ["last_heartbeat_at", "state", "name"]:
        op.drop_index(
            op.f(f"ix_agent_workers_{column}"),
            table_name="agent_workers",
        )
    op.drop_table("agent_workers")
