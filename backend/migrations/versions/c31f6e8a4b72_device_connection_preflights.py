"""device_connection_preflights

Revision ID: c31f6e8a4b72
Revises: b8e1d7c4f2a9
Create Date: 2026-09-18 16:20:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c31f6e8a4b72"
down_revision: Union[str, Sequence[str], None] = "b8e1d7c4f2a9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "device_connections",
        sa.Column(
            "last_verification_worker_id",
            sa.String(length=36),
            nullable=True,
        ),
    )
    op.add_column(
        "device_connections",
        sa.Column(
            "last_verification_latency_ms",
            sa.Integer(),
            nullable=True,
        ),
    )
    op.add_column(
        "device_connections",
        sa.Column(
            "last_verification_evidence",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.add_column(
        "device_connections",
        sa.Column("verification_worker_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "device_connections",
        sa.Column(
            "verification_lease_token_hash",
            sa.String(length=64),
            nullable=True,
        ),
    )
    op.add_column(
        "device_connections",
        sa.Column(
            "verification_lease_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "device_connections",
        sa.Column(
            "next_verification_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_index(
        op.f("ix_device_connections_verification_worker_id"),
        "device_connections",
        ["verification_worker_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connections_verification_lease_expires_at"),
        "device_connections",
        ["verification_lease_expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connections_next_verification_at"),
        "device_connections",
        ["next_verification_at"],
        unique=False,
    )
    op.execute(
        "UPDATE device_connections "
        "SET next_verification_at = CURRENT_TIMESTAMP "
        "WHERE enabled = TRUE AND verification_status = 'pending'"
    )

    op.create_table(
        "device_connection_preflights",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column("worker_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("lease_token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "lease_expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "latency_ms IS NULL OR latency_ms >= 0",
            name="ck_device_preflight_latency_nonnegative",
        ),
        sa.ForeignKeyConstraint(
            ["connection_id"],
            ["device_connections.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["collector_workers.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_device_connection_preflights_connection_id"),
        "device_connection_preflights",
        ["connection_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connection_preflights_worker_id"),
        "device_connection_preflights",
        ["worker_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connection_preflights_status"),
        "device_connection_preflights",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connection_preflights_lease_expires_at"),
        "device_connection_preflights",
        ["lease_expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connection_preflights_started_at"),
        "device_connection_preflights",
        ["started_at"],
        unique=False,
    )
    op.create_index(
        "ix_device_preflight_connection_started",
        "device_connection_preflights",
        ["connection_id", "started_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_device_preflight_connection_started",
        table_name="device_connection_preflights",
    )
    op.drop_index(
        op.f("ix_device_connection_preflights_started_at"),
        table_name="device_connection_preflights",
    )
    op.drop_index(
        op.f("ix_device_connection_preflights_lease_expires_at"),
        table_name="device_connection_preflights",
    )
    op.drop_index(
        op.f("ix_device_connection_preflights_status"),
        table_name="device_connection_preflights",
    )
    op.drop_index(
        op.f("ix_device_connection_preflights_worker_id"),
        table_name="device_connection_preflights",
    )
    op.drop_index(
        op.f("ix_device_connection_preflights_connection_id"),
        table_name="device_connection_preflights",
    )
    op.drop_table("device_connection_preflights")
    op.drop_index(
        op.f("ix_device_connections_next_verification_at"),
        table_name="device_connections",
    )
    op.drop_index(
        op.f("ix_device_connections_verification_lease_expires_at"),
        table_name="device_connections",
    )
    op.drop_index(
        op.f("ix_device_connections_verification_worker_id"),
        table_name="device_connections",
    )
    op.drop_column("device_connections", "next_verification_at")
    op.drop_column("device_connections", "verification_lease_expires_at")
    op.drop_column("device_connections", "verification_lease_token_hash")
    op.drop_column("device_connections", "verification_worker_id")
    op.drop_column("device_connections", "last_verification_evidence")
    op.drop_column("device_connections", "last_verification_latency_ms")
    op.drop_column("device_connections", "last_verification_worker_id")
