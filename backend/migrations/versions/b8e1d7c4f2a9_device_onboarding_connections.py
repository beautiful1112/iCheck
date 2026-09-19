"""device_onboarding_connections

Revision ID: b8e1d7c4f2a9
Revises: a92d4f36e5b1
Create Date: 2026-09-18 14:50:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b8e1d7c4f2a9"
down_revision: Union[str, Sequence[str], None] = "a92d4f36e5b1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column(
            "labels",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.add_column(
        "devices",
        sa.Column(
            "onboarding_status",
            sa.String(length=32),
            nullable=False,
            server_default="pending_verification",
        ),
    )
    op.add_column(
        "devices",
        sa.Column(
            "created_by",
            sa.String(length=255),
            nullable=False,
            server_default="system.migration",
        ),
    )
    op.create_index(
        op.f("ix_devices_onboarding_status"),
        "devices",
        ["onboarding_status"],
        unique=False,
    )

    op.create_table(
        "device_connections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("adapter_type", sa.String(length=128), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column(
            "credential_profile_ref",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column("worker_selector", sa.JSON(), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("verification_status", sa.String(length=32), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_verification_error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "port IS NULL OR (port > 0 AND port <= 65535)",
            name="ck_device_connection_port",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "device_id",
            "protocol",
            name="uq_device_connection_protocol",
        ),
    )
    op.create_index(
        op.f("ix_device_connections_adapter_type"),
        "device_connections",
        ["adapter_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connections_device_id"),
        "device_connections",
        ["device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connections_enabled"),
        "device_connections",
        ["enabled"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connections_protocol"),
        "device_connections",
        ["protocol"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connections_verification_status"),
        "device_connections",
        ["verification_status"],
        unique=False,
    )
    op.create_index(
        "ix_device_connection_verification",
        "device_connections",
        ["verification_status", "updated_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_device_connection_verification",
        table_name="device_connections",
    )
    op.drop_index(
        op.f("ix_device_connections_verification_status"),
        table_name="device_connections",
    )
    op.drop_index(
        op.f("ix_device_connections_protocol"),
        table_name="device_connections",
    )
    op.drop_index(
        op.f("ix_device_connections_enabled"),
        table_name="device_connections",
    )
    op.drop_index(
        op.f("ix_device_connections_device_id"),
        table_name="device_connections",
    )
    op.drop_index(
        op.f("ix_device_connections_adapter_type"),
        table_name="device_connections",
    )
    op.drop_table("device_connections")
    op.drop_index(op.f("ix_devices_onboarding_status"), table_name="devices")
    op.drop_column("devices", "created_by")
    op.drop_column("devices", "onboarding_status")
    op.drop_column("devices", "labels")
