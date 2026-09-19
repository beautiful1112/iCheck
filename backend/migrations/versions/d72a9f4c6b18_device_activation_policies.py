"""device_activation_policies

Revision ID: d72a9f4c6b18
Revises: c31f6e8a4b72
Create Date: 2026-09-18 18:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d72a9f4c6b18"
down_revision: Union[str, Sequence[str], None] = "c31f6e8a4b72"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "device_activation_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "DRAFT",
                "VALIDATED",
                "PUBLISHED",
                "DEPRECATED",
                name="artifactversionstatus",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("adapter_type", sa.String(length=128), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("target_template", sa.JSON(), nullable=False),
        sa.Column("configuration_defaults", sa.JSON(), nullable=False),
        sa.Column("worker_selector", sa.JSON(), nullable=False),
        sa.Column(
            "execution_mode",
            sa.Enum(
                "SCHEDULED",
                "ON_DEMAND",
                name="collectordeploymentmode",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("schedule_seconds", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("validated_by", sa.String(length=255), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_by", sa.String(length=255), nullable=True),
        sa.CheckConstraint(
            "schedule_seconds > 0",
            name="ck_device_activation_policy_schedule_positive",
        ),
        sa.CheckConstraint(
            "version > 0",
            name="ck_device_activation_policy_version_positive",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "name",
            "version",
            name="uq_device_activation_policy_version",
        ),
    )
    op.create_index(
        op.f("ix_device_activation_policies_name"),
        "device_activation_policies",
        ["name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_activation_policies_status"),
        "device_activation_policies",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_activation_policies_protocol"),
        "device_activation_policies",
        ["protocol"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_activation_policies_adapter_type"),
        "device_activation_policies",
        ["adapter_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_activation_policies_artifact_version_id"),
        "device_activation_policies",
        ["artifact_version_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_activation_policies_execution_mode"),
        "device_activation_policies",
        ["execution_mode"],
        unique=False,
    )

    op.create_table(
        "device_connection_activations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column("policy_id", sa.String(length=36), nullable=False),
        sa.Column("deployment_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=False),
        sa.Column("approval_reason", sa.Text(), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deactivated_by", sa.String(length=255), nullable=True),
        sa.Column("deactivation_reason", sa.Text(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["connection_id"],
            ["device_connections.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["deployment_id"],
            ["collector_deployments.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["device_activation_policies.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connection_id",
            name="uq_device_connection_activation",
        ),
        sa.UniqueConstraint(
            "deployment_id",
            name="uq_device_activation_deployment",
        ),
    )
    op.create_index(
        op.f("ix_device_connection_activations_connection_id"),
        "device_connection_activations",
        ["connection_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connection_activations_policy_id"),
        "device_connection_activations",
        ["policy_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connection_activations_deployment_id"),
        "device_connection_activations",
        ["deployment_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connection_activations_status"),
        "device_connection_activations",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_device_connection_activations_status"),
        table_name="device_connection_activations",
    )
    op.drop_index(
        op.f("ix_device_connection_activations_deployment_id"),
        table_name="device_connection_activations",
    )
    op.drop_index(
        op.f("ix_device_connection_activations_policy_id"),
        table_name="device_connection_activations",
    )
    op.drop_index(
        op.f("ix_device_connection_activations_connection_id"),
        table_name="device_connection_activations",
    )
    op.drop_table("device_connection_activations")
    op.drop_index(
        op.f("ix_device_activation_policies_execution_mode"),
        table_name="device_activation_policies",
    )
    op.drop_index(
        op.f("ix_device_activation_policies_artifact_version_id"),
        table_name="device_activation_policies",
    )
    op.drop_index(
        op.f("ix_device_activation_policies_adapter_type"),
        table_name="device_activation_policies",
    )
    op.drop_index(
        op.f("ix_device_activation_policies_protocol"),
        table_name="device_activation_policies",
    )
    op.drop_index(
        op.f("ix_device_activation_policies_status"),
        table_name="device_activation_policies",
    )
    op.drop_index(
        op.f("ix_device_activation_policies_name"),
        table_name="device_activation_policies",
    )
    op.drop_table("device_activation_policies")
