"""governed service indicator evidence and assessment snapshots

Revision ID: a06c8d4e2b97
Revises: 9f5b1c7e3a86
Create Date: 2026-09-28 05:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "a06c8d4e2b97"
down_revision: str | None = "9f5b1c7e3a86"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_indicator_definitions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("service_id", sa.String(length=36), nullable=False),
        sa.Column("indicator_key", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("unit", sa.String(length=64), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_ref", sa.String(length=1024), nullable=False),
        sa.Column("breach_direction", sa.String(length=16), nullable=False),
        sa.Column("warning_threshold", sa.Float(), nullable=True),
        sa.Column("critical_threshold", sa.Float(), nullable=True),
        sa.Column("freshness_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('availability', 'latency', 'error_rate', 'throughput', "
            "'saturation', 'business', 'custom')",
            name="ck_service_indicator_kind",
        ),
        sa.CheckConstraint(
            "source_type IN ('prometheus', 'api', 'collector', 'business_system', 'manual')",
            name="ck_service_indicator_source_type",
        ),
        sa.CheckConstraint(
            "breach_direction IN ('above', 'below', 'none')",
            name="ck_service_indicator_breach_direction",
        ),
        sa.CheckConstraint(
            "freshness_seconds >= 10 AND freshness_seconds <= 2592000",
            name="ck_service_indicator_freshness",
        ),
        sa.CheckConstraint("revision > 0", name="ck_service_indicator_revision"),
        sa.ForeignKeyConstraint(
            ["service_id"], ["service_catalog_entries.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "service_id",
            "indicator_key",
            name="uq_service_indicator_definition_key",
        ),
    )
    for column in (
        "service_id",
        "indicator_key",
        "kind",
        "source_type",
        "enabled",
    ):
        op.create_index(
            op.f(f"ix_service_indicator_definitions_{column}"),
            "service_indicator_definitions",
            [column],
        )
    op.create_index(
        "ix_service_indicator_definition_active",
        "service_indicator_definitions",
        ["service_id", "enabled", "indicator_key"],
    )

    op.create_table(
        "service_indicator_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("definition_id", sa.String(length=36), nullable=False),
        sa.Column("source_observation_id", sa.String(length=255), nullable=False),
        sa.Column("value", sa.Float(), nullable=False),
        sa.Column("measurement_quality", sa.String(length=16), nullable=False),
        sa.Column("dimensions", sa.JSON(), nullable=False),
        sa.Column("evidence_ref", sa.String(length=2048), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.CheckConstraint(
            "measurement_quality IN ('measured', 'estimated', 'manual')",
            name="ck_service_indicator_observation_quality",
        ),
        sa.ForeignKeyConstraint(
            ["definition_id"],
            ["service_indicator_definitions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "definition_id",
            "source_observation_id",
            name="uq_service_indicator_observation_source",
        ),
    )
    for column in (
        "definition_id",
        "source_observation_id",
        "measurement_quality",
        "observed_at",
        "ingested_at",
    ):
        op.create_index(
            op.f(f"ix_service_indicator_observations_{column}"),
            "service_indicator_observations",
            [column],
        )
    op.create_index(
        "ix_service_indicator_observation_latest",
        "service_indicator_observations",
        ["definition_id", "observed_at", "ingested_at"],
    )

    op.add_column(
        "situation_impact_assessments",
        sa.Column(
            "indicator_context_snapshot",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )


def downgrade() -> None:
    op.drop_column(
        "situation_impact_assessments",
        "indicator_context_snapshot",
    )
    op.drop_table("service_indicator_observations")
    op.drop_table("service_indicator_definitions")
