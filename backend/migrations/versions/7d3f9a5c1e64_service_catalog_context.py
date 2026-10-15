"""governed service catalog and impact context snapshot

Revision ID: 7d3f9a5c1e64
Revises: 6c2e8f4b0d53
Create Date: 2026-09-27 20:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "7d3f9a5c1e64"
down_revision: str | None = "6c2e8f4b0d53"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_catalog_entries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("service_key", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("owner_team", sa.String(length=255), nullable=False),
        sa.Column("owner_contact", sa.String(length=512), nullable=True),
        sa.Column("criticality", sa.String(length=16), nullable=False),
        sa.Column("business_impact", sa.String(length=16), nullable=False),
        sa.Column("business_impact_summary", sa.Text(), nullable=False),
        sa.Column("slo_target_percent", sa.Float(), nullable=True),
        sa.Column("recovery_time_objective_minutes", sa.Integer(), nullable=True),
        sa.Column("recovery_point_objective_minutes", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'retired')",
            name="ck_service_catalog_status",
        ),
        sa.CheckConstraint(
            "criticality IN ('tier_0', 'tier_1', 'tier_2', 'tier_3')",
            name="ck_service_catalog_criticality",
        ),
        sa.CheckConstraint(
            "business_impact IN ('critical', 'high', 'moderate', 'low')",
            name="ck_service_catalog_business_impact",
        ),
        sa.CheckConstraint(
            "slo_target_percent IS NULL OR (slo_target_percent >= 0 AND slo_target_percent <= 100)",
            name="ck_service_catalog_slo_target",
        ),
        sa.CheckConstraint(
            "recovery_time_objective_minutes IS NULL OR recovery_time_objective_minutes >= 0",
            name="ck_service_catalog_rto",
        ),
        sa.CheckConstraint(
            "recovery_point_objective_minutes IS NULL OR recovery_point_objective_minutes >= 0",
            name="ck_service_catalog_rpo",
        ),
        sa.CheckConstraint("revision > 0", name="ck_service_catalog_revision"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "service_key",
        "name",
        "owner_team",
        "criticality",
        "business_impact",
        "status",
    ):
        op.create_index(
            op.f(f"ix_service_catalog_entries_{column}"),
            "service_catalog_entries",
            [column],
            unique=column == "service_key",
        )
    op.create_index(
        "ix_service_catalog_priority",
        "service_catalog_entries",
        ["status", "criticality", "business_impact"],
    )

    op.create_table(
        "service_catalog_components",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("service_id", sa.String(length=36), nullable=False),
        sa.Column("node_id", sa.String(length=255), nullable=False),
        sa.Column("node_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("required", sa.Boolean(), nullable=False),
        sa.Column("evidence_note", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "node_type IN ('device', 'endpoint', 'knowledge_entity')",
            name="ck_service_catalog_component_node_type",
        ),
        sa.CheckConstraint(
            "role IN ('entrypoint', 'dependency', 'compute', 'data', 'network', 'other')",
            name="ck_service_catalog_component_role",
        ),
        sa.ForeignKeyConstraint(
            ["service_id"], ["service_catalog_entries.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "service_id",
            "node_id",
            name="uq_service_catalog_component_node",
        ),
    )
    for column in ("service_id", "node_id", "node_type", "entity_id"):
        op.create_index(
            op.f(f"ix_service_catalog_components_{column}"),
            "service_catalog_components",
            [column],
        )
    op.create_index(
        "ix_service_catalog_component_entity",
        "service_catalog_components",
        ["node_type", "entity_id"],
    )

    op.add_column(
        "situation_impact_assessments",
        sa.Column(
            "service_context_snapshot",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )


def downgrade() -> None:
    op.drop_column(
        "situation_impact_assessments",
        "service_context_snapshot",
    )
    op.drop_table("service_catalog_components")
    op.drop_table("service_catalog_entries")
