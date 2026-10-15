"""governed service dependencies and assessment snapshots

Revision ID: 8e4a0b6d2f75
Revises: 7d3f9a5c1e64
Create Date: 2026-09-27 22:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "8e4a0b6d2f75"
down_revision: str | None = "7d3f9a5c1e64"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_catalog_dependencies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_service_id", sa.String(length=36), nullable=False),
        sa.Column("target_service_id", sa.String(length=36), nullable=False),
        sa.Column("dependency_type", sa.String(length=32), nullable=False),
        sa.Column("critical", sa.Boolean(), nullable=False),
        sa.Column("evidence_note", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source_service_id <> target_service_id",
            name="ck_service_catalog_dependency_not_self",
        ),
        sa.CheckConstraint(
            "dependency_type IN ('synchronous', 'asynchronous', 'data', 'shared_infrastructure')",
            name="ck_service_catalog_dependency_type",
        ),
        sa.ForeignKeyConstraint(
            ["source_service_id"],
            ["service_catalog_entries.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_service_id"],
            ["service_catalog_entries.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_service_id",
            "target_service_id",
            "dependency_type",
            name="uq_service_catalog_dependency",
        ),
    )
    for column in (
        "source_service_id",
        "target_service_id",
        "dependency_type",
        "critical",
    ):
        op.create_index(
            op.f(f"ix_service_catalog_dependencies_{column}"),
            "service_catalog_dependencies",
            [column],
        )
    op.create_index(
        "ix_service_catalog_dependency_target_source",
        "service_catalog_dependencies",
        ["target_service_id", "source_service_id"],
    )
    op.add_column(
        "situation_impact_assessments",
        sa.Column(
            "dependency_context_snapshot",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )


def downgrade() -> None:
    op.drop_column(
        "situation_impact_assessments",
        "dependency_context_snapshot",
    )
    op.drop_table("service_catalog_dependencies")
