"""governed artifact service indicator publication

Revision ID: f5d9a3c1b628
Revises: e4c8f2b0a517
Create Date: 2026-09-29 04:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "f5d9a3c1b628"
down_revision: str | None = "e4c8f2b0a517"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_indicator_artifact_bindings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("definition_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("producer_kind", sa.String(length=16), nullable=False),
        sa.Column("binding_key", sa.String(length=128), nullable=False),
        sa.Column("producer_tool_name", sa.String(length=255), nullable=True),
        sa.Column("output_mapping", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "producer_kind IN ('collector', 'workflow')",
            name="ck_indicator_artifact_binding_kind",
        ),
        sa.CheckConstraint(
            "revision > 0",
            name="ck_indicator_artifact_binding_revision",
        ),
        sa.ForeignKeyConstraint(
            ["definition_id"],
            ["service_indicator_definitions.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "artifact_version_id",
            "producer_kind",
            "binding_key",
            name="uq_indicator_artifact_binding_key",
        ),
    )
    op.create_index(
        "ix_service_indicator_artifact_bindings_definition_id",
        "service_indicator_artifact_bindings",
        ["definition_id"],
        unique=True,
    )
    for column in ("artifact_version_id", "producer_kind", "binding_key", "enabled"):
        op.create_index(
            f"ix_service_indicator_artifact_bindings_{column}",
            "service_indicator_artifact_bindings",
            [column],
        )

    op.create_table(
        "service_indicator_artifact_publications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("binding_id", sa.String(length=36), nullable=False),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("producer_kind", sa.String(length=16), nullable=False),
        sa.Column("collection_envelope_id", sa.String(length=36), nullable=True),
        sa.Column("investigation_id", sa.String(length=36), nullable=True),
        sa.Column("source_tool_call_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "producer_kind IN ('collector', 'workflow')",
            name="ck_indicator_artifact_publication_kind",
        ),
        sa.CheckConstraint(
            "(producer_kind = 'collector' AND collection_envelope_id IS NOT NULL "
            "AND investigation_id IS NULL AND source_tool_call_id IS NULL) OR "
            "(producer_kind = 'workflow' AND collection_envelope_id IS NULL "
            "AND investigation_id IS NOT NULL AND source_tool_call_id IS NOT NULL)",
            name="ck_indicator_artifact_publication_source",
        ),
        sa.ForeignKeyConstraint(
            ["binding_id"],
            ["service_indicator_artifact_bindings.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["observation_id"],
            ["service_indicator_observations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["collection_envelope_id"],
            ["collection_envelopes.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["source_tool_call_id"],
            ["investigation_tool_calls.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "observation_id",
            name="uq_indicator_artifact_publication_observation",
        ),
        sa.UniqueConstraint(
            "binding_id",
            "collection_envelope_id",
            name="uq_indicator_artifact_publication_envelope",
        ),
        sa.UniqueConstraint(
            "binding_id",
            "investigation_id",
            name="uq_indicator_artifact_publication_investigation",
        ),
    )
    for column in (
        "binding_id",
        "observation_id",
        "artifact_version_id",
        "producer_kind",
        "collection_envelope_id",
        "investigation_id",
        "source_tool_call_id",
        "created_at",
    ):
        op.create_index(
            op.f(f"ix_service_indicator_artifact_publications_{column}"),
            "service_indicator_artifact_publications",
            [column],
        )


def downgrade() -> None:
    for column in reversed(
        (
            "binding_id",
            "observation_id",
            "artifact_version_id",
            "producer_kind",
            "collection_envelope_id",
            "investigation_id",
            "source_tool_call_id",
            "created_at",
        )
    ):
        op.drop_index(
            op.f(f"ix_service_indicator_artifact_publications_{column}"),
            table_name="service_indicator_artifact_publications",
        )
    op.drop_table("service_indicator_artifact_publications")
    for column in reversed(
        ("artifact_version_id", "producer_kind", "binding_key", "enabled")
    ):
        op.drop_index(
            f"ix_service_indicator_artifact_bindings_{column}",
            table_name="service_indicator_artifact_bindings",
        )
    op.drop_index(
        "ix_service_indicator_artifact_bindings_definition_id",
        table_name="service_indicator_artifact_bindings",
    )
    op.drop_table("service_indicator_artifact_bindings")
