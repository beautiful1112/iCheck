"""generic scoped knowledge entity and relationship graph

Revision ID: 1d5b9f7a4c82
Revises: 0c4a8e6d3f97
Create Date: 2026-09-25 04:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "1d5b9f7a4c82"
down_revision: str | None = "0c4a8e6d3f97"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "knowledge_entities",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("namespace", sa.String(length=255), nullable=False),
        sa.Column("scope_key", sa.String(length=255), nullable=False),
        sa.Column("scope_device_id", sa.String(length=36), nullable=True),
        sa.Column("scope_site", sa.String(length=128), nullable=True),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("external_key", sa.String(length=512), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_envelope_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["last_envelope_id"],
            ["collection_envelopes.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["scope_device_id"], ["devices.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "namespace",
            "scope_key",
            "entity_type",
            "external_key",
            name="uq_knowledge_entity_identity",
        ),
    )
    for column in (
        "namespace",
        "scope_key",
        "scope_device_id",
        "scope_site",
        "entity_type",
        "external_key",
        "display_name",
        "status",
        "active",
        "last_seen",
        "observed_at",
        "last_envelope_id",
    ):
        op.create_index(
            f"ix_knowledge_entities_{column}",
            "knowledge_entities",
            [column],
        )
    op.create_index(
        "ix_knowledge_entity_scope_type",
        "knowledge_entities",
        ["scope_key", "entity_type", "active"],
    )
    op.create_index(
        "ix_knowledge_entity_site_type",
        "knowledge_entities",
        ["scope_site", "entity_type", "active"],
    )

    op.create_table(
        "knowledge_relationships",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("namespace", sa.String(length=255), nullable=False),
        sa.Column("scope_key", sa.String(length=255), nullable=False),
        sa.Column("scope_device_id", sa.String(length=36), nullable=True),
        sa.Column("scope_site", sa.String(length=128), nullable=True),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("source_entity_id", sa.String(length=36), nullable=False),
        sa.Column("target_entity_id", sa.String(length=36), nullable=False),
        sa.Column("directed", sa.Boolean(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_envelope_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["last_envelope_id"],
            ["collection_envelopes.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["scope_device_id"], ["devices.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["source_entity_id"],
            ["knowledge_entities.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_entity_id"],
            ["knowledge_entities.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "namespace",
            "scope_key",
            "relationship_type",
            "source_entity_id",
            "target_entity_id",
            "directed",
            name="uq_knowledge_relationship_identity",
        ),
    )
    for column in (
        "namespace",
        "scope_key",
        "scope_device_id",
        "scope_site",
        "relationship_type",
        "source_entity_id",
        "target_entity_id",
        "active",
        "last_seen",
        "observed_at",
        "last_envelope_id",
    ):
        op.create_index(
            f"ix_knowledge_relationships_{column}",
            "knowledge_relationships",
            [column],
        )
    op.create_index(
        "ix_knowledge_relationship_scope_type",
        "knowledge_relationships",
        ["scope_key", "relationship_type", "active"],
    )
    op.create_index(
        "ix_knowledge_relationship_site_type",
        "knowledge_relationships",
        ["scope_site", "relationship_type", "active"],
    )


def downgrade() -> None:
    op.drop_table("knowledge_relationships")
    op.drop_table("knowledge_entities")
