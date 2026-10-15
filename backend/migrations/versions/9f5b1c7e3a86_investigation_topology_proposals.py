"""investigation topology proposals and evidence

Revision ID: 9f5b1c7e3a86
Revises: 8e4a0b6d2f75
Create Date: 2026-09-28 02:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "9f5b1c7e3a86"
down_revision: str | None = "8e4a0b6d2f75"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "investigation_topology_proposals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("checkpoint_id", sa.String(length=36), nullable=False),
        sa.Column("contract_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("spec", sa.JSON(), nullable=False),
        sa.Column("validation_report", sa.JSON(), nullable=False),
        sa.Column("uncertainty", sa.JSON(), nullable=False),
        sa.Column("authorization_scope", sa.JSON(), nullable=False),
        sa.Column("source_model_id", sa.String(length=36), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("artifact_id", sa.String(length=36), nullable=True),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('proposed', 'published', 'rejected')",
            name="ck_investigation_topology_proposal_status",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"], ["artifacts.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["checkpoint_id"],
            ["investigation_checkpoints.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_id",
            name="uq_investigation_topology_proposal_investigation",
        ),
    )
    for column in (
        "investigation_id",
        "checkpoint_id",
        "status",
        "artifact_id",
        "artifact_version_id",
    ):
        op.create_index(
            op.f(f"ix_investigation_topology_proposals_{column}"),
            "investigation_topology_proposals",
            [column],
            unique=column == "investigation_id",
        )
    op.create_index(
        "ix_investigation_topology_proposal_queue",
        "investigation_topology_proposals",
        ["status", "created_at"],
    )

    op.create_table(
        "investigation_topology_proposal_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("proposal_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_evidence_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["investigation_evidence_id"],
            ["investigation_evidence.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["proposal_id"],
            ["investigation_topology_proposals.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "proposal_id",
            "investigation_evidence_id",
            name="uq_investigation_topology_proposal_evidence",
        ),
    )
    op.create_index(
        op.f("ix_investigation_topology_proposal_evidence_proposal_id"),
        "investigation_topology_proposal_evidence",
        ["proposal_id"],
    )
    op.create_index(
        op.f(
            "ix_investigation_topology_proposal_evidence_investigation_evidence_id"
        ),
        "investigation_topology_proposal_evidence",
        ["investigation_evidence_id"],
    )


def downgrade() -> None:
    op.drop_table("investigation_topology_proposal_evidence")
    op.drop_table("investigation_topology_proposals")
