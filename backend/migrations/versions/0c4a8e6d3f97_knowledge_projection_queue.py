"""knowledge projection workers and durable envelope queue

Revision ID: 0c4a8e6d3f97
Revises: g2d9f7b4c685
Create Date: 2026-09-25 03:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0c4a8e6d3f97"
down_revision: str | None = "g2d9f7b4c685"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "knowledge_projection_workers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(
        "ix_knowledge_projection_workers_name",
        "knowledge_projection_workers",
        ["name"],
    )
    op.create_index(
        "ix_knowledge_projection_workers_state",
        "knowledge_projection_workers",
        ["state"],
    )
    op.create_index(
        "ix_knowledge_projection_workers_last_heartbeat_at",
        "knowledge_projection_workers",
        ["last_heartbeat_at"],
    )

    op.create_table(
        "knowledge_projections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("envelope_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_worker_id", sa.String(length=36), nullable=True),
        sa.Column("lease_token_hash", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_summary", sa.JSON(), nullable=False),
        sa.Column("error_type", sa.String(length=255), nullable=True),
        sa.Column("error_sha256", sa.String(length=64), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts > 0",
            name="ck_knowledge_projection_attempts",
        ),
        sa.ForeignKeyConstraint(
            ["envelope_id"],
            ["collection_envelopes.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lease_worker_id"],
            ["knowledge_projection_workers.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("envelope_id"),
    )
    op.create_index(
        "ix_knowledge_projections_envelope_id",
        "knowledge_projections",
        ["envelope_id"],
        unique=True,
    )
    op.create_index(
        "ix_knowledge_projections_status",
        "knowledge_projections",
        ["status"],
    )
    op.create_index(
        "ix_knowledge_projections_next_attempt_at",
        "knowledge_projections",
        ["next_attempt_at"],
    )
    op.create_index(
        "ix_knowledge_projections_lease_worker_id",
        "knowledge_projections",
        ["lease_worker_id"],
    )
    op.create_index(
        "ix_knowledge_projections_lease_expires_at",
        "knowledge_projections",
        ["lease_expires_at"],
    )
    op.create_index(
        "ix_knowledge_projections_created_at",
        "knowledge_projections",
        ["created_at"],
    )
    op.create_index(
        "ix_knowledge_projection_queue",
        "knowledge_projections",
        ["status", "next_attempt_at", "lease_expires_at"],
    )

    bind = op.get_bind()
    envelopes = sa.table(
        "collection_envelopes",
        sa.column("id", sa.String(length=36)),
        sa.column("received_at", sa.DateTime(timezone=True)),
    )
    projections = sa.table(
        "knowledge_projections",
        sa.column("id", sa.String(length=36)),
        sa.column("envelope_id", sa.String(length=36)),
        sa.column("status", sa.String(length=16)),
        sa.column("attempt_count", sa.Integer()),
        sa.column("max_attempts", sa.Integer()),
        sa.column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.column("result_summary", sa.JSON()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    rows = bind.execute(sa.select(envelopes.c.id, envelopes.c.received_at))
    for partition in rows.partitions(1000):
        bind.execute(
            projections.insert(),
            [
                {
                    "id": row.id,
                    "envelope_id": row.id,
                    "status": "pending",
                    "attempt_count": 0,
                    "max_attempts": 5,
                    "next_attempt_at": row.received_at,
                    "result_summary": {},
                    "created_at": row.received_at,
                    "updated_at": row.received_at,
                }
                for row in partition
            ],
        )


def downgrade() -> None:
    op.drop_index(
        "ix_knowledge_projection_queue",
        table_name="knowledge_projections",
    )
    op.drop_index(
        "ix_knowledge_projections_created_at",
        table_name="knowledge_projections",
    )
    op.drop_index(
        "ix_knowledge_projections_lease_expires_at",
        table_name="knowledge_projections",
    )
    op.drop_index(
        "ix_knowledge_projections_lease_worker_id",
        table_name="knowledge_projections",
    )
    op.drop_index(
        "ix_knowledge_projections_next_attempt_at",
        table_name="knowledge_projections",
    )
    op.drop_index(
        "ix_knowledge_projections_status",
        table_name="knowledge_projections",
    )
    op.drop_index(
        "ix_knowledge_projections_envelope_id",
        table_name="knowledge_projections",
    )
    op.drop_table("knowledge_projections")
    op.drop_index(
        "ix_knowledge_projection_workers_last_heartbeat_at",
        table_name="knowledge_projection_workers",
    )
    op.drop_index(
        "ix_knowledge_projection_workers_state",
        table_name="knowledge_projection_workers",
    )
    op.drop_index(
        "ix_knowledge_projection_workers_name",
        table_name="knowledge_projection_workers",
    )
    op.drop_table("knowledge_projection_workers")
