"""automated signed ecosystem transport

Revision ID: q7a9c1d3f568
Revises: p6f8b0c2e457
Create Date: 2026-09-30 19:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "q7a9c1d3f568"
down_revision: str | None = "p6f8b0c2e457"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ecosystem_transport_endpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column(
            "credential_profile_ref",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column("witness_id", sa.String(length=36), nullable=True),
        sa.Column(
            "target_environment_id",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column("target_stage", sa.String(length=32), nullable=True),
        sa.Column("auto_dispatch", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "request_timeout_seconds",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column("max_response_bytes", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(kind = 'transparency_witness' AND witness_id IS NOT NULL "
            "AND target_environment_id IS NULL AND target_stage IS NULL) OR "
            "(kind = 'promotion_target' AND witness_id IS NULL "
            "AND target_environment_id IS NOT NULL AND target_stage IS NOT NULL)",
            name="ck_ecosystem_transport_endpoint_binding",
        ),
        sa.CheckConstraint(
            "kind IN ('transparency_witness', 'promotion_target')",
            name="ck_ecosystem_transport_endpoint_kind",
        ),
        sa.CheckConstraint(
            "kind != 'promotion_target' OR auto_dispatch = false",
            name="ck_ecosystem_transport_endpoint_promotion_explicit",
        ),
        sa.CheckConstraint(
            "max_response_bytes BETWEEN 1024 AND 5000000",
            name="ck_ecosystem_transport_endpoint_response_limit",
        ),
        sa.CheckConstraint(
            "target_stage IS NULL OR target_stage IN "
            "('development', 'test', 'staging', 'production')",
            name="ck_ecosystem_transport_endpoint_stage",
        ),
        sa.CheckConstraint(
            "request_timeout_seconds BETWEEN 1 AND 30",
            name="ck_ecosystem_transport_endpoint_timeout",
        ),
        sa.ForeignKeyConstraint(
            ["witness_id"],
            ["capability_transparency_witnesses.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "name",
            name="uq_ecosystem_transport_endpoint_name",
        ),
    )
    for name, columns in (
        ("ix_ecosystem_transport_endpoints_auto_dispatch", ["auto_dispatch"]),
        ("ix_ecosystem_transport_endpoints_enabled", ["enabled"]),
        ("ix_ecosystem_transport_endpoints_kind", ["kind"]),
        (
            "ix_ecosystem_transport_endpoints_target_environment_id",
            ["target_environment_id"],
        ),
        ("ix_ecosystem_transport_endpoints_witness_id", ["witness_id"]),
    ):
        op.create_index(
            name,
            "ecosystem_transport_endpoints",
            columns,
            unique=False,
        )

    op.create_table(
        "ecosystem_transport_workers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column(
            "last_heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "name",
            name="uq_ecosystem_transport_worker_name",
        ),
    )
    op.create_index(
        "ix_ecosystem_transport_workers_last_heartbeat_at",
        "ecosystem_transport_workers",
        ["last_heartbeat_at"],
        unique=False,
    )
    op.create_index(
        "ix_ecosystem_transport_workers_name",
        "ecosystem_transport_workers",
        ["name"],
        unique=False,
    )
    op.create_index(
        "ix_ecosystem_transport_workers_state",
        "ecosystem_transport_workers",
        ["state"],
        unique=False,
    )

    op.create_table(
        "ecosystem_transport_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("endpoint_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column(
            "checkpoint_offer_id",
            sa.String(length=36),
            nullable=True,
        ),
        sa.Column("dedupe_key", sa.String(length=128), nullable=False),
        sa.Column("payload_snapshot", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("lease_worker_id", sa.String(length=36), nullable=True),
        sa.Column("lease_token_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "lease_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "response_digest_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("result_summary", sa.JSON(), nullable=False),
        sa.Column("error_type", sa.String(length=255), nullable=True),
        sa.Column("error_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 20",
            name="ck_ecosystem_transport_job_attempts",
        ),
        sa.CheckConstraint(
            "kind IN ('witness_checkpoint', 'promotion_delivery')",
            name="ck_ecosystem_transport_job_kind",
        ),
        sa.CheckConstraint(
            "(kind = 'witness_checkpoint' AND checkpoint_offer_id IS NOT NULL) "
            "OR (kind = 'promotion_delivery' AND checkpoint_offer_id IS NULL)",
            name="ck_ecosystem_transport_job_binding",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'retry', 'succeeded', "
            "'dead_letter', 'cancelled')",
            name="ck_ecosystem_transport_job_status",
        ),
        sa.ForeignKeyConstraint(
            ["checkpoint_offer_id"],
            ["capability_transparency_checkpoint_offers.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["endpoint_id"],
            ["ecosystem_transport_endpoints.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["lease_worker_id"],
            ["ecosystem_transport_workers.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "dedupe_key",
            name="uq_ecosystem_transport_job_dedupe",
        ),
    )
    for name, columns in (
        (
            "ix_ecosystem_transport_job_queue",
            ["status", "next_attempt_at", "lease_expires_at"],
        ),
        (
            "ix_ecosystem_transport_jobs_checkpoint_offer_id",
            ["checkpoint_offer_id"],
        ),
        ("ix_ecosystem_transport_jobs_created_at", ["created_at"]),
        ("ix_ecosystem_transport_jobs_dedupe_key", ["dedupe_key"]),
        ("ix_ecosystem_transport_jobs_endpoint_id", ["endpoint_id"]),
        (
            "ix_ecosystem_transport_jobs_lease_expires_at",
            ["lease_expires_at"],
        ),
        ("ix_ecosystem_transport_jobs_lease_worker_id", ["lease_worker_id"]),
        ("ix_ecosystem_transport_jobs_next_attempt_at", ["next_attempt_at"]),
        ("ix_ecosystem_transport_jobs_kind", ["kind"]),
        ("ix_ecosystem_transport_jobs_status", ["status"]),
    ):
        op.create_index(
            name,
            "ecosystem_transport_jobs",
            columns,
            unique=False,
        )


def downgrade() -> None:
    op.drop_table("ecosystem_transport_jobs")
    op.drop_table("ecosystem_transport_workers")
    op.drop_table("ecosystem_transport_endpoints")
