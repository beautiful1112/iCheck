"""external transparency witnesses and cross-region gossip

Revision ID: n4d6f8a0c235
Revises: m3c5e7a9b124
Create Date: 2026-09-30 08:30:00.000000
"""

from collections.abc import Sequence
from datetime import UTC, datetime
import uuid

from alembic import op
import sqlalchemy as sa


revision: str = "n4d6f8a0c235"
down_revision: str | None = "m3c5e7a9b124"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "capability_transparency_state",
        sa.Column("log_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "capability_transparency_state",
        sa.Column(
            "epoch",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.execute(
        sa.text(
            "UPDATE capability_transparency_state "
            "SET log_id = :log_id WHERE id = 'global'"
        ).bindparams(log_id=str(uuid.uuid4()))
    )
    with op.batch_alter_table("capability_transparency_state") as batch_op:
        batch_op.create_unique_constraint(
            "uq_capability_transparency_state_log_id",
            ["log_id"],
        )

    policy = op.create_table(
        "capability_transparency_witness_policy",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("required_quorum", sa.Integer(), nullable=False),
        sa.Column(
            "max_attestation_age_hours",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "max_attestation_age_hours BETWEEN 1 AND 720",
            name="ck_transparency_witness_policy_age",
        ),
        sa.CheckConstraint(
            "required_quorum BETWEEN 1 AND 16",
            name="ck_transparency_witness_policy_quorum",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.bulk_insert(
        policy,
        [
            {
                "id": "global",
                "required_quorum": 2,
                "max_attestation_age_hours": 168,
                "updated_by": "migration",
                "updated_at": datetime.now(UTC),
            }
        ],
    )

    op.create_table(
        "capability_transparency_witnesses",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("witness_id", sa.String(length=255), nullable=False),
        sa.Column("region", sa.String(length=128), nullable=False),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column(
            "key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "witness_id",
            name="uq_capability_transparency_witness_identity",
        ),
        sa.UniqueConstraint(
            "name",
            name="uq_capability_transparency_witness_name",
        ),
    )
    for name, columns in (
        ("ix_capability_transparency_witnesses_enabled", ["enabled"]),
        (
            "ix_capability_transparency_witnesses_key_fingerprint_sha256",
            ["key_fingerprint_sha256"],
        ),
        ("ix_capability_transparency_witnesses_region", ["region"]),
        (
            "ix_capability_transparency_witnesses_trust_key_id",
            ["trust_key_id"],
        ),
        (
            "ix_capability_transparency_witnesses_witness_id",
            ["witness_id"],
        ),
    ):
        op.create_index(
            op.f(name),
            "capability_transparency_witnesses",
            columns,
            unique=False,
        )

    op.create_table(
        "capability_transparency_checkpoint_offers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("log_id", sa.String(length=36), nullable=False),
        sa.Column("epoch", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column(
            "head_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "statement_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("statement_snapshot", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sequence > 0",
            name="ck_transparency_checkpoint_offer_sequence_positive",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "statement_digest_sha256",
            name="uq_transparency_checkpoint_offer_digest",
        ),
    )
    for name, columns in (
        (
            "ix_capability_transparency_checkpoint_offers_head_digest_sha256",
            ["head_digest_sha256"],
        ),
        (
            "ix_capability_transparency_checkpoint_offers_log_id",
            ["log_id"],
        ),
        (
            "ix_capability_transparency_checkpoint_offers_statement_digest_sha256",
            ["statement_digest_sha256"],
        ),
        (
            "ix_transparency_checkpoint_offer_sequence",
            ["log_id", "epoch", "sequence"],
        ),
    ):
        op.create_index(
            op.f(name),
            "capability_transparency_checkpoint_offers",
            columns,
            unique=False,
        )

    op.create_table(
        "capability_transparency_witness_attestations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column(
            "checkpoint_offer_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column("witness_id", sa.String(length=36), nullable=False),
        sa.Column(
            "external_witness_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column(
            "key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("log_id", sa.String(length=36), nullable=False),
        sa.Column("epoch", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column(
            "head_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "checkpoint_statement_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "attestation_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "signature_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("signed_attestation_snapshot", sa.JSON(), nullable=False),
        sa.Column("witnessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_by", sa.String(length=255), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["checkpoint_offer_id"],
            ["capability_transparency_checkpoint_offers.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["witness_id"],
            ["capability_transparency_witnesses.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "attestation_digest_sha256",
            name="uq_transparency_attestation_digest",
        ),
        sa.UniqueConstraint(
            "checkpoint_offer_id",
            "witness_id",
            name="uq_transparency_offer_witness",
        ),
    )
    for name, columns in (
        (
            "ix_capability_transparency_witness_attestations_attestation_digest_sha256",
            ["attestation_digest_sha256"],
        ),
        (
            "ix_capability_transparency_witness_attestations_checkpoint_offer_id",
            ["checkpoint_offer_id"],
        ),
        (
            "ix_capability_transparency_witness_attestations_external_witness_id",
            ["external_witness_id"],
        ),
        (
            "ix_capability_transparency_witness_attestations_key_fingerprint_sha256",
            ["key_fingerprint_sha256"],
        ),
        (
            "ix_capability_transparency_witness_attestations_log_id",
            ["log_id"],
        ),
        (
            "ix_capability_transparency_witness_attestations_trust_key_id",
            ["trust_key_id"],
        ),
        (
            "ix_capability_transparency_witness_attestations_witness_id",
            ["witness_id"],
        ),
        (
            "ix_transparency_witness_attestation_sequence",
            ["witness_id", "log_id", "epoch", "sequence"],
        ),
    ):
        op.create_index(
            op.f(name),
            "capability_transparency_witness_attestations",
            columns,
            unique=False,
        )

    op.create_table(
        "capability_transparency_gossip_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_region", sa.String(length=128), nullable=False),
        sa.Column("log_id", sa.String(length=36), nullable=False),
        sa.Column("epoch", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column(
            "head_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "checkpoint_statement_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "document_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("witness_count", sa.Integer(), nullable=False),
        sa.Column("witness_evidence", sa.JSON(), nullable=False),
        sa.Column("initial_status", sa.String(length=32), nullable=False),
        sa.Column("gossip_snapshot", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("received_by", sa.String(length=255), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "document_digest_sha256",
            name="uq_transparency_gossip_document",
        ),
    )
    for name, columns in (
        (
            "ix_capability_transparency_gossip_observations_document_digest_sha256",
            ["document_digest_sha256"],
        ),
        (
            "ix_capability_transparency_gossip_observations_head_digest_sha256",
            ["head_digest_sha256"],
        ),
        (
            "ix_capability_transparency_gossip_observations_initial_status",
            ["initial_status"],
        ),
        (
            "ix_capability_transparency_gossip_observations_log_id",
            ["log_id"],
        ),
        (
            "ix_capability_transparency_gossip_observations_source_region",
            ["source_region"],
        ),
        (
            "ix_transparency_gossip_checkpoint",
            ["log_id", "epoch", "sequence"],
        ),
        (
            "ix_transparency_gossip_status_time",
            ["initial_status", "received_at"],
        ),
    ):
        op.create_index(
            op.f(name),
            "capability_transparency_gossip_observations",
            columns,
            unique=False,
        )


def downgrade() -> None:
    op.drop_table("capability_transparency_gossip_observations")
    op.drop_table("capability_transparency_witness_attestations")
    op.drop_table("capability_transparency_checkpoint_offers")
    op.drop_table("capability_transparency_witnesses")
    op.drop_table("capability_transparency_witness_policy")
    with op.batch_alter_table("capability_transparency_state") as batch_op:
        batch_op.drop_constraint(
            "uq_capability_transparency_state_log_id",
            type_="unique",
        )
        batch_op.drop_column("epoch")
        batch_op.drop_column("log_id")
