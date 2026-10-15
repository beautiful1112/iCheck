"""governed emergency organization trust-root recovery

Revision ID: p6f8b0c2e457
Revises: o5e7a9b1d346
Create Date: 2026-09-30 15:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "p6f8b0c2e457"
down_revision: str | None = "o5e7a9b1d346"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organization_trust_recovery_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("trust_domain_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column(
            "authority_trust_key_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column(
            "authority_key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("trustee_key_ids", sa.JSON(), nullable=False),
        sa.Column(
            "trustee_key_fingerprints_sha256",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column("required_approvals", sa.Integer(), nullable=False),
        sa.Column("delay_hours", sa.Integer(), nullable=False),
        sa.Column("bundle_sequence", sa.Integer(), nullable=False),
        sa.Column(
            "bundle_digest_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "statement_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "authority_signature_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("signed_policy_snapshot", sa.JSON(), nullable=False),
        sa.Column("transparency_sequence", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "superseded_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.CheckConstraint(
            "delay_hours BETWEEN 1 AND 72",
            name="ck_organization_trust_recovery_policy_delay",
        ),
        sa.CheckConstraint(
            "required_approvals BETWEEN 2 AND 8",
            name="ck_organization_trust_recovery_policy_quorum",
        ),
        sa.CheckConstraint(
            "version > 0",
            name="ck_organization_trust_recovery_policy_version_positive",
        ),
        sa.ForeignKeyConstraint(
            ["authority_trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["trust_domain_id"],
            ["organization_trust_domains.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "statement_digest_sha256",
            name="uq_organization_trust_recovery_policy_statement",
        ),
        sa.UniqueConstraint(
            "trust_domain_id",
            "version",
            name="uq_organization_trust_recovery_policy_version",
        ),
    )
    for name, columns in (
        (
            "ix_organization_trust_recovery_policies_active",
            ["active"],
        ),
        (
            "ix_organization_trust_recovery_policies_authority_trust_key_id",
            ["authority_trust_key_id"],
        ),
        (
            "ix_organization_trust_recovery_policies_statement_digest_sha256",
            ["statement_digest_sha256"],
        ),
        (
            "ix_organization_trust_recovery_policies_trust_domain_id",
            ["trust_domain_id"],
        ),
        (
            "ix_organization_trust_recovery_policy_active",
            ["trust_domain_id", "active"],
        ),
    ):
        op.create_index(
            name,
            "organization_trust_recovery_policies",
            columns,
            unique=False,
        )

    op.create_table(
        "organization_trust_root_reanchors",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("trust_domain_id", sa.String(length=36), nullable=False),
        sa.Column("recovery_policy_id", sa.String(length=36), nullable=False),
        sa.Column("from_trust_key_id", sa.String(length=36), nullable=False),
        sa.Column("to_trust_key_id", sa.String(length=36), nullable=False),
        sa.Column("ceremony_id", sa.String(length=36), nullable=False),
        sa.Column(
            "from_key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "to_key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("bundle_sequence", sa.Integer(), nullable=False),
        sa.Column(
            "bundle_digest_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "witness_checkpoint_offer_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column("witness_log_id", sa.String(length=36), nullable=False),
        sa.Column("witness_epoch", sa.Integer(), nullable=False),
        sa.Column("witness_sequence", sa.Integer(), nullable=False),
        sa.Column(
            "witness_head_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "statement_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "next_signature_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("trustee_approval_count", sa.Integer(), nullable=False),
        sa.Column("trustee_signature_evidence", sa.JSON(), nullable=False),
        sa.Column("signed_reanchor_snapshot", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "execute_after",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "proposal_transparency_sequence",
            sa.Integer(),
            nullable=True,
        ),
        sa.Column(
            "execution_checkpoint_offer_id",
            sa.String(length=36),
            nullable=True,
        ),
        sa.Column(
            "execution_transparency_sequence",
            sa.Integer(),
            nullable=True,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("proposed_by", sa.String(length=255), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_reason", sa.Text(), nullable=True),
        sa.Column("executed_by", sa.String(length=255), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_by", sa.String(length=255), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'executed', 'cancelled')",
            name="ck_organization_trust_root_reanchor_status",
        ),
        sa.CheckConstraint(
            "trustee_approval_count BETWEEN 2 AND 8",
            name="ck_organization_trust_root_reanchor_approvals",
        ),
        sa.ForeignKeyConstraint(
            ["execution_checkpoint_offer_id"],
            ["capability_transparency_checkpoint_offers.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["from_trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["recovery_policy_id"],
            ["organization_trust_recovery_policies.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["to_trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["trust_domain_id"],
            ["organization_trust_domains.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["witness_checkpoint_offer_id"],
            ["capability_transparency_checkpoint_offers.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "statement_digest_sha256",
            name="uq_organization_trust_root_reanchor_statement",
        ),
        sa.UniqueConstraint(
            "trust_domain_id",
            "ceremony_id",
            name="uq_organization_trust_root_reanchor_ceremony",
        ),
    )
    for name, columns in (
        (
            "ix_organization_trust_root_reanchors_ceremony_id",
            ["ceremony_id"],
        ),
        (
            "ix_organization_trust_root_reanchors_from_trust_key_id",
            ["from_trust_key_id"],
        ),
        (
            "ix_organization_trust_root_reanchors_recovery_policy_id",
            ["recovery_policy_id"],
        ),
        (
            "ix_organization_trust_root_reanchors_statement_digest_sha256",
            ["statement_digest_sha256"],
        ),
        (
            "ix_organization_trust_root_reanchors_status",
            ["status"],
        ),
        (
            "ix_organization_trust_root_reanchors_to_trust_key_id",
            ["to_trust_key_id"],
        ),
        (
            "ix_organization_trust_root_reanchors_trust_domain_id",
            ["trust_domain_id"],
        ),
        (
            "ix_organization_trust_root_reanchors_witness_checkpoint_offer_id",
            ["witness_checkpoint_offer_id"],
        ),
        (
            "ix_organization_trust_root_reanchor_status_time",
            ["status", "proposed_at"],
        ),
    ):
        op.create_index(
            op.f(name),
            "organization_trust_root_reanchors",
            columns,
            unique=False,
        )


def downgrade() -> None:
    op.drop_table("organization_trust_root_reanchors")
    op.drop_table("organization_trust_recovery_policies")
