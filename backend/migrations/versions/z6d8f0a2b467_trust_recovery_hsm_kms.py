"""add external HSM and KMS recovery signing gateways

Revision ID: z6d8f0a2b467
Revises: y5c7e9f1a356
Create Date: 2026-09-29 18:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "z6d8f0a2b467"
down_revision: str | None = "y5c7e9f1a356"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


PROVIDERS = "trust_recovery_signing_providers"
EVENTS = "trust_recovery_signing_events"


def _enable_namespace_rls(table_name: str) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(sa.text(f'ALTER TABLE "{table_name}" ENABLE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            f'CREATE POLICY icheck_namespace_isolation ON "{table_name}" '
            "USING (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true))"
        )
    )


def _disable_namespace_rls(table_name: str) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        sa.text(
            f'DROP POLICY IF EXISTS icheck_namespace_isolation ON "{table_name}"'
        )
    )
    op.execute(sa.text(f'ALTER TABLE "{table_name}" DISABLE ROW LEVEL SECURITY'))


def upgrade() -> None:
    op.create_table(
        PROVIDERS,
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("provider_kind", sa.String(length=32), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("signing_key_ref", sa.String(length=1024), nullable=False),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column(
            "key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "credential_profile_ref",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "tls_mode",
            sa.String(length=16),
            nullable=False,
            server_default="server_auth",
        ),
        sa.Column(
            "tls_ca_certificate_ref",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "tls_client_certificate_ref",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "tls_client_private_key_ref",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "tls_client_private_key_password_ref",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "tls_revision",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column(
            "request_timeout_seconds",
            sa.Integer(),
            nullable=False,
            server_default="10",
        ),
        sa.Column(
            "max_response_bytes",
            sa.Integer(),
            nullable=False,
            server_default="65536",
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("region_id", sa.String(length=36), nullable=False),
        sa.CheckConstraint(
            "provider_kind IN ('hsm_gateway', 'kms_gateway')",
            name="ck_trust_recovery_signing_provider_kind",
        ),
        sa.CheckConstraint(
            "request_timeout_seconds BETWEEN 1 AND 30",
            name="ck_trust_recovery_signing_provider_timeout",
        ),
        sa.CheckConstraint(
            "max_response_bytes BETWEEN 1024 AND 65536",
            name="ck_trust_recovery_signing_provider_response_limit",
        ),
        sa.CheckConstraint(
            "tls_mode IN ('server_auth', 'mutual_tls')",
            name="ck_trust_recovery_signing_provider_tls_mode",
        ),
        sa.CheckConstraint(
            "(tls_mode = 'server_auth' "
            "AND tls_client_certificate_ref IS NULL "
            "AND tls_client_private_key_ref IS NULL "
            "AND tls_client_private_key_password_ref IS NULL) OR "
            "(tls_mode = 'mutual_tls' "
            "AND tls_client_certificate_ref IS NOT NULL "
            "AND tls_client_private_key_ref IS NOT NULL)",
            name="ck_trust_recovery_signing_provider_tls_binding",
        ),
        sa.CheckConstraint(
            "tls_revision > 0",
            name="ck_trust_recovery_signing_provider_tls_revision",
        ),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_trust_recovery_signing_provider_name",
        ),
    )
    for column in (
        "name",
        "provider_kind",
        "trust_key_id",
        "key_fingerprint_sha256",
        "tls_mode",
        "enabled",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_{PROVIDERS}_{column}",
            PROVIDERS,
            [column],
            unique=False,
        )

    op.create_table(
        EVENTS,
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("provider_id", sa.String(length=36), nullable=False),
        sa.Column("document_type", sa.String(length=32), nullable=False),
        sa.Column(
            "signed_format_version",
            sa.String(length=128),
            nullable=False,
        ),
        sa.Column(
            "statement_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "request_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column(
            "key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_snapshot", sa.JSON(), nullable=False),
        sa.Column(
            "response_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("tls_evidence", sa.JSON(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("region_id", sa.String(length=36), nullable=False),
        sa.CheckConstraint(
            "document_type IN ('recovery_policy', 'root_reanchor')",
            name="ck_trust_recovery_signing_event_document_type",
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"],
            [f"{PROVIDERS}.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "request_digest_sha256",
            name="uq_trust_recovery_signing_event_request",
        ),
    )
    for column in (
        "provider_id",
        "document_type",
        "statement_digest_sha256",
        "request_digest_sha256",
        "trust_key_id",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_{EVENTS}_{column}",
            EVENTS,
            [column],
            unique=False,
        )
    op.create_index(
        "ix_trust_recovery_signing_event_time",
        EVENTS,
        ["provider_id", "requested_at"],
        unique=False,
    )

    _enable_namespace_rls(PROVIDERS)
    _enable_namespace_rls(EVENTS)


def downgrade() -> None:
    _disable_namespace_rls(EVENTS)
    _disable_namespace_rls(PROVIDERS)

    op.drop_index(
        "ix_trust_recovery_signing_event_time",
        table_name=EVENTS,
    )
    for column in reversed(
        (
            "provider_id",
            "document_type",
            "statement_digest_sha256",
            "request_digest_sha256",
            "trust_key_id",
            "tenant_id",
            "region_id",
        )
    ):
        op.drop_index(f"ix_{EVENTS}_{column}", table_name=EVENTS)
    op.drop_table(EVENTS)

    for column in reversed(
        (
            "name",
            "provider_kind",
            "trust_key_id",
            "key_fingerprint_sha256",
            "tls_mode",
            "enabled",
            "tenant_id",
            "region_id",
        )
    ):
        op.drop_index(f"ix_{PROVIDERS}_{column}", table_name=PROVIDERS)
    op.drop_table(PROVIDERS)
