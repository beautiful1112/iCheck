"""add authenticated MCP Worker attestation queue

Revision ID: m9l1f3h5c7d0
Revises: l8k0e2g4b6c9
Create Date: 2026-09-30 14:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "m9l1f3h5c7d0"
down_revision: str | None = "l8k0e2g4b6c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mcp_tool_attestations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column(
            "status",
            sa.String(length=24),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("mcp_tool_name", sa.String(length=255), nullable=False),
        sa.Column(
            "expected_server_config_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "expected_artifact_content_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "expected_contract_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "expected_input_schema_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "expected_output_schema_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("credential_profile_id", sa.String(length=36), nullable=True),
        sa.Column("credential_profile_revision", sa.Integer(), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("request_reason", sa.Text(), nullable=False),
        sa.Column("worker_id", sa.String(length=36), nullable=True),
        sa.Column("lease_token_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "lease_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "attempt_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "max_attempts",
            sa.Integer(),
            nullable=False,
            server_default="3",
        ),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("advertised_tool_count", sa.Integer(), nullable=True),
        sa.Column("catalog_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "remote_contract_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_sha256", sa.String(length=64), nullable=True),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "consumed_by_activation_id",
            sa.String(length=36),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            nullable=False,
            server_default="00000000-0000-0000-0000-000000000001",
        ),
        sa.Column(
            "region_id",
            sa.String(length=36),
            nullable=False,
            server_default="00000000-0000-0000-0000-000000000002",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'passed', 'failed', "
            "'dead_letter', 'consumed')",
            name="ck_mcp_tool_attestation_status",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts > 0",
            name="ck_mcp_tool_attestation_attempts",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["consumed_by_activation_id"],
            ["mcp_tool_activations.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["credential_profile_id"],
            ["credential_profiles.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["mcp_servers.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["agent_workers.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "server_id",
        "artifact_version_id",
        "status",
        "tool_name",
        "credential_profile_id",
        "worker_id",
        "lease_expires_at",
        "next_attempt_at",
        "attested_at",
        "expires_at",
        "created_at",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_mcp_tool_attestations_{column}",
            "mcp_tool_attestations",
            [column],
        )
    op.create_index(
        "ix_mcp_tool_attestation_queue",
        "mcp_tool_attestations",
        ["status", "next_attempt_at", "lease_expires_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            sa.text(
                'ALTER TABLE "mcp_tool_attestations" ENABLE ROW LEVEL SECURITY'
            )
        )
        op.execute(
            sa.text(
                'CREATE POLICY icheck_namespace_isolation ON '
                '"mcp_tool_attestations" '
                "USING (tenant_id = current_setting('icheck.tenant_id', true) "
                "AND region_id = current_setting('icheck.region_id', true)) "
                "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
                "AND region_id = current_setting('icheck.region_id', true))"
            )
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            sa.text(
                'DROP POLICY IF EXISTS icheck_namespace_isolation ON '
                '"mcp_tool_attestations"'
            )
        )
        op.execute(
            sa.text(
                'ALTER TABLE "mcp_tool_attestations" DISABLE ROW LEVEL SECURITY'
            )
        )
    op.drop_table("mcp_tool_attestations")
