"""add MCP OAuth authorization-code lifecycle

Revision ID: l8k0e2g4b6c9
Revises: k7j9d1f3a5b8
Create Date: 2026-09-30 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "l8k0e2g4b6c9"
down_revision: str | None = "k7j9d1f3a5b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.add_column(
            sa.Column("auth_mode", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("oauth_client_id", sa.String(length=2048), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "oauth_client_secret_profile_ref",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "oauth_authorization_server",
                sa.String(length=2048),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "oauth_requested_scopes",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'"),
            )
        )
        batch_op.add_column(
            sa.Column("oauth_status", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("oauth_issuer", sa.String(length=2048), nullable=True)
        )
        batch_op.add_column(
            sa.Column("oauth_resource", sa.String(length=2048), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "oauth_granted_scopes",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'"),
            )
        )
        batch_op.add_column(
            sa.Column("oauth_metadata_sha256", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "oauth_access_token_sha256",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "oauth_refresh_token_present",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(
            sa.Column(
                "oauth_token_expires_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column("oauth_connected_by", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "oauth_connected_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column("oauth_revoked_by", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "oauth_revoked_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )

    op.execute(
        "UPDATE mcp_servers SET auth_mode = CASE "
        "WHEN credential_profile_ref IS NULL THEN 'none' "
        "ELSE 'credential_profile' END, oauth_status = 'not_configured'"
    )
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.alter_column("auth_mode", nullable=False, server_default="none")
        batch_op.alter_column(
            "oauth_status",
            nullable=False,
            server_default="not_configured",
        )
        batch_op.create_check_constraint(
            "ck_mcp_server_auth_mode",
            "auth_mode IN ('none', 'credential_profile', 'oauth_authorization_code')",
        )
        batch_op.create_check_constraint(
            "ck_mcp_server_oauth_status",
            "oauth_status IN ('not_configured', 'disconnected', 'connected', "
            "'expired', 'revoked', 'revocation_pending')",
        )
        batch_op.create_index("ix_mcp_servers_auth_mode", ["auth_mode"])
        batch_op.create_index("ix_mcp_servers_oauth_status", ["oauth_status"])
        batch_op.create_index(
            "ix_mcp_servers_oauth_token_expires_at",
            ["oauth_token_expires_at"],
        )

    op.create_table(
        "mcp_oauth_transactions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_id", sa.String(length=36), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("browser_token_hash", sa.String(length=64), nullable=False),
        sa.Column("code_verifier_ciphertext", sa.Text(), nullable=False),
        sa.Column("issuer", sa.String(length=2048), nullable=False),
        sa.Column("resource", sa.String(length=2048), nullable=False),
        sa.Column("metadata_sha256", sa.String(length=64), nullable=False),
        sa.Column("requested_scopes", sa.JSON(), nullable=False),
        sa.Column("return_to", sa.String(length=2048), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.ForeignKeyConstraint(["server_id"], ["mcp_servers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("browser_token_hash"),
        sa.UniqueConstraint("state_hash"),
    )
    for column in (
        "server_id",
        "state_hash",
        "browser_token_hash",
        "expires_at",
        "consumed_at",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_mcp_oauth_transactions_{column}",
            "mcp_oauth_transactions",
            [column],
        )


def downgrade() -> None:
    op.drop_table("mcp_oauth_transactions")
    with op.batch_alter_table("mcp_servers") as batch_op:
        batch_op.drop_index("ix_mcp_servers_oauth_token_expires_at")
        batch_op.drop_index("ix_mcp_servers_oauth_status")
        batch_op.drop_index("ix_mcp_servers_auth_mode")
        batch_op.drop_constraint("ck_mcp_server_oauth_status", type_="check")
        batch_op.drop_constraint("ck_mcp_server_auth_mode", type_="check")
        for column in (
            "oauth_revoked_at",
            "oauth_revoked_by",
            "oauth_connected_at",
            "oauth_connected_by",
            "oauth_token_expires_at",
            "oauth_refresh_token_present",
            "oauth_access_token_sha256",
            "oauth_metadata_sha256",
            "oauth_granted_scopes",
            "oauth_resource",
            "oauth_issuer",
            "oauth_status",
            "oauth_requested_scopes",
            "oauth_authorization_server",
            "oauth_client_secret_profile_ref",
            "oauth_client_id",
            "auth_mode",
        ):
            batch_op.drop_column(column)
