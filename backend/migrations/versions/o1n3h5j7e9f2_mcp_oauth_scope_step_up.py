"""add governed MCP OAuth scope step-up ledger

Revision ID: o1n3h5j7e9f2
Revises: n0m2g4i6d8e1
Create Date: 2026-09-30 18:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "o1n3h5j7e9f2"
down_revision: str | None = "n0m2g4i6d8e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mcp_oauth_scope_challenges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_id", sa.String(length=36), nullable=False),
        sa.Column("activation_id", sa.String(length=36), nullable=True),
        sa.Column("investigation_id", sa.String(length=36), nullable=True),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("challenged_scopes", sa.JSON(), nullable=False),
        sa.Column("requested_scopes", sa.JSON(), nullable=False),
        sa.Column("resource_metadata_url", sa.String(length=2048), nullable=True),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "occurrence_count",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column(
            "revision",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("approval_reason", sa.Text(), nullable=True),
        sa.Column(
            "allowlist_expanded",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=255), nullable=True),
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
            "status IN ('pending', 'authorizing', 'resolved')",
            name="ck_mcp_oauth_scope_challenge_status",
        ),
        sa.CheckConstraint(
            "occurrence_count > 0 AND revision > 0",
            name="ck_mcp_oauth_scope_challenge_counters",
        ),
        sa.ForeignKeyConstraint(
            ["activation_id"],
            ["mcp_tool_activations.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["mcp_servers.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "server_id",
        "activation_id",
        "investigation_id",
        "tool_name",
        "status",
        "last_seen_at",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_mcp_oauth_scope_challenges_{column}",
            "mcp_oauth_scope_challenges",
            [column],
        )
    op.create_index(
        "uq_mcp_oauth_scope_challenge_active_tool",
        "mcp_oauth_scope_challenges",
        ["tenant_id", "region_id", "server_id", "tool_name"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'authorizing')"),
        sqlite_where=sa.text("status IN ('pending', 'authorizing')"),
    )
    with op.batch_alter_table("mcp_oauth_transactions") as batch_op:
        batch_op.add_column(
            sa.Column(
                "resource_metadata_url",
                sa.String(length=2048),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column("scope_challenge_id", sa.String(length=36), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_mcp_oauth_transaction_scope_challenge",
            "mcp_oauth_scope_challenges",
            ["scope_challenge_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_mcp_oauth_transactions_scope_challenge_id",
            ["scope_challenge_id"],
        )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            sa.text(
                'ALTER TABLE "mcp_oauth_scope_challenges" '
                "ENABLE ROW LEVEL SECURITY"
            )
        )
        op.execute(
            sa.text(
                'CREATE POLICY icheck_namespace_isolation ON '
                '"mcp_oauth_scope_challenges" '
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
                '"mcp_oauth_scope_challenges"'
            )
        )
        op.execute(
            sa.text(
                'ALTER TABLE "mcp_oauth_scope_challenges" '
                "DISABLE ROW LEVEL SECURITY"
            )
        )
    with op.batch_alter_table("mcp_oauth_transactions") as batch_op:
        batch_op.drop_index("ix_mcp_oauth_transactions_scope_challenge_id")
        batch_op.drop_constraint(
            "fk_mcp_oauth_transaction_scope_challenge",
            type_="foreignkey",
        )
        batch_op.drop_column("scope_challenge_id")
        batch_op.drop_column("resource_metadata_url")
    op.drop_index(
        "uq_mcp_oauth_scope_challenge_active_tool",
        table_name="mcp_oauth_scope_challenges",
    )
    op.drop_table("mcp_oauth_scope_challenges")
