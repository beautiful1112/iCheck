"""add browser session provenance and administration metadata

Revision ID: s5r7l9n1i3j6
Revises: r4q6k8m0h2i5
Create Date: 2026-09-30 23:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "s5r7l9n1i3j6"
down_revision: str | None = "r4q6k8m0h2i5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("control_plane_browser_sessions") as batch_op:
        batch_op.add_column(
            sa.Column(
                "auth_source",
                sa.String(32),
                nullable=False,
                server_default="unknown",
            )
        )
        batch_op.add_column(
            sa.Column(
                "federated_identity_id",
                sa.String(36),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column("revoked_by", sa.String(255), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "revocation_reason_sha256",
                sa.String(64),
                nullable=True,
            )
        )
        batch_op.create_index(
            "ix_control_plane_browser_sessions_auth_source",
            ["auth_source"],
        )
        batch_op.create_index(
            "ix_control_plane_browser_sessions_federated_identity_id",
            ["federated_identity_id"],
        )
        batch_op.create_check_constraint(
            "ck_control_plane_browser_session_source",
            "(auth_source IN ('unknown', 'local_token') "
            "AND federated_identity_id IS NULL) OR "
            "(auth_source IN ('oidc', 'trusted_proxy') "
            "AND federated_identity_id IS NOT NULL)",
        )


def downgrade() -> None:
    with op.batch_alter_table("control_plane_browser_sessions") as batch_op:
        batch_op.drop_constraint(
            "ck_control_plane_browser_session_source",
            type_="check",
        )
        batch_op.drop_index(
            "ix_control_plane_browser_sessions_federated_identity_id"
        )
        batch_op.drop_index(
            "ix_control_plane_browser_sessions_auth_source"
        )
        batch_op.drop_column("revocation_reason_sha256")
        batch_op.drop_column("revoked_by")
        batch_op.drop_column("federated_identity_id")
        batch_op.drop_column("auth_source")
