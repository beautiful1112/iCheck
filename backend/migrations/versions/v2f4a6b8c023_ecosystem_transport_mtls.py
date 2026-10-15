"""ecosystem transport mTLS workload identity

Revision ID: v2f4a6b8c023
Revises: u1e3f5a7b912
Create Date: 2026-10-05 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "v2f4a6b8c023"
down_revision: str | None = "u1e3f5a7b912"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


TABLE = "ecosystem_transport_endpoints"


def upgrade() -> None:
    with op.batch_alter_table(TABLE) as batch:
        batch.add_column(
            sa.Column(
                "tls_mode",
                sa.String(length=16),
                nullable=False,
                server_default="server_auth",
            )
        )
        batch.add_column(
            sa.Column(
                "tls_ca_certificate_ref",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "tls_client_certificate_ref",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "tls_client_private_key_ref",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "tls_client_private_key_password_ref",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "tls_revision",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )
        batch.create_check_constraint(
            "ck_ecosystem_transport_endpoint_tls_mode",
            "tls_mode IN ('server_auth', 'mutual_tls')",
        )
        batch.create_check_constraint(
            "ck_ecosystem_transport_endpoint_tls_binding",
            "(tls_mode = 'server_auth' "
            "AND tls_client_certificate_ref IS NULL "
            "AND tls_client_private_key_ref IS NULL "
            "AND tls_client_private_key_password_ref IS NULL) OR "
            "(tls_mode = 'mutual_tls' "
            "AND tls_client_certificate_ref IS NOT NULL "
            "AND tls_client_private_key_ref IS NOT NULL)",
        )
        batch.create_check_constraint(
            "ck_ecosystem_transport_endpoint_tls_revision",
            "tls_revision > 0",
        )
        batch.create_index(
            "ix_ecosystem_transport_endpoints_tls_mode",
            ["tls_mode"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_index("ix_ecosystem_transport_endpoints_tls_mode")
        batch.drop_constraint(
            "ck_ecosystem_transport_endpoint_tls_revision",
            type_="check",
        )
        batch.drop_constraint(
            "ck_ecosystem_transport_endpoint_tls_binding",
            type_="check",
        )
        batch.drop_constraint(
            "ck_ecosystem_transport_endpoint_tls_mode",
            type_="check",
        )
        batch.drop_column("tls_revision")
        batch.drop_column("tls_client_private_key_password_ref")
        batch.drop_column("tls_client_private_key_ref")
        batch.drop_column("tls_client_certificate_ref")
        batch.drop_column("tls_ca_certificate_ref")
        batch.drop_column("tls_mode")
