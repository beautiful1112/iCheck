"""bind collector and agent workers to verified mTLS identities

Revision ID: e1c3d5f7a9b2
Revises: d0b2c4e6f8a1
Create Date: 2026-09-30 03:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e1c3d5f7a9b2"
down_revision: str | None = "d0b2c4e6f8a1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


TABLES = ("collector_workers", "agent_workers")


def upgrade() -> None:
    for table in TABLES:
        prefix = table.removesuffix("s")
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("mtls_fingerprint_sha256", sa.String(64)))
            batch.add_column(sa.Column("mtls_subject_sha256", sa.String(64)))
            batch.add_column(sa.Column("mtls_serial_sha256", sa.String(64)))
            batch.add_column(sa.Column("mtls_not_after", sa.DateTime(timezone=True)))
            batch.add_column(sa.Column("mtls_activated_at", sa.DateTime(timezone=True)))
            batch.add_column(
                sa.Column("mtls_next_fingerprint_sha256", sa.String(64))
            )
            batch.add_column(sa.Column("mtls_next_subject_sha256", sa.String(64)))
            batch.add_column(sa.Column("mtls_next_serial_sha256", sa.String(64)))
            batch.add_column(
                sa.Column("mtls_next_not_before", sa.DateTime(timezone=True))
            )
            batch.add_column(
                sa.Column("mtls_next_not_after", sa.DateTime(timezone=True))
            )
            batch.add_column(
                sa.Column(
                    "mtls_revision",
                    sa.Integer(),
                    nullable=False,
                    server_default="0",
                )
            )
            batch.create_check_constraint(
                f"ck_{prefix}_mtls_revision",
                "mtls_revision >= 0",
            )
            batch.create_unique_constraint(
                f"uq_{prefix}_namespace_mtls_fingerprint",
                ["tenant_id", "region_id", "mtls_fingerprint_sha256"],
            )
            batch.create_unique_constraint(
                f"uq_{prefix}_namespace_mtls_next_fingerprint",
                ["tenant_id", "region_id", "mtls_next_fingerprint_sha256"],
            )
            batch.create_index(
                f"ix_{table}_mtls_fingerprint_sha256",
                ["mtls_fingerprint_sha256"],
            )
            batch.create_index(
                f"ix_{table}_mtls_next_fingerprint_sha256",
                ["mtls_next_fingerprint_sha256"],
            )


def downgrade() -> None:
    for table in reversed(TABLES):
        prefix = table.removesuffix("s")
        with op.batch_alter_table(table) as batch:
            batch.drop_index(f"ix_{table}_mtls_next_fingerprint_sha256")
            batch.drop_index(f"ix_{table}_mtls_fingerprint_sha256")
            batch.drop_constraint(
                f"uq_{prefix}_namespace_mtls_next_fingerprint",
                type_="unique",
            )
            batch.drop_constraint(
                f"uq_{prefix}_namespace_mtls_fingerprint",
                type_="unique",
            )
            batch.drop_constraint(f"ck_{prefix}_mtls_revision", type_="check")
            batch.drop_column("mtls_revision")
            batch.drop_column("mtls_next_not_after")
            batch.drop_column("mtls_next_not_before")
            batch.drop_column("mtls_next_serial_sha256")
            batch.drop_column("mtls_next_subject_sha256")
            batch.drop_column("mtls_next_fingerprint_sha256")
            batch.drop_column("mtls_activated_at")
            batch.drop_column("mtls_not_after")
            batch.drop_column("mtls_serial_sha256")
            batch.drop_column("mtls_subject_sha256")
            batch.drop_column("mtls_fingerprint_sha256")
