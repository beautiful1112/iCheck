"""govern promotion receipts into atomic artifact publication

Revision ID: y5c7e9f1a356
Revises: x4b6d8e0f245
Create Date: 2026-09-29 16:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "y5c7e9f1a356"
down_revision: str | None = "x4b6d8e0f245"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


POLICY = "capability_promotion_policy"
PUBLICATIONS = "capability_promotion_publications"


def upgrade() -> None:
    with op.batch_alter_table(POLICY) as batch:
        batch.add_column(
            sa.Column(
                "publication_mode",
                sa.String(length=32),
                nullable=False,
                server_default="disabled",
            )
        )
        batch.add_column(
            sa.Column(
                "require_distinct_publisher",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            )
        )
        batch.create_check_constraint(
            "ck_capability_promotion_publication_mode",
            "publication_mode IN ('disabled', 'manual')",
        )

    op.create_table(
        PUBLICATIONS,
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("receipt_id", sa.String(length=36), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column(
            "publication_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("artifact_count", sa.Integer(), nullable=False),
        sa.Column("newly_published_count", sa.Integer(), nullable=False),
        sa.Column("artifact_version_ids", sa.JSON(), nullable=False),
        sa.Column("newly_published_version_ids", sa.JSON(), nullable=False),
        sa.Column(
            "already_published_version_ids",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column("reused_version_ids", sa.JSON(), nullable=False),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("published_by", sa.String(length=255), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("region_id", sa.String(length=36), nullable=False),
        sa.CheckConstraint(
            "artifact_count > 0",
            name="ck_capability_promotion_publication_artifact_count",
        ),
        sa.CheckConstraint(
            "newly_published_count >= 0",
            name="ck_capability_promotion_publication_new_count",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["capability_pack_installations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["receipt_id"],
            ["capability_promotion_receipts.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "publication_digest_sha256",
            name="uq_capability_promotion_publication_digest",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "receipt_id",
            name="uq_capability_promotion_publication_receipt",
        ),
    )
    op.create_index(
        "ix_capability_promotion_publications_installation_id",
        PUBLICATIONS,
        ["installation_id"],
        unique=False,
    )
    op.create_index(
        "ix_capability_promotion_publication_time",
        PUBLICATIONS,
        ["published_at"],
        unique=False,
    )
    for column in ("tenant_id", "region_id"):
        op.create_index(
            f"ix_{PUBLICATIONS}_{column}",
            PUBLICATIONS,
            [column],
            unique=False,
        )

    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            sa.text(f'ALTER TABLE "{PUBLICATIONS}" ENABLE ROW LEVEL SECURITY')
        )
        op.execute(
            sa.text(
                f'CREATE POLICY icheck_namespace_isolation ON "{PUBLICATIONS}" '
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
                f'DROP POLICY IF EXISTS icheck_namespace_isolation ON "{PUBLICATIONS}"'
            )
        )
        op.execute(
            sa.text(f'ALTER TABLE "{PUBLICATIONS}" DISABLE ROW LEVEL SECURITY')
        )

    for column in ("region_id", "tenant_id"):
        op.drop_index(
            f"ix_{PUBLICATIONS}_{column}",
            table_name=PUBLICATIONS,
        )
    op.drop_index(
        "ix_capability_promotion_publication_time",
        table_name=PUBLICATIONS,
    )
    op.drop_index(
        "ix_capability_promotion_publications_installation_id",
        table_name=PUBLICATIONS,
    )
    op.drop_table(PUBLICATIONS)

    with op.batch_alter_table(POLICY) as batch:
        batch.drop_constraint(
            "ck_capability_promotion_publication_mode",
            type_="check",
        )
        batch.drop_column("require_distinct_publisher")
        batch.drop_column("publication_mode")
