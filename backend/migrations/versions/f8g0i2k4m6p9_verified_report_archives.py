"""Independent Report archive retrieval receipts and verified purge binding.

Revision ID: f8g0i2k4m6p9
Revises: e7f9h1j3l5n8
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "f8g0i2k4m6p9"
down_revision: str | None = "e7f9h1j3l5n8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _namespace():
    return (
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
    )


def upgrade() -> None:
    op.create_table("report_archive_sources",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("origin", sa.String(2048), nullable=False),
        sa.Column("credential_profile_id", sa.String(36), sa.ForeignKey("credential_profiles.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace(),
        sa.UniqueConstraint("tenant_id", "region_id", "name", name="uq_report_archive_source_namespace_name"),
        sa.CheckConstraint("revision > 0", name="ck_report_archive_source_revision"),
    )
    op.create_table("report_archive_verifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("instance_id", sa.String(36), nullable=False),
        sa.Column("acknowledgement_id", sa.String(36), sa.ForeignKey("report_archive_acknowledgements.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("report_archive_sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("artifact_version_id", sa.String(36), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("package_sha256", sa.String(64), nullable=False),
        sa.Column("package_size_bytes", sa.Integer(), nullable=False),
        sa.Column("source_binding_sha256", sa.String(64), nullable=False),
        sa.Column("attachments", sa.JSON(), nullable=False),
        sa.Column("source_revision", sa.Integer(), nullable=False),
        sa.Column("credential_revision", sa.Integer(), nullable=False),
        sa.Column("reason_sha256", sa.String(64), nullable=False),
        sa.Column("verified_by", sa.String(255), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace(),
        sa.CheckConstraint("package_size_bytes > 0 AND package_size_bytes <= 22000000", name="ck_report_archive_package_size"),
        sa.CheckConstraint("source_revision > 0 AND credential_revision >= 0", name="ck_report_archive_verification_revisions"),
    )
    for table, columns in (
        ("report_archive_sources", ("tenant_id", "region_id")),
        ("report_archive_verifications", ("tenant_id", "region_id", "instance_id", "acknowledgement_id", "source_id")),
    ):
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(
                f"CREATE POLICY icheck_namespace_isolation ON {table} "
                "USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) "
                "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"
            ))
    for table in ("report_purge_requests", "report_purge_tombstones"):
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("archive_verification_id", sa.String(36), nullable=True))
            batch.create_foreign_key(f"fk_{table}_archive_verification", "report_archive_verifications", ["archive_verification_id"], ["id"], ondelete="RESTRICT")
    with op.batch_alter_table("report_purge_tombstones") as batch:
        batch.add_column(sa.Column("archive_revalidated_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_check_constraint("ck_report_tombstone_archive_revalidation",
            "(archive_verification_id IS NULL AND archive_revalidated_at IS NULL) OR "
            "(archive_verification_id IS NOT NULL AND archive_revalidated_at IS NOT NULL)")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("report_archive_sources", "report_archive_verifications", "report_purge_requests", "report_purge_tombstones"):
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Report archive downgrade requires a migration role that can inspect all namespaces")
    for table in ("report_archive_sources", "report_archive_verifications"):
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() is not None:
            raise RuntimeError("Cannot downgrade configured Report archive sources or verified archive history")
    for table in ("report_purge_requests", "report_purge_tombstones"):
        if bind.execute(sa.text(f"SELECT 1 FROM {table} WHERE archive_verification_id IS NOT NULL LIMIT 1")).first() is not None:
            raise RuntimeError("Cannot downgrade verified Report purge history")
    with op.batch_alter_table("report_purge_tombstones") as batch:
        batch.drop_constraint("ck_report_tombstone_archive_revalidation", type_="check")
        batch.drop_column("archive_revalidated_at")
    for table in ("report_purge_tombstones", "report_purge_requests"):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(f"fk_{table}_archive_verification", type_="foreignkey")
            batch.drop_column("archive_verification_id")
    op.drop_table("report_archive_verifications")
    op.drop_table("report_archive_sources")
