"""Store immutable rendered report attachments and exact delivery references.

Revision ID: d6e8g0i2k4m7
Revises: c5d7f9h1j3l6
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "d6e8g0i2k4m7"
down_revision: str | None = "c5d7f9h1j3l6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("report_purge_tombstones", sa.Column("attachments", sa.JSON(), nullable=False, server_default="[]"))
    with op.batch_alter_table("report_storage_policies") as batch:
        batch.add_column(sa.Column("max_attachment_bytes", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("used_attachment_bytes", sa.BigInteger(), nullable=False, server_default="0"))
        batch.create_check_constraint("ck_report_storage_max_attachment_bytes", "max_attachment_bytes IS NULL OR max_attachment_bytes > 0")
        batch.create_check_constraint("ck_report_storage_attachment_usage", "used_attachment_bytes >= 0")
    op.create_table(
        "report_attachments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("instance_id", sa.String(36), sa.ForeignKey("service_report_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("export_format", sa.String(8), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(128), nullable=False),
        sa.Column("renderer", sa.String(255), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.UniqueConstraint("instance_id", "export_format", name="uq_report_attachment_instance_format"),
        sa.CheckConstraint("size_bytes > 0 AND size_bytes <= 4000000", name="ck_report_attachment_size"),
        sa.CheckConstraint("export_format IN ('json', 'html', 'csv', 'pdf')", name="ck_report_attachment_format"),
    )
    for column in ("instance_id", "tenant_id", "region_id"):
        op.create_index(f"ix_report_attachments_{column}", "report_attachments", [column])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("ALTER TABLE report_attachments ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(
            "CREATE POLICY icheck_namespace_isolation ON report_attachments "
            "USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"
        ))
    with op.batch_alter_table("workflow_schedule_activations") as batch:
        batch.add_column(sa.Column("report_attachment_format", sa.String(8), nullable=True))
        batch.create_check_constraint(
            "ck_workflow_schedule_attachment_binding",
            "report_attachment_format IS NULL OR (report_artifact_version_id IS NOT NULL AND report_attachment_format IN ('json', 'html', 'csv', 'pdf'))",
        )
    with op.batch_alter_table("report_delivery_receipts") as batch:
        batch.add_column(sa.Column("report_attachment_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("report_attachment_sha256", sa.String(64), nullable=True))
        batch.create_foreign_key("fk_report_receipt_attachment", "report_attachments", ["report_attachment_id"], ["id"], ondelete="RESTRICT")
        batch.create_check_constraint(
            "ck_report_receipt_attachment_complete",
            "(report_attachment_id IS NULL AND report_attachment_sha256 IS NULL) OR "
            "(report_attachment_id IS NOT NULL AND report_attachment_sha256 IS NOT NULL AND report_instance_id IS NOT NULL)",
        )
    op.create_index("ix_report_delivery_receipts_report_attachment_id", "report_delivery_receipts", ["report_attachment_id"])


def downgrade() -> None:
    bind = op.get_bind()
    for query in (
        "SELECT 1 FROM report_attachments LIMIT 1",
        "SELECT 1 FROM workflow_schedule_activations WHERE report_attachment_format IS NOT NULL LIMIT 1",
        "SELECT 1 FROM report_storage_policies WHERE max_attachment_bytes IS NOT NULL OR used_attachment_bytes <> 0 LIMIT 1",
        "SELECT 1 FROM report_delivery_receipts WHERE report_attachment_id IS NOT NULL LIMIT 1",
        "SELECT 1 FROM report_purge_tombstones WHERE CAST(attachments AS TEXT) <> '[]' LIMIT 1",
    ):
        if bind.execute(sa.text(query)).first() is not None:
            raise RuntimeError("Cannot downgrade configured or retained report attachments")
    op.drop_index("ix_report_delivery_receipts_report_attachment_id", table_name="report_delivery_receipts")
    with op.batch_alter_table("report_delivery_receipts") as batch:
        batch.drop_constraint("ck_report_receipt_attachment_complete", type_="check")
        batch.drop_constraint("fk_report_receipt_attachment", type_="foreignkey")
        batch.drop_column("report_attachment_sha256")
        batch.drop_column("report_attachment_id")
    with op.batch_alter_table("workflow_schedule_activations") as batch:
        batch.drop_constraint("ck_workflow_schedule_attachment_binding", type_="check")
        batch.drop_column("report_attachment_format")
    op.drop_table("report_attachments")
    with op.batch_alter_table("report_storage_policies") as batch:
        batch.drop_constraint("ck_report_storage_attachment_usage", type_="check")
        batch.drop_constraint("ck_report_storage_max_attachment_bytes", type_="check")
        batch.drop_column("used_attachment_bytes")
        batch.drop_column("max_attachment_bytes")
    with op.batch_alter_table("report_purge_tombstones") as batch:
        batch.drop_column("attachments")
