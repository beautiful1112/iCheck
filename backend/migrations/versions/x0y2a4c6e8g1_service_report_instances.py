"""retain immutable scoped service-health report snapshots

Revision ID: x0y2a4c6e8g1
Revises: w9x1z3b5d7f0
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "x0y2a4c6e8g1"
down_revision: str | None = "w9x1z3b5d7f0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _namespace_columns():
    return [
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
    ]


def upgrade() -> None:
    op.create_table(
        "service_report_instances",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("artifact_id", sa.String(36), sa.ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("artifact_version_id", sa.String(36), sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        *_namespace_columns(),
        sa.UniqueConstraint("tenant_id", "region_id", "request_sha256", name="uq_report_instance_request"),
    )
    op.create_table(
        "service_report_instance_services",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("instance_id", sa.String(36), sa.ForeignKey("service_report_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_key", sa.String(128), nullable=False),
        *_namespace_columns(),
        sa.UniqueConstraint("instance_id", "service_key", name="uq_report_instance_service"),
    )
    for table, columns in (
        ("service_report_instances", ("tenant_id", "region_id", "artifact_id", "artifact_version_id", "generated_at")),
        ("service_report_instance_services", ("tenant_id", "region_id", "instance_id", "service_key")),
    ):
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
            op.execute(sa.text(
                f'CREATE POLICY icheck_namespace_isolation ON "{table}" '
                "USING (tenant_id = current_setting('icheck.tenant_id', true) "
                "AND region_id = current_setting('icheck.region_id', true)) "
                "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
                "AND region_id = current_setting('icheck.region_id', true))"
            ))
    op.create_index("ix_report_instance_artifact_created", "service_report_instances", ["artifact_id", "created_at", "id"])


def downgrade() -> None:
    op.drop_table("service_report_instance_services")
    op.drop_table("service_report_instances")
