"""Continuous capability execution quality and exact Tool-call provenance.

Revision ID: g9h1j3l5n7q0
Revises: f8g0i2k4m6p9
"""
from alembic import op
import sqlalchemy as sa

revision = "g9h1j3l5n7q0"
down_revision = "f8g0i2k4m6p9"
branch_labels = None
depends_on = None


def _namespace():
    return (
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
    )


def upgrade():
    op.create_table("capability_quality_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("artifact_version_id", sa.String(36), sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("window_minutes", sa.Integer(), nullable=False),
        sa.Column("min_samples", sa.Integer(), nullable=False),
        sa.Column("max_failure_ppm", sa.Integer(), nullable=False),
        sa.Column("max_p95_ms", sa.Integer(), nullable=False),
        sa.Column("max_sample_age_seconds", sa.Integer(), nullable=False),
        sa.Column("evaluation_interval_seconds", sa.Integer(), nullable=False),
        sa.Column("min_records_per_run", sa.Integer(), nullable=False),
        sa.Column("alert_on_degradation", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("last_assessment_id", sa.String(36), nullable=True),
        sa.Column("next_evaluation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace(),
        sa.UniqueConstraint("tenant_id", "region_id", "artifact_version_id", name="uq_quality_policy_namespace_version"),
        sa.CheckConstraint("revision > 0", name="ck_quality_policy_revision"),
        sa.CheckConstraint("window_minutes BETWEEN 5 AND 10080", name="ck_quality_policy_window"),
        sa.CheckConstraint("min_samples BETWEEN 1 AND 2000", name="ck_quality_policy_samples"),
        sa.CheckConstraint("max_failure_ppm BETWEEN 0 AND 1000000", name="ck_quality_policy_failure_ppm"),
        sa.CheckConstraint("max_p95_ms BETWEEN 1 AND 3600000", name="ck_quality_policy_latency"),
        sa.CheckConstraint("max_sample_age_seconds BETWEEN 60 AND 604800", name="ck_quality_policy_freshness"),
        sa.CheckConstraint("evaluation_interval_seconds BETWEEN 60 AND 86400", name="ck_quality_policy_interval"),
        sa.CheckConstraint("min_records_per_run BETWEEN 0 AND 1000000", name="ck_quality_policy_records"),
    )
    op.create_index("ix_quality_policy_due", "capability_quality_policies", ["tenant_id", "region_id", "next_evaluation_at"])
    op.create_table("capability_quality_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("policy_id", sa.String(36), sa.ForeignKey("capability_quality_policies.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("artifact_version_id", sa.String(36), sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("failure_ppm", sa.Integer(), nullable=True),
        sa.Column("p95_ms", sa.Integer(), nullable=True),
        sa.Column("latest_sample_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_truncated", sa.Boolean(), nullable=False),
        sa.Column("evidence_manifest", sa.JSON(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("assessment_sha256", sa.String(64), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evaluated_by", sa.String(255), nullable=False),
        *_namespace(),
        sa.CheckConstraint("policy_revision > 0", name="ck_quality_assessment_revision"),
        sa.CheckConstraint("status IN ('healthy', 'degraded', 'insufficient_data', 'disabled')", name="ck_quality_assessment_status"),
        sa.CheckConstraint("sample_count BETWEEN 0 AND 2000 AND failed_count BETWEEN 0 AND sample_count", name="ck_quality_assessment_counts"),
        sa.CheckConstraint("failure_ppm IS NULL OR failure_ppm BETWEEN 0 AND 1000000", name="ck_quality_assessment_failure_ppm"),
    )
    op.create_index("ix_quality_assessment_policy_time", "capability_quality_assessments", ["policy_id", "evaluated_at"])
    for table, fields in (
        ("capability_quality_policies", ("tenant_id", "region_id", "artifact_version_id")),
        ("capability_quality_assessments", ("tenant_id", "region_id", "artifact_version_id", "policy_id")),
    ):
        for field in fields:
            op.create_index(f"ix_{table}_{field}", table, [field])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} "
                "USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) "
                "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"))
    with op.batch_alter_table("investigation_tool_calls") as batch:
        batch.add_column(sa.Column("artifact_version_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("artifact_content_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("artifact_activation_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("artifact_activation_sha256", sa.String(64), nullable=True))
        batch.create_foreign_key("fk_tool_call_artifact_version", "artifact_versions", ["artifact_version_id"], ["id"], ondelete="RESTRICT")
        batch.create_check_constraint("ck_tool_call_artifact_provenance",
            "(artifact_version_id IS NULL AND artifact_content_hash IS NULL AND artifact_activation_id IS NULL AND artifact_activation_sha256 IS NULL) OR "
            "(artifact_version_id IS NOT NULL AND artifact_content_hash IS NOT NULL AND artifact_activation_id IS NOT NULL AND artifact_activation_sha256 IS NOT NULL)")
        batch.create_index("ix_investigation_tool_calls_artifact_version_id", ["artifact_version_id"])


def downgrade():
    bind = op.get_bind()
    tables = ("capability_quality_policies", "capability_quality_assessments", "investigation_tool_calls")
    if bind.dialect.name == "postgresql":
        for table in tables:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Quality downgrade requires visibility of all namespaces")
    for table in tables[:2]:
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Cannot downgrade configured capability quality or assessment history")
    if bind.execute(sa.text("SELECT 1 FROM investigation_tool_calls WHERE artifact_version_id IS NOT NULL LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade version-pinned Tool execution history")
    with op.batch_alter_table("investigation_tool_calls") as batch:
        batch.drop_constraint("ck_tool_call_artifact_provenance", type_="check")
        batch.drop_constraint("fk_tool_call_artifact_version", type_="foreignkey")
        batch.drop_index("ix_investigation_tool_calls_artifact_version_id")
        for column in ("artifact_activation_sha256", "artifact_activation_id", "artifact_content_hash", "artifact_version_id"):
            batch.drop_column(column)
    op.drop_table("capability_quality_assessments")
    op.drop_table("capability_quality_policies")
