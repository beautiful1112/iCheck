"""Track exact saved-report bytes and namespace-local storage quotas.

Revision ID: a3b5d7f9h1j4
Revises: z2a4c6e8g0i3
"""

from collections.abc import Sequence
from datetime import UTC, datetime
import json
import uuid

from alembic import op
import sqlalchemy as sa


revision: str = "a3b5d7f9h1j4"
down_revision: str | None = "z2a4c6e8g0i3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _snapshot_size(row) -> int:
    material = {
        "format_version": "icheck.service-report-instance/v1",
        "instance_id": row["id"],
        "tenant_id": row["tenant_id"],
        "region_id": row["region_id"],
        "artifact_version_id": row["artifact_version_id"],
        "snapshot": row["snapshot"],
    }
    return len(json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8"))


def upgrade() -> None:
    op.add_column("service_report_instances", sa.Column("snapshot_size_bytes", sa.Integer(), nullable=True))
    bind = op.get_bind()
    instances = sa.Table("service_report_instances", sa.MetaData(), autoload_with=bind)
    last_id = ""
    while True:
        rows = bind.execute(sa.select(
            instances.c.id, instances.c.tenant_id, instances.c.region_id,
            instances.c.artifact_version_id, instances.c.snapshot,
        ).where(instances.c.id > last_id).order_by(instances.c.id).limit(500)).mappings().all()
        if not rows:
            break
        for row in rows:
            bind.execute(instances.update().where(instances.c.id == row["id"]).values(
                snapshot_size_bytes=_snapshot_size(row),
            ))
        last_id = rows[-1]["id"]
    with op.batch_alter_table("service_report_instances") as batch:
        batch.alter_column("snapshot_size_bytes", existing_type=sa.Integer(), nullable=False)
        batch.create_check_constraint("ck_report_instance_snapshot_size_positive", "snapshot_size_bytes > 0")

    policies = op.create_table(
        "report_storage_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("max_instances", sa.Integer(), nullable=True),
        sa.Column("max_bytes", sa.BigInteger(), nullable=True),
        sa.Column("used_instances", sa.Integer(), nullable=False),
        sa.Column("used_bytes", sa.BigInteger(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000002"),
        sa.UniqueConstraint("tenant_id", "region_id", name="uq_report_storage_policy_namespace"),
        sa.CheckConstraint("max_instances IS NULL OR max_instances > 0", name="ck_report_storage_max_instances"),
        sa.CheckConstraint("max_bytes IS NULL OR max_bytes > 0", name="ck_report_storage_max_bytes"),
        sa.CheckConstraint("used_instances >= 0 AND used_bytes >= 0", name="ck_report_storage_usage_nonnegative"),
        sa.CheckConstraint("revision > 0", name="ck_report_storage_policy_revision"),
    )
    for column in ("tenant_id", "region_id"):
        op.create_index(f"ix_report_storage_policies_{column}", "report_storage_policies", [column])
    summaries = bind.execute(sa.select(
        instances.c.tenant_id, instances.c.region_id,
        sa.func.count(instances.c.id).label("used_instances"),
        sa.func.sum(instances.c.snapshot_size_bytes).label("used_bytes"),
    ).group_by(instances.c.tenant_id, instances.c.region_id)).mappings().all()
    now = datetime.now(UTC)
    for row in summaries:
        bind.execute(policies.insert().values(
            id=str(uuid.uuid4()), tenant_id=row["tenant_id"], region_id=row["region_id"],
            max_instances=None, max_bytes=None,
            used_instances=row["used_instances"], used_bytes=row["used_bytes"],
            revision=1, created_by="migration.backfill", updated_by="migration.backfill",
            created_at=now, updated_at=now,
        ))
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('ALTER TABLE "report_storage_policies" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(
            'CREATE POLICY icheck_namespace_isolation ON "report_storage_policies" '
            "USING (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true))"
        ))


def downgrade() -> None:
    bind = op.get_bind()
    configured = bind.execute(sa.text(
        "SELECT id FROM report_storage_policies WHERE max_instances IS NOT NULL "
        "OR max_bytes IS NOT NULL LIMIT 1"
    )).first()
    if configured is not None:
        raise RuntimeError("Cannot downgrade configured report storage quotas")
    op.drop_table("report_storage_policies")
    with op.batch_alter_table("service_report_instances") as batch:
        batch.drop_constraint("ck_report_instance_snapshot_size_positive", type_="check")
        batch.drop_column("snapshot_size_bytes")
