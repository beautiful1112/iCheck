"""Retain archive attestations, legal holds, purge review and tombstones.

Revision ID: c5d7f9h1j3l6
Revises: b4c6e8g0i2k5
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c5d7f9h1j3l6"
down_revision: str | None = "b4c6e8g0i2k5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _namespace():
    return [
        sa.Column("tenant_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000002"),
    ]


def _indices_and_rls(table: str, extra: tuple[str, ...]) -> None:
    for column in ("tenant_id", "region_id", *extra):
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


def upgrade() -> None:
    op.create_table(
        "report_archive_acknowledgements",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("instance_id", sa.String(36), nullable=False),
        sa.Column("artifact_version_id", sa.String(36), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot_size_bytes", sa.Integer(), nullable=False),
        sa.Column("archive_reference", sa.String(255), nullable=False),
        sa.Column("reason_sha256", sa.String(64), nullable=False),
        sa.Column("acknowledged_by", sa.String(255), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace(),
        sa.UniqueConstraint("tenant_id", "region_id", "instance_id", "archive_reference",
                            name="uq_report_archive_namespace_instance_reference"),
        sa.CheckConstraint("snapshot_size_bytes > 0", name="ck_report_archive_snapshot_size_positive"),
    )
    _indices_and_rls("report_archive_acknowledgements", ("instance_id", "artifact_version_id"))

    op.create_table(
        "report_legal_holds",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("instance_id", sa.String(36), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("hold_reference", sa.String(255), nullable=False),
        sa.Column("reason_sha256", sa.String(64), nullable=False),
        sa.Column("placed_by", sa.String(255), nullable=False),
        sa.Column("placed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_by", sa.String(255), nullable=True),
        sa.Column("release_reason_sha256", sa.String(64), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        *_namespace(),
        sa.UniqueConstraint("tenant_id", "region_id", "instance_id", "hold_reference",
                            name="uq_report_hold_namespace_instance_reference"),
        sa.CheckConstraint(
            "(released_at IS NULL AND released_by IS NULL AND release_reason_sha256 IS NULL) "
            "OR (released_at IS NOT NULL AND released_by IS NOT NULL "
            "AND release_reason_sha256 IS NOT NULL)",
            name="ck_report_hold_release_complete",
        ),
    )
    _indices_and_rls("report_legal_holds", ("instance_id",))

    op.create_table(
        "report_purge_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("instance_id", sa.String(36), nullable=False),
        sa.Column("artifact_version_id", sa.String(36), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot_size_bytes", sa.Integer(), nullable=False),
        sa.Column("archive_acknowledgement_id", sa.String(36),
                  sa.ForeignKey("report_archive_acknowledgements.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("request_reason_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("requester_identity", sa.String(255), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewer_identity", sa.String(255), nullable=True),
        sa.Column("review_reason_sha256", sa.String(64), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_by", sa.String(255), nullable=True),
        sa.Column("execution_reason_sha256", sa.String(64), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        *_namespace(),
        sa.UniqueConstraint("tenant_id", "region_id", "request_sha256",
                            name="uq_report_purge_namespace_request"),
        sa.CheckConstraint("status IN ('requested', 'approved', 'rejected', 'executed')",
                           name="ck_report_purge_request_status"),
        sa.CheckConstraint("snapshot_size_bytes > 0", name="ck_report_purge_snapshot_size_positive"),
    )
    _indices_and_rls("report_purge_requests", (
        "instance_id", "archive_acknowledgement_id", "status",
    ))

    op.create_table(
        "report_purge_tombstones",
        sa.Column("instance_id", sa.String(36), primary_key=True),
        sa.Column("artifact_id", sa.String(36), nullable=False),
        sa.Column("artifact_version_id", sa.String(36), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot_size_bytes", sa.Integer(), nullable=False),
        sa.Column("archive_acknowledgement_id", sa.String(36),
                  sa.ForeignKey("report_archive_acknowledgements.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("purge_request_id", sa.String(36),
                  sa.ForeignKey("report_purge_requests.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("deleted_by", sa.String(255), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace(),
        sa.UniqueConstraint("tenant_id", "region_id", "request_sha256",
                            name="uq_report_tombstone_namespace_capture_request"),
        sa.UniqueConstraint("purge_request_id", name="uq_report_tombstone_purge_request"),
        sa.CheckConstraint("snapshot_size_bytes > 0", name="ck_report_tombstone_snapshot_size_positive"),
    )
    _indices_and_rls("report_purge_tombstones", (
        "archive_acknowledgement_id", "purge_request_id",
    ))


def downgrade() -> None:
    bind = op.get_bind()
    for table in (
        "report_purge_tombstones", "report_purge_requests", "report_legal_holds",
        "report_archive_acknowledgements",
    ):
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() is not None:
            raise RuntimeError("Cannot downgrade retained Report governance history")
    for table in (
        "report_purge_tombstones", "report_purge_requests", "report_legal_holds",
        "report_archive_acknowledgements",
    ):
        op.drop_table(table)
