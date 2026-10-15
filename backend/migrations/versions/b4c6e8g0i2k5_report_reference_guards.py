"""Pin saved Report references in Agent evidence and delivery receipts.

Revision ID: b4c6e8g0i2k5
Revises: a3b5d7f9h1j4
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "b4c6e8g0i2k5"
down_revision: str | None = "a3b5d7f9h1j4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("investigation_evidence", sa.Column("report_instance_id", sa.String(36), nullable=True))
    op.add_column("report_delivery_receipts", sa.Column("report_instance_id", sa.String(36), nullable=True))
    bind = op.get_bind()
    metadata = sa.MetaData()
    evidence = sa.Table("investigation_evidence", metadata, autoload_with=bind)
    reports = sa.Table("service_report_instances", metadata, autoload_with=bind)
    missing = bind.execute(sa.select(evidence.c.id).select_from(
        evidence.outerjoin(reports, reports.c.id == evidence.c.evidence_id)
    ).where(
        evidence.c.evidence_type == "service_report_instance",
        sa.or_(
            reports.c.id.is_(None), reports.c.tenant_id != evidence.c.tenant_id,
            reports.c.region_id != evidence.c.region_id,
        ),
    ).limit(1)).first()
    if missing is not None:
        raise RuntimeError("Cannot backfill orphaned or cross-namespace saved Report evidence")
    bind.execute(evidence.update().where(
        evidence.c.evidence_type == "service_report_instance"
    ).values(report_instance_id=evidence.c.evidence_id))
    with op.batch_alter_table("investigation_evidence") as batch:
        batch.create_foreign_key(
            "fk_investigation_evidence_report_instance", "service_report_instances",
            ["report_instance_id"], ["id"], ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_investigation_evidence_report_instance_ref",
            "(evidence_type = 'service_report_instance' AND report_instance_id IS NOT NULL "
            "AND report_instance_id = evidence_id) "
            "OR (evidence_type <> 'service_report_instance' AND report_instance_id IS NULL)",
        )
    op.create_index(
        "ix_investigation_evidence_report_instance_id", "investigation_evidence",
        ["report_instance_id"],
    )
    with op.batch_alter_table("report_delivery_receipts") as batch:
        batch.create_foreign_key(
            "fk_report_delivery_receipt_instance", "service_report_instances",
            ["report_instance_id"], ["id"], ondelete="RESTRICT",
        )
    op.create_index(
        "ix_report_delivery_receipts_report_instance_id", "report_delivery_receipts",
        ["report_instance_id"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("investigation_evidence", "report_delivery_receipts"):
        linked = bind.execute(sa.text(
            f"SELECT id FROM {table} WHERE report_instance_id IS NOT NULL LIMIT 1"
        )).first()
        if linked is not None:
            raise RuntimeError("Cannot downgrade while saved Report evidence or delivery references exist")
    op.drop_index("ix_report_delivery_receipts_report_instance_id", table_name="report_delivery_receipts")
    with op.batch_alter_table("report_delivery_receipts") as batch:
        batch.drop_constraint("fk_report_delivery_receipt_instance", type_="foreignkey")
        batch.drop_column("report_instance_id")
    op.drop_index("ix_investigation_evidence_report_instance_id", table_name="investigation_evidence")
    with op.batch_alter_table("investigation_evidence") as batch:
        batch.drop_constraint("ck_investigation_evidence_report_instance_ref", type_="check")
        batch.drop_constraint("fk_investigation_evidence_report_instance", type_="foreignkey")
        batch.drop_column("report_instance_id")
