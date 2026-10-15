"""automated quorum-backed transparency gossip transport

Revision ID: x4b6d8e0f245
Revises: w3a5c7d9e134
Create Date: 2026-10-07 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "x4b6d8e0f245"
down_revision: str | None = "w3a5c7d9e134"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


ENDPOINTS = "ecosystem_transport_endpoints"
JOBS = "ecosystem_transport_jobs"


def upgrade() -> None:
    with op.batch_alter_table(ENDPOINTS) as batch:
        batch.add_column(
            sa.Column("target_region_id", sa.String(length=255), nullable=True)
        )
        batch.drop_constraint(
            "ck_ecosystem_transport_endpoint_binding", type_="check"
        )
        batch.drop_constraint(
            "ck_ecosystem_transport_endpoint_kind", type_="check"
        )
        batch.create_check_constraint(
            "ck_ecosystem_transport_endpoint_kind",
            "kind IN ('transparency_witness', 'promotion_target', "
            "'gossip_peer')",
        )
        batch.create_check_constraint(
            "ck_ecosystem_transport_endpoint_binding",
            "(kind = 'transparency_witness' AND witness_id IS NOT NULL "
            "AND target_environment_id IS NULL AND target_stage IS NULL "
            "AND target_region_id IS NULL) OR "
            "(kind = 'promotion_target' AND witness_id IS NULL "
            "AND target_environment_id IS NOT NULL AND target_stage IS NOT NULL "
            "AND target_region_id IS NULL) OR "
            "(kind = 'gossip_peer' AND witness_id IS NULL "
            "AND target_environment_id IS NULL AND target_stage IS NULL "
            "AND target_region_id IS NOT NULL)",
        )
        batch.create_index(
            "ix_ecosystem_transport_endpoints_target_region_id",
            ["target_region_id"],
            unique=False,
        )

    with op.batch_alter_table(JOBS) as batch:
        batch.drop_constraint("ck_ecosystem_transport_job_binding", type_="check")
        batch.drop_constraint("ck_ecosystem_transport_job_kind", type_="check")
        batch.create_check_constraint(
            "ck_ecosystem_transport_job_kind",
            "kind IN ('witness_checkpoint', 'promotion_delivery', "
            "'gossip_delivery')",
        )
        batch.create_check_constraint(
            "ck_ecosystem_transport_job_binding",
            "(kind IN ('witness_checkpoint', 'gossip_delivery') "
            "AND checkpoint_offer_id IS NOT NULL) OR "
            "(kind = 'promotion_delivery' AND checkpoint_offer_id IS NULL)",
        )


def downgrade() -> None:
    with op.batch_alter_table(JOBS) as batch:
        batch.drop_constraint("ck_ecosystem_transport_job_binding", type_="check")
        batch.drop_constraint("ck_ecosystem_transport_job_kind", type_="check")
        batch.create_check_constraint(
            "ck_ecosystem_transport_job_kind",
            "kind IN ('witness_checkpoint', 'promotion_delivery')",
        )
        batch.create_check_constraint(
            "ck_ecosystem_transport_job_binding",
            "(kind = 'witness_checkpoint' AND checkpoint_offer_id IS NOT NULL) "
            "OR (kind = 'promotion_delivery' AND checkpoint_offer_id IS NULL)",
        )

    with op.batch_alter_table(ENDPOINTS) as batch:
        batch.drop_index("ix_ecosystem_transport_endpoints_target_region_id")
        batch.drop_constraint(
            "ck_ecosystem_transport_endpoint_binding", type_="check"
        )
        batch.drop_constraint(
            "ck_ecosystem_transport_endpoint_kind", type_="check"
        )
        batch.create_check_constraint(
            "ck_ecosystem_transport_endpoint_kind",
            "kind IN ('transparency_witness', 'promotion_target')",
        )
        batch.create_check_constraint(
            "ck_ecosystem_transport_endpoint_binding",
            "(kind = 'transparency_witness' AND witness_id IS NOT NULL "
            "AND target_environment_id IS NULL AND target_stage IS NULL) OR "
            "(kind = 'promotion_target' AND witness_id IS NULL "
            "AND target_environment_id IS NOT NULL AND target_stage IS NOT NULL)",
        )
        batch.drop_column("target_region_id")
