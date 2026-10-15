"""Link model-call quota receipts to their operator-facing source.

Revision ID: z9b1d3f5h7j0
Revises: y8a0c2e4g6i9
"""

from alembic import op
import sqlalchemy as sa


revision = "z9b1d3f5h7j0"
down_revision = "y8a0c2e4g6i9"
branch_labels = depends_on = None

TABLE = "ai_authoring_quota_reservations"
SOURCE_INDEX = "ix_ai_authoring_quota_reservation_source"
CREATED_INDEX = "ix_ai_authoring_quota_reservation_created"
ACTOR_CREATED_INDEX = "ix_ai_authoring_quota_reservation_actor_created"


def _postgres_guard(*, source_columns: bool) -> None:
    source_check = (
        "OR OLD.source_entity_type IS DISTINCT FROM NEW.source_entity_type "
        "OR OLD.source_entity_id IS DISTINCT FROM NEW.source_entity_id "
        "OR OLD.source_step IS DISTINCT FROM NEW.source_step "
        if source_columns else ""
    )
    op.execute(sa.text(
        "CREATE OR REPLACE FUNCTION icheck_guard_ai_authoring_quota_reservation() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'AI quota reservation cannot be deleted'; END IF; "
        "IF OLD.status = 'settled' OR OLD.status != 'reserved' OR NEW.status != 'settled' "
        "OR OLD.id IS DISTINCT FROM NEW.id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id "
        "OR OLD.region_id IS DISTINCT FROM NEW.region_id "
        "OR OLD.entity_type IS DISTINCT FROM NEW.entity_type OR OLD.entity_id IS DISTINCT FROM NEW.entity_id "
        + source_check +
        "OR OLD.actor IS DISTINCT FROM NEW.actor OR OLD.period_start IS DISTINCT FROM NEW.period_start "
        "OR OLD.reserved_tokens IS DISTINCT FROM NEW.reserved_tokens "
        "OR OLD.created_at IS DISTINCT FROM NEW.created_at "
        "THEN RAISE EXCEPTION 'AI quota reservation is sealed'; END IF; "
        "RETURN NEW; END; $$"
    ))


def _sqlite_guard(*, source_columns: bool, drop_existing: bool = True) -> None:
    if drop_existing:
        op.execute(sa.text(
            "DROP TRIGGER icheck_sealed_ai_authoring_quota_reservation_update"
        ))
    source_check = (
        "OR OLD.source_entity_type IS NOT NEW.source_entity_type "
        "OR OLD.source_entity_id IS NOT NEW.source_entity_id "
        "OR OLD.source_step IS NOT NEW.source_step "
        if source_columns else ""
    )
    op.execute(sa.text(
        f"CREATE TRIGGER icheck_sealed_ai_authoring_quota_reservation_update "
        f"BEFORE UPDATE ON {TABLE} WHEN OLD.status != 'reserved' "
        "OR NEW.status != 'settled' OR OLD.id IS NOT NEW.id "
        "OR OLD.tenant_id IS NOT NEW.tenant_id OR OLD.region_id IS NOT NEW.region_id "
        "OR OLD.entity_type IS NOT NEW.entity_type OR OLD.entity_id IS NOT NEW.entity_id "
        + source_check +
        "OR OLD.actor IS NOT NEW.actor OR OLD.period_start IS NOT NEW.period_start "
        "OR OLD.reserved_tokens IS NOT NEW.reserved_tokens OR OLD.created_at IS NOT NEW.created_at "
        "BEGIN SELECT RAISE(ABORT, 'AI quota reservation is sealed'); END"
    ))


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("source_entity_type", sa.String(64), nullable=True))
    op.add_column(TABLE, sa.Column("source_entity_id", sa.String(36), nullable=True))
    op.add_column(TABLE, sa.Column("source_step", sa.Integer(), nullable=True))
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE ai_authoring_quota_reservations "
            "DISABLE TRIGGER icheck_sealed_ai_authoring_quota_reservation"
        ))
    elif dialect == "sqlite":
        op.execute(sa.text(
            "DROP TRIGGER icheck_sealed_ai_authoring_quota_reservation_update"
        ))
    # Legacy Agent step identities are one-way hashes; never mislabel them as
    # directly addressable investigations. Other old receipts identify their
    # source by their original entity type and ID.
    op.execute(sa.text(
        f"UPDATE {TABLE} SET source_entity_type = entity_type, "
        "source_entity_id = entity_id WHERE entity_type != 'investigation_step'"
    ))
    if dialect == "postgresql":
        op.execute(sa.text(
            "ALTER TABLE ai_authoring_quota_reservations "
            "ENABLE TRIGGER icheck_sealed_ai_authoring_quota_reservation"
        ))
    if dialect == "postgresql":
        _postgres_guard(source_columns=True)
    elif dialect == "sqlite":
        _sqlite_guard(source_columns=True, drop_existing=False)
    op.create_index(
        SOURCE_INDEX, TABLE,
        ["tenant_id", "region_id", "source_entity_type", "source_entity_id"],
    )
    op.create_index(
        CREATED_INDEX, TABLE, ["tenant_id", "region_id", "created_at", "id"],
    )
    op.create_index(
        ACTOR_CREATED_INDEX, TABLE,
        ["tenant_id", "region_id", "actor", "created_at", "id"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot discard AI quota reservation source history")
    dialect = bind.dialect.name
    if dialect == "sqlite":
        op.execute(sa.text(
            "DROP TRIGGER icheck_sealed_ai_authoring_quota_reservation_update"
        ))
    op.drop_index(ACTOR_CREATED_INDEX, table_name=TABLE)
    op.drop_index(CREATED_INDEX, table_name=TABLE)
    op.drop_index(SOURCE_INDEX, table_name=TABLE)
    op.drop_column(TABLE, "source_step")
    op.drop_column(TABLE, "source_entity_id")
    op.drop_column(TABLE, "source_entity_type")
    if dialect == "postgresql":
        _postgres_guard(source_columns=False)
    elif dialect == "sqlite":
        _sqlite_guard(source_columns=False, drop_existing=False)
