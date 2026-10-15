"""Namespace-local promotion policy, source and signed receipt identities."""
from alembic import op
import sqlalchemy as sa

revision = "m5o7q9s1u3w6"
down_revision = "l4n6p8r0t2v5"
branch_labels = None
depends_on = None

CHANGES = (
    ("capability_promotion_policy", "uq_capability_promotion_local_environment", "uq_promotion_policy_namespace_environment", ("local_environment_id",)),
    ("capability_promotion_sources", "uq_capability_promotion_source_name", "uq_promotion_source_namespace_name", ("name",)),
    ("capability_promotion_sources", "uq_capability_promotion_source_environment", "uq_promotion_source_namespace_environment", ("environment_id",)),
    ("capability_promotion_receipts", "uq_capability_promotion_statement_digest", "uq_promotion_receipt_namespace_statement", ("statement_digest_sha256",)),
    ("capability_promotion_receipts", "uq_capability_promotion_target_pack", "uq_promotion_receipt_namespace_target_pack", ("target_environment_id", "pack_digest_sha256")),
)


def _retain_all_namespace_visibility():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        tables = sorted({item[0] for item in CHANGES})
        for table in tables:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Promotion policy migration requires visibility of all namespaces")
        bind.execute(sa.text(f"LOCK TABLE {', '.join(tables)} IN ACCESS EXCLUSIVE MODE"))
    return bind


def upgrade():
    bind = _retain_all_namespace_visibility()
    if bind.execute(sa.text("SELECT tenant_id, region_id FROM capability_promotion_policy "
        "GROUP BY tenant_id, region_id HAVING count(*) > 1 LIMIT 1")).first():
        raise RuntimeError("Promotion namespace contains multiple policies; reconcile without deleting history before upgrading")
    # Retain every ID, audit, signature, FK and timestamp; do not rewrite a
    # legacy non-default 'global' row into another namespace or identity.
    for table, old, new, columns in CHANGES:
        with op.batch_alter_table(table) as batch:
            batch.create_unique_constraint(new, ["tenant_id", "region_id", *columns])
            batch.drop_constraint(old, type_="unique")
    with op.batch_alter_table("capability_promotion_policy") as batch:
        batch.create_unique_constraint("uq_promotion_policy_namespace", ["tenant_id", "region_id"])


def downgrade():
    bind = _retain_all_namespace_visibility()
    # The old application can address only 'global'. Refuse rather than rename
    # accepted policy IDs and leave their durable audit references pointing away.
    if bind.execute(sa.text("SELECT id FROM capability_promotion_policy WHERE id <> 'global' LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade namespace-local promotion authority while non-legacy policies exist")
    for table, _, _, columns in CHANGES:
        names = ", ".join(columns)
        if bind.execute(sa.text(f"SELECT {names} FROM {table} GROUP BY {names} HAVING count(*) > 1 LIMIT 1")).first():
            raise RuntimeError("Cannot downgrade namespace-local promotion authority while duplicate identities exist")
    with op.batch_alter_table("capability_promotion_policy") as batch:
        batch.drop_constraint("uq_promotion_policy_namespace", type_="unique")
    for table, old, new, columns in reversed(CHANGES):
        with op.batch_alter_table(table) as batch:
            batch.create_unique_constraint(old, list(columns))
            batch.drop_constraint(new, type_="unique")
