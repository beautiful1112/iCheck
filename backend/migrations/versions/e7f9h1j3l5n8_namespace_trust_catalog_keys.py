"""Make publisher trust pins and catalog identities tenant/region-local.

Revision ID: e7f9h1j3l5n8
Revises: d6e8g0i2k4m7
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e7f9h1j3l5n8"
down_revision: str | None = "d6e8g0i2k4m7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KEYS = (
    ("artifact_trust_keys", "name", "uq_trust_key_namespace_name"),
    ("artifact_trust_keys", "fingerprint_sha256", "uq_trust_key_namespace_fingerprint"),
    ("organization_trust_domains", "organization_id", "uq_trust_domain_namespace_organization"),
    ("organization_trust_domains", "name", "uq_trust_domain_namespace_name"),
    ("remote_capability_catalog_sources", "name", "uq_remote_catalog_namespace_name"),
    ("remote_capability_catalog_sources", "index_url", "uq_remote_catalog_namespace_url"),
)
LEGACY_NAMES = {
    ("organization_trust_domains", "organization_id"): "uq_organization_trust_domain_organization",
    ("organization_trust_domains", "name"): "uq_organization_trust_domain_name",
    ("remote_capability_catalog_sources", "name"): "uq_remote_capability_catalog_name",
    ("remote_capability_catalog_sources", "index_url"): "uq_remote_capability_catalog_index_url",
}
NAMING = {"uq": "uq_%(table_name)s_%(column_0_name)s"}


def upgrade() -> None:
    for table, column, scoped_name in KEYS:
        # PostgreSQL assigns names to the original unnamed key constraints;
        # SQLite reflects None. Resolve both without assuming a PG-generated name.
        matches = [item for item in sa.inspect(op.get_bind()).get_unique_constraints(table)
                   if item["column_names"] == [column]]
        if len(matches) != 1:
            raise RuntimeError(f"Expected one legacy trust uniqueness constraint on {table}.{column}")
        old_name = matches[0]["name"] or f"uq_{table}_{column}"
        with op.batch_alter_table(table, naming_convention=NAMING) as batch:
            batch.create_unique_constraint(scoped_name, ["tenant_id", "region_id", column])
            batch.drop_constraint(old_name, type_="unique")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in dict.fromkeys(item[0] for item in KEYS):
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Trust downgrade requires a migration role that can inspect all namespaces")
    # Check every identity before changing any constraint. Never merge pins,
    # erase revocations, or silently delete independently accepted history.
    for table, column, _ in KEYS:
        duplicate = bind.execute(sa.text(
            f"SELECT {column} FROM {table} GROUP BY {column} HAVING COUNT(*) > 1 LIMIT 1"
        )).first()
        if duplicate is not None:
            raise RuntimeError(
                "Cannot downgrade namespace-local trust/catalog identities while duplicate "
                "publisher pins or catalog identities exist across tenants or regions"
            )
    for table, column, scoped_name in reversed(KEYS):
        with op.batch_alter_table(table, naming_convention=NAMING) as batch:
            batch.create_unique_constraint(
                LEGACY_NAMES.get((table, column), f"uq_{table}_{column}"), [column],
            )
            batch.drop_constraint(scoped_name, type_="unique")
