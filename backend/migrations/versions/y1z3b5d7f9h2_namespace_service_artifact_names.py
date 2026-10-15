"""Scope service keys and Artifact kind/name identities to tenant and region.

Revision ID: y1z3b5d7f9h2
Revises: x0y2a4c6e8g1
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "y1z3b5d7f9h2"
down_revision: str | None = "x0y2a4c6e8g1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add each scoped constraint before removing the old global one. The batch
    # form also rebuilds SQLite tables while retaining their dependent rows.
    with op.batch_alter_table("service_catalog_entries") as batch:
        batch.create_unique_constraint(
            "uq_service_namespace_key", ["tenant_id", "region_id", "service_key"],
        )
        batch.drop_index("ix_service_catalog_entries_service_key")
        batch.create_index("ix_service_catalog_entries_service_key", ["service_key"], unique=False)
    with op.batch_alter_table("artifacts") as batch:
        batch.create_unique_constraint(
            "uq_artifact_namespace_kind_name", ["tenant_id", "region_id", "kind", "name"],
        )
        batch.drop_constraint("uq_artifact_kind_name", type_="unique")
    # The same pack payload digest may be installed in two namespaces after
    # Artifact names become namespace-local. Each namespace still verifies its
    # own trusted signature; trust-key identities are not changed here.
    with op.batch_alter_table("capability_pack_installations") as batch:
        batch.create_unique_constraint(
            "uq_capability_pack_namespace_name_version",
            ["tenant_id", "region_id", "pack_name", "pack_version"],
        )
        batch.create_unique_constraint(
            "uq_capability_pack_namespace_digest",
            ["tenant_id", "region_id", "pack_digest_sha256"],
        )
        batch.drop_constraint("uq_capability_pack_name_version", type_="unique")
        batch.drop_constraint("uq_capability_pack_digest", type_="unique")


def downgrade() -> None:
    bind = op.get_bind()
    service_duplicate = bind.execute(sa.text(
        "SELECT service_key FROM service_catalog_entries GROUP BY service_key "
        "HAVING COUNT(*) > 1 LIMIT 1"
    )).first()
    artifact_duplicate = bind.execute(sa.text(
        "SELECT kind, name FROM artifacts GROUP BY kind, name "
        "HAVING COUNT(*) > 1 LIMIT 1"
    )).first()
    pack_name_duplicate = bind.execute(sa.text(
        "SELECT pack_name, pack_version FROM capability_pack_installations "
        "GROUP BY pack_name, pack_version HAVING COUNT(*) > 1 LIMIT 1"
    )).first()
    pack_digest_duplicate = bind.execute(sa.text(
        "SELECT pack_digest_sha256 FROM capability_pack_installations "
        "GROUP BY pack_digest_sha256 HAVING COUNT(*) > 1 LIMIT 1"
    )).first()
    if any(item is not None for item in (
        service_duplicate, artifact_duplicate, pack_name_duplicate, pack_digest_duplicate,
    )):
        raise RuntimeError(
            "Cannot downgrade namespace-local names while duplicate keys exist "
            "across tenants or regions; service, Artifact, and pack identities "
            "must remain distinct for the old schema"
        )
    with op.batch_alter_table("capability_pack_installations") as batch:
        batch.create_unique_constraint(
            "uq_capability_pack_name_version", ["pack_name", "pack_version"],
        )
        batch.create_unique_constraint("uq_capability_pack_digest", ["pack_digest_sha256"])
        batch.drop_constraint("uq_capability_pack_namespace_name_version", type_="unique")
        batch.drop_constraint("uq_capability_pack_namespace_digest", type_="unique")
    with op.batch_alter_table("artifacts") as batch:
        batch.create_unique_constraint("uq_artifact_kind_name", ["kind", "name"])
        batch.drop_constraint("uq_artifact_namespace_kind_name", type_="unique")
    with op.batch_alter_table("service_catalog_entries") as batch:
        batch.drop_index("ix_service_catalog_entries_service_key")
        batch.create_index("ix_service_catalog_entries_service_key", ["service_key"], unique=True)
        batch.drop_constraint("uq_service_namespace_key", type_="unique")
