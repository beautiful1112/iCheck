"""Scope transparency chains and witness identities to each namespace.

Revision ID: z2a4c6e8g0i3
Revises: y1z3b5d7f9h2
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "z2a4c6e8g0i3"
down_revision: str | None = "y1z3b5d7f9h2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SCOPED_CONSTRAINTS = (
    (
        "capability_transparency_records",
        (
            ("uq_capability_transparency_record_sequence", "uq_transparency_record_namespace_sequence", ("sequence",)),
            ("uq_capability_transparency_record_digest", "uq_transparency_record_namespace_digest", ("record_digest_sha256",)),
        ),
    ),
    (
        "capability_transparency_witnesses",
        (
            ("uq_capability_transparency_witness_identity", "uq_transparency_witness_namespace_identity", ("witness_id",)),
            ("uq_capability_transparency_witness_name", "uq_transparency_witness_namespace_name", ("name",)),
        ),
    ),
    (
        "capability_transparency_checkpoint_offers",
        (("uq_transparency_checkpoint_offer_digest", "uq_transparency_offer_namespace_digest", ("statement_digest_sha256",)),),
    ),
    (
        "capability_transparency_witness_attestations",
        (("uq_transparency_attestation_digest", "uq_transparency_attestation_namespace_digest", ("attestation_digest_sha256",)),),
    ),
    (
        "capability_transparency_gossip_observations",
        (("uq_transparency_gossip_document", "uq_transparency_gossip_namespace_document", ("document_digest_sha256",)),),
    ),
)


def upgrade() -> None:
    for table, changes in SCOPED_CONSTRAINTS:
        with op.batch_alter_table(table) as batch:
            for old_name, new_name, columns in changes:
                batch.create_unique_constraint(
                    new_name, ["tenant_id", "region_id", *columns],
                )
                batch.drop_constraint(old_name, type_="unique")


def downgrade() -> None:
    bind = op.get_bind()
    for table, changes in SCOPED_CONSTRAINTS:
        for _, _, columns in changes:
            names = ", ".join(columns)
            duplicate = bind.execute(sa.text(
                f"SELECT {names} FROM {table} GROUP BY {names} HAVING COUNT(*) > 1 LIMIT 1"
            )).first()
            if duplicate is not None:
                raise RuntimeError(
                    "Cannot downgrade namespace-local transparency while cross-namespace duplicate identities exist"
                )
    for table in ("capability_transparency_state", "capability_transparency_witness_policy"):
        nondefault = bind.execute(sa.text(
            f"SELECT id FROM {table} WHERE id <> 'global' LIMIT 1"
        )).first()
        if nondefault is not None:
            raise RuntimeError(
                "Cannot downgrade namespace-local transparency while non-default log state or policy exists"
            )
    for table, changes in reversed(SCOPED_CONSTRAINTS):
        with op.batch_alter_table(table) as batch:
            for old_name, new_name, columns in changes:
                batch.create_unique_constraint(old_name, list(columns))
                batch.drop_constraint(new_name, type_="unique")
