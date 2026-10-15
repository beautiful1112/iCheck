"""Separate preapproval prerequisite freshness from Alert freshness."""
from datetime import UTC, datetime
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision = "k3m5p7r9t1v4"
down_revision = "j2l4n6p8r0t3"
branch_labels = None
depends_on = None


TABLE = "change_preapproval_policies"


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"),
        {"table": TABLE}).scalar():
        raise RuntimeError("Preapproval evidence-age migration requires visibility of all namespaces")
    with op.batch_alter_table(TABLE) as batch:
        batch.add_column(sa.Column("max_evidence_age_seconds", sa.Integer(),
            nullable=False, server_default="300"))
        batch.create_check_constraint("ck_change_preapproval_evidence_age",
            "max_evidence_age_seconds BETWEEN 60 AND 3600")
    # The new field was not part of old peer-review hashes. Explicitly return
    # reviewed policies to draft and leave a namespace-local, hash-only audit
    # event, rather than displaying a stale review as valid configuration.
    reviewed = bind.execute(sa.text(f"SELECT id, tenant_id, region_id, revision, review_sha256 "
        f"FROM {TABLE} WHERE status = 'reviewed'")).mappings().all()
    audit = sa.table("audit_events",
        sa.column("id", sa.String(36)), sa.column("tenant_id", sa.String(36)),
        sa.column("region_id", sa.String(36)), sa.column("occurred_at", sa.DateTime(timezone=True)),
        sa.column("event_type", sa.String(128)), sa.column("actor_type", sa.String(32)),
        sa.column("actor_id", sa.String(255)), sa.column("entity_type", sa.String(64)),
        sa.column("entity_id", sa.String(255)), sa.column("outcome", sa.String(32)),
        sa.column("details", sa.JSON()))
    for policy in reviewed:
        now = datetime.now(UTC)
        updated = bind.execute(sa.text(f"UPDATE {TABLE} SET status = 'draft', revision = revision + 1, "
            "reviewed_by = NULL, reviewed_by_principal_id = NULL, reviewed_at = NULL, "
            "review_sha256 = NULL, updated_by = :actor, updated_at = :now "
            "WHERE id = :id AND tenant_id = :tenant_id AND region_id = :region_id "
            "AND status = 'reviewed' AND revision = :revision"),
            {"actor": "migration.evidence_age", "now": now, "id": policy["id"],
             "tenant_id": policy["tenant_id"], "region_id": policy["region_id"],
             "revision": policy["revision"]})
        if updated.rowcount != 1:
            raise RuntimeError("Preapproval review changed during evidence-age migration")
        bind.execute(audit.insert().values(id=str(uuid4()), tenant_id=policy["tenant_id"],
            region_id=policy["region_id"], occurred_at=now,
            event_type="change.preapproval.review_invalidated", actor_type="system",
            actor_id="migration.evidence_age", entity_type="change_preapproval_policy",
            entity_id=policy["id"], outcome="success",
            details={"previous_review_sha256": policy["review_sha256"],
                "new_revision": policy["revision"] + 1,
                "reason": "new_required_evidence_age_bound"}))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"),
        {"table": TABLE}).scalar():
        raise RuntimeError("Preapproval evidence-age downgrade requires visibility of all namespaces")
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot drop configured preapproval evidence-age history")
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_constraint("ck_change_preapproval_evidence_age", type_="check")
        batch.drop_column("max_evidence_age_seconds")
