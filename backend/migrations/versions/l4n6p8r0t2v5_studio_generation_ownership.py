"""Durable Studio generation ownership and exact candidate outcomes."""
from alembic import op
import sqlalchemy as sa
from datetime import UTC, datetime
from uuid import uuid4

revision = "l4n6p8r0t2v5"
down_revision = "k3m5p7r9t1v4"
branch_labels = None
depends_on = None
TABLE = "capability_studio_generation_attempts"


def _install_history_guard(bind):
    frozen = ("id", "tenant_id", "region_id", "session_id", "request_key", "request_sha256", "request_document", "actor", "created_at")
    model = ("model_document", "model_document_sha256", "route_id", "model_id", "tokens_used")
    candidate = ("artifact_id", "artifact_version_id", "candidate_sha256")
    result = ("result_snapshot", "result_sha256")
    usage = ("usage_recorded", "tokens_used", "route_id", "model_id")
    if bind.dialect.name == "postgresql":
        def changed(fields):
            return " OR ".join(f'OLD."{field}"' + ("::jsonb" if field in {"request_document", "model_document", "result_snapshot"} else "")
                + " IS DISTINCT FROM " + f'NEW."{field}"' + ("::jsonb" if field in {"request_document", "model_document", "result_snapshot"} else "") for field in fields)
        invalid = f"({changed(frozen)}) OR (OLD.model_schema IS NOT NULL AND ({changed(('model_schema', 'prompt_sha256'))})) "
        invalid += f"OR (OLD.model_document_sha256 IS NOT NULL AND ({changed(model)})) "
        invalid += f"OR (OLD.artifact_version_id IS NOT NULL AND ({changed(candidate)})) "
        invalid += f"OR (OLD.result_sha256 IS NOT NULL AND ({changed(result)})) "
        invalid += f"OR (OLD.usage_recorded AND ({changed(usage)})) "
        invalid += "OR (OLD.status IN ('validated', 'failed', 'interrupted') AND OLD.status IS DISTINCT FROM NEW.status)"
        op.execute(sa.text("CREATE FUNCTION icheck_guard_studio_generation_history() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Studio generation history cannot be deleted'; END IF; "
            f"IF {invalid} THEN RAISE EXCEPTION 'Studio generation history is sealed'; END IF; RETURN NEW; END; $$"))
        op.execute(sa.text(f"CREATE TRIGGER icheck_sealed_studio_generation BEFORE UPDATE OR DELETE ON {TABLE} "
            "FOR EACH ROW EXECUTE FUNCTION icheck_guard_studio_generation_history()"))
    elif bind.dialect.name == "sqlite":
        def changed(fields):
            return " OR ".join(f'OLD."{field}" IS NOT NEW."{field}"' for field in fields)
        invalid = f"({changed(frozen)}) OR (OLD.model_schema IS NOT NULL AND ({changed(('model_schema', 'prompt_sha256'))})) "
        invalid += f"OR (OLD.model_document_sha256 IS NOT NULL AND ({changed(model)})) "
        invalid += f"OR (OLD.artifact_version_id IS NOT NULL AND ({changed(candidate)})) "
        invalid += f"OR (OLD.result_sha256 IS NOT NULL AND ({changed(result)})) "
        invalid += f"OR (OLD.usage_recorded AND ({changed(usage)})) "
        invalid += "OR (OLD.status IN ('validated', 'failed', 'interrupted') AND OLD.status IS NOT NEW.status)"
        op.execute(sa.text(f"CREATE TRIGGER icheck_sealed_studio_generation_update BEFORE UPDATE ON {TABLE} "
            f"WHEN {invalid} BEGIN SELECT RAISE(ABORT, 'Studio generation history is sealed'); END"))
        op.execute(sa.text(f"CREATE TRIGGER icheck_sealed_studio_generation_delete BEFORE DELETE ON {TABLE} "
            "BEGIN SELECT RAISE(ABORT, 'Studio generation history cannot be deleted'); END"))


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text(
        "SELECT row_security_active('capability_studio_sessions')")).scalar():
        raise RuntimeError("Studio ownership migration requires visibility of all namespaces")
    op.add_column("capability_studio_sessions", sa.Column("generation_attempt_id", sa.String(36), nullable=True))
    op.create_index("ix_capability_studio_sessions_generation_attempt_id", "capability_studio_sessions", ["generation_attempt_id"])
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("capability_studio_sessions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("request_key", sa.String(36), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("request_document", sa.JSON(), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("owner_sha256", sa.String(64), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("model_schema", sa.String(128), nullable=True),
        sa.Column("prompt_sha256", sa.String(64), nullable=True),
        sa.Column("model_document", sa.JSON(), nullable=False),
        sa.Column("model_document_sha256", sa.String(64), nullable=True),
        sa.Column("usage_recorded", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("route_id", sa.String(36), nullable=True),
        sa.Column("model_id", sa.String(36), nullable=True),
        sa.Column("tokens_used", sa.Integer(), nullable=False),
        sa.Column("artifact_id", sa.String(36), sa.ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("artifact_version_id", sa.String(36), sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("candidate_sha256", sa.String(64), nullable=True),
        sa.Column("result_snapshot", sa.JSON(), nullable=False),
        sa.Column("result_sha256", sa.String(64), nullable=True),
        sa.Column("failure_code", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "session_id", "request_key", name="uq_studio_generation_request"),
        sa.CheckConstraint("status IN ('generating', 'generated', 'draft', 'validated', 'failed', 'interrupted')", name="ck_studio_generation_status"),
        sa.CheckConstraint("tokens_used >= 0", name="ck_studio_generation_tokens"),
        sa.CheckConstraint("(artifact_id IS NULL AND artifact_version_id IS NULL AND candidate_sha256 IS NULL) OR "
            "(artifact_id IS NOT NULL AND artifact_version_id IS NOT NULL AND candidate_sha256 IS NOT NULL)", name="ck_studio_generation_candidate"))
    for field in ("tenant_id", "region_id", "session_id", "status", "artifact_id", "artifact_version_id"):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} "
            "USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"))
    _install_history_guard(bind)
    # Old in-flight requests have no lease or response record. Preserve their
    # existing spec/draft/messages/usage, but do not inherit execution ownership.
    legacy = bind.execute(sa.text("SELECT id, tenant_id, region_id, artifact_version_id FROM capability_studio_sessions WHERE status = 'generating'")).mappings().all()
    audits = sa.table("audit_events", sa.column("id", sa.String(36)), sa.column("tenant_id", sa.String(36)),
        sa.column("region_id", sa.String(36)), sa.column("occurred_at", sa.DateTime(timezone=True)),
        sa.column("event_type", sa.String(128)), sa.column("actor_type", sa.String(32)), sa.column("actor_id", sa.String(255)),
        sa.column("entity_type", sa.String(64)), sa.column("entity_id", sa.String(255)), sa.column("outcome", sa.String(32)), sa.column("details", sa.JSON()))
    for row in legacy:
        bind.execute(audits.insert().values(id=str(uuid4()), tenant_id=row["tenant_id"], region_id=row["region_id"],
            occurred_at=datetime.now(UTC), event_type="capability.studio.generation.legacy_interrupted", actor_type="system",
            actor_id="migration.studio_ownership", entity_type="capability_studio_session", entity_id=row["id"], outcome="failure",
            details={"artifact_version_id": row["artifact_version_id"], "reason": "legacy_request_has_no_durable_owner_or_response"}))
    op.execute(sa.text("UPDATE capability_studio_sessions SET status = 'failed' WHERE status = 'generating'"))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text(
        "SELECT row_security_active(:table)"), {"table": TABLE}).scalar():
        raise RuntimeError("Studio ownership downgrade requires visibility of all namespaces")
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade recorded Studio generation history")
    op.drop_table(TABLE)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_studio_generation_history()"))
    op.drop_index("ix_capability_studio_sessions_generation_attempt_id", table_name="capability_studio_sessions")
    op.drop_column("capability_studio_sessions", "generation_attempt_id")
