"""Exact replacement peer governance only; no retirement, backfill or execution."""
from alembic import op
import sqlalchemy as sa

revision = "e9g1i3k5m7o0"
down_revision = "d8f0h2j4l6n9"
branch_labels = depends_on = None
TABLES = ("collector_source_replacement_requests", "collector_source_replacement_reviews",
    "collector_source_replacement_revocations")
PARENTS = ("collector_deployments", "collector_runs", "knowledge_projections", "agent_executions",
    "collector_condition_sources", "collector_source_qualification_requests",
    "collector_source_qualification_reviews", "collector_source_qualification_revocations")


def _visibility(bind, tables):
    if bind.dialect.name == "postgresql":
        for table in tables:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Source replacement migration requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE " + ", ".join(tables) + " IN ACCESS EXCLUSIVE MODE"))


def upgrade():
    bind = op.get_bind(); pg = bind.dialect.name == "postgresql"
    if bind.dialect.name not in {"postgresql", "sqlite"}:
        raise RuntimeError("Source replacement governance requires PostgreSQL or SQLite")
    _visibility(bind, PARENTS)
    for query in (
        "SELECT 1 FROM collector_deployments WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_runs WHERE status='RUNNING' LIMIT 1",
        "SELECT 1 FROM knowledge_projections WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL OR status='PROCESSING' LIMIT 1",
        "SELECT 1 FROM agent_executions WHERE lease_token_hash IS NOT NULL OR status='RUNNING' LIMIT 1",
    ):
        if bind.execute(sa.text(query)).first():
            raise RuntimeError("Drain API/Collector/Projection/Agent ownership before source replacement migration")
    def columns():
        return [sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("region_id", sa.String(36), nullable=False)]
    def ref(name, table):
        return sa.Column(name, sa.String(36), sa.ForeignKey(table + ".id", ondelete="RESTRICT"), nullable=False)
    op.create_table(TABLES[0], *columns(),
        *[ref(key, "collector_condition_sources") for key in ("old_source_id", "new_source_id")],
        *[ref(key, "collector_source_qualification_reviews") for key in ("old_qualification_review_id", "new_qualification_review_id")],
        ref("author_principal_id", "control_plane_principals"), sa.Column("author_subject", sa.String(255), nullable=False),
        sa.Column("request_key", sa.String(128), nullable=False), sa.Column("evidence_environment", sa.String(32), nullable=False),
        sa.Column("validation_reference", sa.String(1024), nullable=False), sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "request_key", name="uq_source_replacement_request_key"),
        sa.CheckConstraint("old_source_id <> new_source_id", name="ck_source_replacement_distinct_sources"),
        sa.CheckConstraint("expires_at > created_at", name="ck_source_replacement_request_lifetime"))
    op.create_table(TABLES[1], *columns(), ref("request_id", TABLES[0]),
        ref("reviewer_principal_id", "control_plane_principals"), sa.Column("reviewer_subject", sa.String(255), nullable=False),
        sa.Column("acceptance_reference", sa.String(1024), nullable=False), sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("request_id", name="uq_source_replacement_review_request"))
    op.create_table(TABLES[2], *columns(), ref("review_id", TABLES[1]),
        ref("principal_id", "control_plane_principals"), sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("review_id", name="uq_source_replacement_revocation_review"))
    for table in TABLES:
        for name in ("tenant_id", "region_id"):
            op.create_index(f"ix_{table}_{name}", table, [name])
    for table, field in ((TABLES[0], "old_source_id"), (TABLES[0], "new_source_id"),
        (TABLES[1], "request_id"), (TABLES[2], "review_id")):
        op.create_index(f"ix_{table}_{field}", table, [field])

    def j(column, path, *, raw=False):
        if pg:
            return f"{column}::jsonb #{'>' if raw else '>>'} '{{{path}}}'"
        return f"json_extract({column},'$.{path.replace(',', '.')}')"
    def obj(column, path, keys):
        value = j(column, path, raw=True) if path else (f"{column}::jsonb" if pg else column)
        if pg:
            return f"(jsonb_typeof({value}) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys({value}))<>{len(keys)} OR EXISTS(SELECT 1 FROM jsonb_object_keys({value}) k WHERE k NOT IN ({','.join(repr(key) for key in keys)})))"
        location = "$." + path.replace(",", ".") if path else "$"
        return f"(json_type({column},'{location}') IS NOT 'object' OR (SELECT count(*) FROM json_each({value}))<>{len(keys)} OR EXISTS(SELECT 1 FROM json_each({value}) WHERE key NOT IN ({','.join(repr(key) for key in keys)})))"
    distinct = "IS DISTINCT FROM" if pg else "IS NOT"
    # Native JSON checks bind each side to actual append-only qualification
    # material and independently compare the normalized predicate/entity.
    shapes = [obj("NEW.snapshot", "", ("protocol", "material", "initiating_authority", "verification_basis", "physical_truth_automatically_verified", "authorizes_incident_closure")),
        obj("NEW.snapshot", "material", ("old", "new", "semantics", "entity")),
        obj("NEW.snapshot", "initiating_authority", ("permissions", "scope")),
        obj("NEW.snapshot", "material,semantics", ("event_type", "entity_type", "operator", "expected", "unit")),
        obj("NEW.snapshot", "material,entity", ("type", "id"))]
    for side in ("old", "new"):
        shapes.append(obj("NEW.snapshot", "material," + side,
            ("source_id", "qualification_request_id", "qualification_review_id", "baseline_receipt_id", "qualification_snapshot")))
    false_checks = ("NEW.snapshot::jsonb->'authorizes_incident_closure' IS DISTINCT FROM 'false'::jsonb OR NEW.snapshot::jsonb->'physical_truth_automatically_verified' IS DISTINCT FROM 'false'::jsonb" if pg else
        "json_type(NEW.snapshot,'$.authorizes_incident_closure') IS NOT 'false' OR json_type(NEW.snapshot,'$.physical_truth_automatically_verified') IS NOT 'false'")
    request_checks = [*shapes, false_checks,
        f"{j('NEW.snapshot','protocol')} {distinct} 'icheck.collector.source-replacement/v1'",
        f"{j('NEW.snapshot','verification_basis')} {distinct} 'peer_reviewed_external_attestation'",
        "length(NEW.snapshot::text)>524288" if pg else "length(NEW.snapshot)>524288",
        "NEW.expires_at>NEW.created_at+interval '30 days'" if pg else "julianday(NEW.expires_at)>julianday(NEW.created_at)+30",
        "NEW.evidence_environment NOT IN ('controlled_fixture','live_lab','production')",
        "length(NEW.request_key) NOT BETWEEN 8 AND 128", "length(NEW.validation_reference) NOT BETWEEN 10 AND 1024",
        "NOT EXISTS(SELECT 1 FROM control_plane_principals p WHERE p.id=NEW.author_principal_id AND p.subject=NEW.author_subject AND p.tenant_id=NEW.tenant_id AND p.enabled AND p.principal_type IN ('user','service'))"]
    permissions = j("NEW.snapshot", "initiating_authority,permissions", raw=True)
    if pg:
        request_checks.extend([
            f"jsonb_typeof({permissions}) IS DISTINCT FROM 'array' OR jsonb_array_length({permissions}) NOT BETWEEN 1 AND 128",
            f"EXISTS(SELECT 1 FROM jsonb_array_elements({permissions}) p WHERE jsonb_typeof(p) IS DISTINCT FROM 'string' OR length(p #>> '{{}}') NOT BETWEEN 1 AND 128)",
            f"(SELECT count(DISTINCT p) FROM jsonb_array_elements({permissions}) p)<>jsonb_array_length({permissions})",
            f"jsonb_typeof({j('NEW.snapshot','initiating_authority,scope',raw=True)}) IS DISTINCT FROM 'object'"])
    else:
        request_checks.extend([
            "json_type(NEW.snapshot,'$.initiating_authority.permissions') IS NOT 'array'",
            f"json_array_length({permissions}) NOT BETWEEN 1 AND 128",
            f"EXISTS(SELECT 1 FROM json_each({permissions}) WHERE type IS NOT 'text' OR length(value) NOT BETWEEN 1 AND 128)",
            f"(SELECT count(DISTINCT value) FROM json_each({permissions}))<>json_array_length({permissions})",
            "json_type(NEW.snapshot,'$.initiating_authority.scope') IS NOT 'object'"])
    for side in ("old", "new"):
        refchecks = [f"{j('NEW.snapshot', 'material,'+side+','+key, raw=key=='qualification_snapshot')} {distinct} {expression}" for key, expression in (
            ("source_id", "s.id"), ("qualification_request_id", "q.id"), ("qualification_review_id", "r.id"),
            ("baseline_receipt_id", "q.baseline_receipt_id"), ("qualification_snapshot", "q.snapshot::jsonb" if pg else "json(q.snapshot)"))]
        for key in ("event_type", "entity_type", "operator", "expected", "unit"):
            refchecks.append(f"{j('NEW.snapshot', 'material,semantics,'+key, raw=True)} {distinct} {j('s.context', 'definition,'+key, raw=True)}")
        refchecks.extend([f"{j('NEW.snapshot','material,entity,type')} {distinct} s.entity_type",
            f"{j('NEW.snapshot','material,entity,id')} {distinct} s.entity_id"])
        expiry = " OR NEW.created_at>=q.expires_at OR NEW.expires_at>q.expires_at" if side == "new" else ""
        request_checks.append(f"""NOT EXISTS(SELECT 1 FROM collector_source_qualification_reviews r
            JOIN collector_source_qualification_requests q ON q.id=r.request_id
            JOIN collector_condition_sources s ON s.id=q.source_id
            WHERE r.id=NEW.{side}_qualification_review_id AND s.id=NEW.{side}_source_id
            AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id
            AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id
            AND s.tenant_id=NEW.tenant_id AND s.region_id=NEW.region_id
            AND q.evidence_environment=NEW.evidence_environment
            AND NOT ({' OR '.join(refchecks)}{expiry})
            AND NOT EXISTS(SELECT 1 FROM collector_source_qualification_revocations x WHERE x.review_id=r.id))""")
    # Peer cannot attest their own replacement or either frozen Collector's
    # author/validator/publisher identity. Revocation remains possible without
    # fresh origin, original peers, material read or an unexpired proposal.
    actor_fields = [j("q.snapshot", f"material,{side},qualification_snapshot,version_actors,{key}")
        for side in ("old", "new") for key in ("created_by", "validated_by", "published_by")]
    review_checks = f"""length(NEW.acceptance_reference) NOT BETWEEN 10 AND 1024
        OR NOT EXISTS(SELECT 1 FROM {TABLES[0]} q JOIN control_plane_principals p ON p.id=NEW.reviewer_principal_id
            WHERE q.id=NEW.request_id AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id
            AND p.tenant_id=NEW.tenant_id AND p.subject=NEW.reviewer_subject AND p.enabled AND p.principal_type='user'
            AND p.id<>q.author_principal_id AND p.subject<>q.author_subject AND NEW.created_at<q.expires_at
            AND NOT EXISTS(SELECT 1 FROM collector_source_qualification_revocations x
                WHERE x.review_id IN (q.old_qualification_review_id,q.new_qualification_review_id))
            AND NOT ({' OR '.join('NEW.reviewer_subject '+('IS NOT DISTINCT FROM' if pg else 'IS')+' '+value for value in actor_fields)}))"""
    revoke_checks = f"""NOT EXISTS(SELECT 1 FROM {TABLES[1]} r JOIN control_plane_principals p ON p.id=NEW.principal_id
        WHERE r.id=NEW.review_id AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id
        AND p.tenant_id=NEW.tenant_id AND p.subject=NEW.subject AND p.enabled AND p.principal_type='user')"""
    for table, checks in zip(TABLES, (" OR ".join(request_checks), review_checks, revoke_checks)):
        checks += " OR length(NEW.reason) NOT BETWEEN 10 AND 512"
        if pg:
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)) WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"))
            op.execute(sa.text(f"""CREATE FUNCTION icheck_guard_{table}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Collector source replacement history is append-only'; END IF;
                IF {checks} THEN RAISE EXCEPTION 'Source replacement reference or attestation is invalid'; END IF;
                RETURN NEW; END; $$"""))
            op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table} BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_guard_{table}()"))
        else:
            op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table} BEFORE INSERT ON {table} WHEN {checks} BEGIN SELECT RAISE(ABORT,'Source replacement reference or attestation is invalid'); END"))
            for action in ("UPDATE", "DELETE"):
                op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'Collector source replacement history is append-only'); END"))


def downgrade():
    bind = op.get_bind()
    _visibility(bind, TABLES)
    for table in TABLES:
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Retain populated source replacement history; downgrade is refused")
    for table in reversed(TABLES):
        op.drop_table(table)
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(f"DROP FUNCTION icheck_guard_{table}()"))
