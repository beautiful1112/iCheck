"""Reusable reviewed recovery criteria; no backfill or closure authority."""
from alembic import op
import sqlalchemy as sa

revision = "b6d8f0h2j4l7"
down_revision = "a5c7e9g1i3k6"
branch_labels = depends_on = None
TABLES = ("situation_recovery_policy_requests", "situation_recovery_policy_reviews",
    "situation_recovery_policy_revocations")


def columns():
    return [sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("region_id", sa.String(36), nullable=False)]


def ref(name, table):
    return sa.Column(name, sa.String(36), sa.ForeignKey(table + ".id", ondelete="RESTRICT"), nullable=False)


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name not in {"postgresql", "sqlite"}:
        raise RuntimeError("Situation recovery policies require PostgreSQL or SQLite")
    op.create_table(TABLES[0], *columns(),
        sa.Column("request_key", sa.String(128), nullable=False), sa.Column("name", sa.String(128), nullable=False),
        sa.Column("source_bindings", sa.JSON(), nullable=False), sa.Column("evidence_environment", sa.String(32), nullable=False),
        *[sa.Column(key, sa.Integer(), nullable=False) for key in
            ("min_quiet_samples", "min_quiet_seconds", "max_sample_gap_seconds", "max_age_seconds")],
        ref("author_principal_id", "control_plane_principals"), sa.Column("author_subject", sa.String(255), nullable=False),
        sa.Column("validation_reference", sa.String(1024), nullable=False), sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "request_key", name="uq_situation_recovery_policy_key"),
        sa.CheckConstraint("expires_at > created_at", name="ck_situation_recovery_policy_lifetime"),
        *[sa.CheckConstraint(f"{key} BETWEEN {low} AND {high}", name=f"ck_situation_recovery_policy_{name}")
            for key, low, high, name in (("min_quiet_samples", 2, 128, "samples"),
                ("min_quiet_seconds", 1, 86400, "duration"), ("max_sample_gap_seconds", 1, 86400, "gap"),
                ("max_age_seconds", 1, 86400, "age"))])
    op.create_table(TABLES[1], *columns(), ref("request_id", TABLES[0]),
        ref("reviewer_principal_id", "control_plane_principals"), sa.Column("reviewer_subject", sa.String(255), nullable=False),
        sa.Column("acceptance_reference", sa.String(1024), nullable=False), sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("request_id", name="uq_situation_recovery_policy_review"))
    op.create_table(TABLES[2], *columns(), ref("review_id", TABLES[1]),
        ref("principal_id", "control_plane_principals"), sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("review_id", name="uq_situation_recovery_policy_revocation"))
    for table in TABLES:
        for column in ("tenant_id", "region_id"):
            op.create_index(f"ix_{table}_{column}", table, [column])
    for table, column in ((TABLES[1], "request_id"), (TABLES[2], "review_id")):
        op.create_index(f"ix_{table}_{column}", table, [column])

    if bind.dialect.name == "postgresql":
        rows = "jsonb_array_elements(NEW.source_bindings::jsonb) AS entry(value)"
        field = lambda key: f"entry.value->>'{key}'"
        json_check = f"""jsonb_typeof(NEW.source_bindings::jsonb)<>'array'
            OR jsonb_array_length(NEW.source_bindings::jsonb) NOT BETWEEN 1 AND 64
            OR EXISTS(SELECT 1 FROM {rows} WHERE jsonb_typeof(entry.value)<>'object'
                OR (SELECT count(*) FROM jsonb_object_keys(entry.value))<>2
                OR jsonb_typeof(entry.value->'source_id') IS DISTINCT FROM 'string'
                OR jsonb_typeof(entry.value->'qualification_review_id') IS DISTINCT FROM 'string')
            OR (SELECT count(DISTINCT {field('source_id')}) FROM {rows})<>jsonb_array_length(NEW.source_bindings::jsonb)"""
        lifetime = "NEW.expires_at>NEW.created_at+interval '30 days'"
    else:
        rows = "json_each(NEW.source_bindings) AS entry"
        field = lambda key: f"json_extract(entry.value,'$.{key}')"
        json_check = f"""json_type(NEW.source_bindings) IS NOT 'array'
            OR json_array_length(NEW.source_bindings) NOT BETWEEN 1 AND 64
            OR EXISTS(SELECT 1 FROM {rows} WHERE entry.type IS NOT 'object'
                OR (SELECT count(*) FROM json_each(entry.value))<>2
                OR json_type(entry.value,'$.source_id') IS NOT 'text'
                OR json_type(entry.value,'$.qualification_review_id') IS NOT 'text')
            OR (SELECT count(DISTINCT {field('source_id')}) FROM {rows})<>json_array_length(NEW.source_bindings)"""
        lifetime = "julianday(NEW.expires_at)>julianday(NEW.created_at)+30"
    source_refs = f"""EXISTS(SELECT 1 FROM {rows}
        LEFT JOIN collector_source_qualification_reviews r ON r.id={field('qualification_review_id')}
            AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id
        LEFT JOIN collector_source_qualification_requests q ON q.id=r.request_id
            AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id
        LEFT JOIN collector_condition_sources s ON s.id=q.source_id
            AND s.tenant_id=NEW.tenant_id AND s.region_id=NEW.region_id
        WHERE r.id IS NULL OR q.id IS NULL OR s.id IS NULL OR s.id<>{field('source_id')}
            OR NEW.evidence_environment<>q.evidence_environment OR NEW.expires_at>q.expires_at
            OR NEW.created_at>=q.expires_at OR EXISTS(SELECT 1 FROM collector_source_qualification_revocations x WHERE x.review_id=r.id))"""
    checks = {
        TABLES[0]: f"""({json_check}) OR ({source_refs}) OR ({lifetime})
            OR NEW.evidence_environment NOT IN ('controlled_fixture','live_lab','production')
            OR length(NEW.request_key) NOT BETWEEN 8 AND 128 OR length(NEW.name) NOT BETWEEN 3 AND 128
            OR length(NEW.validation_reference) NOT BETWEEN 10 AND 1024
            OR NOT EXISTS(SELECT 1 FROM control_plane_principals p WHERE p.id=NEW.author_principal_id
                AND p.subject=NEW.author_subject AND p.tenant_id=NEW.tenant_id AND p.enabled AND p.principal_type='user')""",
        TABLES[1]: f"""length(NEW.acceptance_reference) NOT BETWEEN 10 AND 1024
            OR NOT EXISTS(SELECT 1 FROM {TABLES[0]} q JOIN control_plane_principals p ON p.id=NEW.reviewer_principal_id
                WHERE q.id=NEW.request_id AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id
                AND p.tenant_id=NEW.tenant_id AND p.subject=NEW.reviewer_subject AND p.enabled AND p.principal_type='user'
                AND p.id<>q.author_principal_id AND p.subject<>q.author_subject AND NEW.created_at<q.expires_at)""",
        TABLES[2]: f"""NOT EXISTS(SELECT 1 FROM {TABLES[1]} r JOIN control_plane_principals p ON p.id=NEW.principal_id
                WHERE r.id=NEW.review_id AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id
                AND p.tenant_id=NEW.tenant_id AND p.subject=NEW.subject AND p.enabled AND p.principal_type='user')""",
    }
    for table in TABLES:
        checks[table] += " OR length(NEW.reason) NOT BETWEEN 10 AND 512"
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"""CREATE POLICY icheck_namespace_isolation ON {table}
                USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))
                WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"""))
            op.execute(sa.text(f"""CREATE FUNCTION icheck_guard_{table}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Situation recovery policy history is append-only'; END IF;
                IF {checks[table]} THEN RAISE EXCEPTION 'Situation recovery policy reference or criteria are invalid'; END IF;
                RETURN NEW; END; $$"""))
            op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table} BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_guard_{table}()"))
        else:
            op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table} BEFORE INSERT ON {table} WHEN {checks[table]} BEGIN SELECT RAISE(ABORT,'Situation recovery policy reference or criteria are invalid'); END"))
            for action in ("UPDATE", "DELETE"):
                op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'Situation recovery policy history is append-only'); END"))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in TABLES:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Recovery policy downgrade requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE " + ", ".join(TABLES) + " IN ACCESS EXCLUSIVE MODE"))
    for table in TABLES:
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Retain populated Situation recovery policy history; downgrade is refused")
    for table in reversed(TABLES):
        op.drop_table(table)
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(f"DROP FUNCTION icheck_guard_{table}()"))
