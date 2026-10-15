"""Append-only source peer acceptance; no existing source or closure rewrite."""
from alembic import op
import sqlalchemy as sa

revision = "a5c7e9g1i3k6"
down_revision = "z4b6d8f0h2j5"
branch_labels = depends_on = None
TABLES = ("collector_source_qualification_requests", "collector_source_qualification_reviews",
    "collector_source_qualification_revocations")


def columns():
    return [sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("region_id", sa.String(36), nullable=False)]


def ref(name, target):
    return sa.Column(name, sa.String(36), sa.ForeignKey(target+".id", ondelete="RESTRICT"), nullable=False)


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name not in {"postgresql", "sqlite"}:
        raise RuntimeError("Source qualification requires PostgreSQL or SQLite")
    # Additive ledger: no alteration/backfill of Collector producers. Source
    # clocks and legacy non-independent receipts retain their original meaning.
    op.create_table(TABLES[0], *columns(), ref("source_id", "collector_condition_sources"),
        ref("baseline_receipt_id", "collector_condition_receipts"),
        ref("author_principal_id", "control_plane_principals"),
        sa.Column("author_subject", sa.String(255), nullable=False),
        sa.Column("request_key", sa.String(128), nullable=False),
        sa.Column("evidence_environment", sa.String(32), nullable=False),
        sa.Column("validation_reference", sa.String(1024), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False), sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "source_id", "request_key", name="uq_source_qualification_request_key"),
        sa.CheckConstraint("expires_at > created_at", name="ck_source_qualification_request_lifetime"))
    op.create_table(TABLES[1], *columns(), ref("request_id", TABLES[0]),
        ref("reviewer_principal_id", "control_plane_principals"),
        sa.Column("reviewer_subject", sa.String(255), nullable=False),
        sa.Column("acceptance_reference", sa.String(1024), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("request_id", name="uq_source_qualification_review_request"))
    op.create_table(TABLES[2], *columns(), ref("review_id", TABLES[1]),
        ref("principal_id", "control_plane_principals"), sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("review_id", name="uq_source_qualification_revocation_review"))
    for table, field in zip(TABLES, ("source_id", "request_id", "review_id")):
        for name in ("tenant_id", "region_id", field):
            op.create_index(f"ix_{table}_{name}", table, [name])

    references = {
        TABLES[0]: """NOT EXISTS(SELECT 1 FROM collector_condition_sources s
            JOIN collector_condition_receipts r ON r.id=NEW.baseline_receipt_id
            JOIN collector_condition_admissions a ON a.id=r.admission_id
            JOIN control_plane_principals p ON p.id=NEW.author_principal_id
            WHERE s.id=NEW.source_id AND r.source_id=s.id AND r.disposition='accepted'
            AND r.verdict IN ('active','quiet') AND r.observed_at<=NEW.created_at
            AND p.subject=NEW.author_subject AND p.principal_type='user' AND p.enabled
            AND s.tenant_id=NEW.tenant_id AND s.region_id=NEW.region_id
            AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id
            AND a.tenant_id=NEW.tenant_id AND a.region_id=NEW.region_id AND p.tenant_id=NEW.tenant_id)""",
        TABLES[1]: f"""NOT EXISTS(SELECT 1 FROM {TABLES[0]} q
            JOIN control_plane_principals p ON p.id=NEW.reviewer_principal_id
            WHERE q.id=NEW.request_id AND q.tenant_id=NEW.tenant_id AND q.region_id=NEW.region_id
            AND p.tenant_id=NEW.tenant_id AND p.subject=NEW.reviewer_subject AND p.principal_type='user' AND p.enabled
            AND p.id<>q.author_principal_id AND p.subject<>q.author_subject AND NEW.created_at<q.expires_at)""",
        TABLES[2]: f"""NOT EXISTS(SELECT 1 FROM {TABLES[1]} r
            JOIN control_plane_principals p ON p.id=NEW.principal_id
            WHERE r.id=NEW.review_id AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id
            AND p.tenant_id=NEW.tenant_id AND p.subject=NEW.subject AND p.principal_type='user' AND p.enabled)""",
    }
    if bind.dialect.name == "postgresql":
        refs = lambda column, path: f"{column}::jsonb #>> '{{{path}}}'"
        extra_request = f"""jsonb_typeof(NEW.snapshot::jsonb)<>'object'
            OR (SELECT count(*) FROM jsonb_object_keys(NEW.snapshot::jsonb))<>7
            OR EXISTS(SELECT 1 FROM jsonb_object_keys(NEW.snapshot::jsonb) key WHERE key NOT IN
                ('pins','worker_auth_method','worker_mtls_mode','version_actors','verification_basis',
                'physical_truth_automatically_verified','authorizes_incident_closure'))
            OR COALESCE({refs('NEW.snapshot','worker_mtls_mode')},'') NOT IN ('disabled','optional','required')
            OR NEW.snapshot::jsonb->'authorizes_incident_closure' IS DISTINCT FROM 'false'::jsonb
            OR NEW.snapshot::jsonb->'physical_truth_automatically_verified' IS DISTINCT FROM 'false'::jsonb
            OR {refs('NEW.snapshot','verification_basis')} IS DISTINCT FROM 'peer_reviewed_external_attestation'
            OR NOT EXISTS(SELECT 1 FROM collector_condition_receipts r
                JOIN collector_condition_admissions a ON a.id=r.admission_id
                JOIN artifact_versions v ON v.id=a.artifact_version_id
                WHERE r.id=NEW.baseline_receipt_id AND NEW.snapshot::jsonb->'pins'=a.context::jsonb->'pins'
                AND {refs('NEW.snapshot','worker_auth_method')}={refs('a.context','worker_auth_method')}
                AND {refs('NEW.snapshot','version_actors,created_by')} IS NOT DISTINCT FROM v.created_by
                AND {refs('NEW.snapshot','version_actors,validated_by')} IS NOT DISTINCT FROM v.validated_by
                AND {refs('NEW.snapshot','version_actors,published_by')} IS NOT DISTINCT FROM v.published_by)
            OR (NEW.evidence_environment='production' AND
                ({refs('NEW.snapshot','worker_auth_method')} IS DISTINCT FROM 'bearer+verified_proxy_mtls'
                OR {refs('NEW.snapshot','worker_mtls_mode')} IS NOT DISTINCT FROM 'disabled'))
            OR length(NEW.snapshot::text)>131072 OR NEW.expires_at>NEW.created_at+interval '30 days'"""
        extra_review = f"""EXISTS(SELECT 1 FROM {TABLES[0]} q WHERE q.id=NEW.request_id
            AND NEW.reviewer_subject IN ({refs('q.snapshot','version_actors,created_by')},
                {refs('q.snapshot','version_actors,validated_by')}, {refs('q.snapshot','version_actors,published_by')}))"""
    else:
        refs = lambda column, path: f"json_extract({column},'$.{path.replace(',', '.')}')"
        extra_request = f"""json_type(NEW.snapshot) IS NOT 'object'
            OR (SELECT count(*) FROM json_each(NEW.snapshot))<>7
            OR EXISTS(SELECT 1 FROM json_each(NEW.snapshot) WHERE key NOT IN
                ('pins','worker_auth_method','worker_mtls_mode','version_actors','verification_basis',
                'physical_truth_automatically_verified','authorizes_incident_closure'))
            OR COALESCE({refs('NEW.snapshot','worker_mtls_mode')},'') NOT IN ('disabled','optional','required')
            OR json_type(NEW.snapshot,'$.authorizes_incident_closure') IS NOT 'false'
            OR json_type(NEW.snapshot,'$.physical_truth_automatically_verified') IS NOT 'false'
            OR {refs('NEW.snapshot','verification_basis')} IS NOT 'peer_reviewed_external_attestation'
            OR NOT EXISTS(SELECT 1 FROM collector_condition_receipts r
                JOIN collector_condition_admissions a ON a.id=r.admission_id
                JOIN artifact_versions v ON v.id=a.artifact_version_id
                WHERE r.id=NEW.baseline_receipt_id AND {refs('NEW.snapshot','pins')} IS {refs('a.context','pins')}
                AND {refs('NEW.snapshot','worker_auth_method')} IS {refs('a.context','worker_auth_method')}
                AND {refs('NEW.snapshot','version_actors,created_by')} IS v.created_by
                AND {refs('NEW.snapshot','version_actors,validated_by')} IS v.validated_by
                AND {refs('NEW.snapshot','version_actors,published_by')} IS v.published_by)
            OR (NEW.evidence_environment='production' AND
                ({refs('NEW.snapshot','worker_auth_method')} IS NOT 'bearer+verified_proxy_mtls'
                OR {refs('NEW.snapshot','worker_mtls_mode')} IS 'disabled'))
            OR length(NEW.snapshot)>131072 OR julianday(NEW.expires_at)>julianday(NEW.created_at)+30"""
        extra_review = f"""EXISTS(SELECT 1 FROM {TABLES[0]} q WHERE q.id=NEW.request_id
            AND NEW.reviewer_subject IN ({refs('q.snapshot','version_actors,created_by')},
                {refs('q.snapshot','version_actors,validated_by')}, {refs('q.snapshot','version_actors,published_by')}))"""
    checks = dict(references)
    checks[TABLES[0]] += f""" OR ({extra_request})
        OR NEW.evidence_environment NOT IN ('controlled_fixture','live_lab','production')
        OR length(NEW.validation_reference) NOT BETWEEN 10 AND 1024
        OR length(NEW.request_key) NOT BETWEEN 8 AND 128"""
    checks[TABLES[1]] += f" OR ({extra_review}) OR length(NEW.acceptance_reference) NOT BETWEEN 10 AND 1024"
    for table in TABLES:
        checks[table] += " OR length(NEW.reason) NOT BETWEEN 10 AND 512"
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"""CREATE POLICY icheck_namespace_isolation ON {table}
                USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))
                WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"""))
            op.execute(sa.text(f"""CREATE FUNCTION icheck_guard_{table}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Source qualification history is append-only'; END IF;
                IF {checks[table]} THEN RAISE EXCEPTION 'Source qualification reference or attestation is invalid'; END IF;
                RETURN NEW; END; $$"""))
            op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table} BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION icheck_guard_{table}()"))
        else:
            op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table} BEFORE INSERT ON {table} WHEN {checks[table]} BEGIN SELECT RAISE(ABORT,'Source qualification reference or attestation is invalid'); END"))
            for action in ("UPDATE", "DELETE"):
                op.execute(sa.text(f"CREATE TRIGGER icheck_guard_{table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'Source qualification history is append-only'); END"))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in TABLES:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Source qualification downgrade requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE "+", ".join(TABLES)+" IN ACCESS EXCLUSIVE MODE"))
    for table in TABLES:
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Retain populated source qualification history; downgrade is refused")
    for table in reversed(TABLES):
        op.drop_table(table)
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(f"DROP FUNCTION icheck_guard_{table}()"))
