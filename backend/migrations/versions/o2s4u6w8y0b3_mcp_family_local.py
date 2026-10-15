"""Retain exact-family local execution, human mutation admission and receipts."""
from alembic import op
import sqlalchemy as sa

revision = "o2s4u6w8y0b3"
down_revision = "n1r3u5w7y9a2"
branch_labels = depends_on = None
EXECUTION = "mcp_oauth_family_local_executions"
MUTATION = "mcp_oauth_family_local_mutations"
CONSENT = "mcp_oauth_consent_attempts"
FAMILY = "mcp_oauth_family_recoveries"


def _visible(*tables):
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in tables:
            if bind.scalar(sa.text("SELECT row_security_active(:table)"), {"table": table}) is not False:
                raise RuntimeError("Local family migration requires actual all-namespace visibility")
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("Local family custody requires PostgreSQL or SQLite")
    return bind


def upgrade():
    bind = _visible(CONSENT, FAMILY)
    op.add_column(CONSENT, sa.Column("family_contained_at", sa.DateTime(timezone=True), nullable=True))
    namespace = lambda: [
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002")]
    op.create_table(EXECUTION,
        sa.Column("id", sa.String(32), primary_key=True), *namespace(),
        sa.Column("recovery_id", sa.String(32), sa.ForeignKey(FAMILY + ".id", ondelete="RESTRICT"), nullable=False),
        sa.Column("plan", sa.JSON(), nullable=False), sa.Column("proof", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("admitted_by", sa.String(36), nullable=False),
        sa.Column("auth_method", sa.String(32), nullable=False),
        sa.Column("credential_id", sa.String(36), nullable=False),
        sa.Column("admitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("receipt", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("deleted_versions", sa.JSON(), nullable=False),
        sa.Column("completion", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "region_id", "recovery_id", name="uq_mcp_family_local_recovery"),
        sa.CheckConstraint("status IN ('admitted','fenced','complete')", name="ck_mcp_family_local_status"),
        sa.CheckConstraint("auth_method IN ('bearer','browser_session')", name="ck_mcp_family_local_human"),
        sa.CheckConstraint("(status='admitted' AND receipt IS NULL AND completion IS NULL AND completed_at IS NULL) OR (status='fenced' AND receipt IS NOT NULL AND completion IS NULL AND completed_at IS NULL) OR (status='complete' AND receipt IS NOT NULL AND completion IS NOT NULL AND completed_at IS NOT NULL)", name="ck_mcp_family_local_receipts"),
    )
    op.create_table(MUTATION,
        sa.Column("id", sa.String(36), primary_key=True), *namespace(),
        sa.Column("execution_id", sa.String(32), sa.ForeignKey(EXECUTION + ".id", ondelete="RESTRICT"), nullable=False),
        sa.Column("phase", sa.String(24), nullable=False), sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("authorized_by", sa.String(36), nullable=False),
        sa.Column("auth_method", sa.String(32), nullable=False), sa.Column("credential_id", sa.String(36), nullable=False),
        sa.Column("admitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("phase IN ('reserve','delete_version','restore','delete_reservation')", name="ck_mcp_family_mutation_phase"),
        sa.CheckConstraint("version BETWEEN 0 AND 2147483647", name="ck_mcp_family_mutation_version"),
        sa.CheckConstraint("auth_method IN ('bearer','browser_session')", name="ck_mcp_family_mutation_human"),
    )
    op.create_index("ix_mcp_oauth_family_local_mutations_execution_id", MUTATION, ["execution_id"])
    if bind.dialect.name != "postgresql":
        return
    for table in (EXECUTION, MUTATION):
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})"))
    op.execute(sa.text("""CREATE FUNCTION icheck_family_local_human(who text, method text, credential text, tid text, rid text)
    RETURNS boolean LANGUAGE plpgsql AS $$
    DECLARE expires timestamptz; browser record;
    BEGIN
      PERFORM 1 FROM tenants WHERE id=tid FOR SHARE;
      PERFORM 1 FROM regions WHERE id=rid AND tenant_id=tid FOR SHARE;
      PERFORM 1 FROM control_plane_principals WHERE id=who FOR SHARE;
      IF method='bearer' THEN
        SELECT expires_at INTO expires FROM control_plane_access_tokens WHERE id=credential
          AND principal_id=who AND tenant_id=tid AND revoked_at IS NULL AND workload_identity_id IS NULL FOR SHARE;
      ELSIF method='browser_session' THEN
        SELECT * INTO browser FROM control_plane_browser_sessions WHERE id=credential;
        IF browser.auth_source='oidc' THEN
          PERFORM 1 FROM control_plane_oidc_identities WHERE id=browser.federated_identity_id FOR SHARE;
          IF NOT EXISTS (SELECT 1 FROM control_plane_oidc_identities WHERE id=browser.federated_identity_id
            AND enabled AND principal_id=who AND tenant_id=tid) THEN RETURN false; END IF;
        ELSIF browser.auth_source='trusted_proxy' THEN
          PERFORM 1 FROM control_plane_trusted_proxy_identities WHERE id=browser.federated_identity_id FOR SHARE;
          IF NOT EXISTS (SELECT 1 FROM control_plane_trusted_proxy_identities WHERE id=browser.federated_identity_id
            AND enabled AND principal_id=who AND tenant_id=tid) THEN RETURN false; END IF;
        ELSIF browser.auth_source<>'local_token' OR browser.federated_identity_id IS NOT NULL THEN RETURN false;
        END IF;
        SELECT expires_at INTO expires FROM control_plane_browser_sessions WHERE id=credential
          AND principal_id=who AND tenant_id=tid AND revoked_at IS NULL
          AND auth_source=browser.auth_source AND federated_identity_id IS NOT DISTINCT FROM browser.federated_identity_id FOR SHARE;
      ELSE RETURN false;
      END IF;
      PERFORM 1 FROM control_plane_roles r WHERE EXISTS (SELECT 1 FROM control_plane_role_bindings b
        WHERE b.role_id=r.id AND b.principal_id=who AND b.tenant_id=tid AND b.region_id=rid) ORDER BY r.id FOR SHARE;
      PERFORM 1 FROM control_plane_role_bindings WHERE principal_id=who AND tenant_id=tid AND region_id=rid ORDER BY id FOR SHARE;
      RETURN expires IS NOT NULL AND expires>clock_timestamp()
        AND EXISTS (SELECT 1 FROM tenants WHERE id=tid AND enabled)
        AND EXISTS (SELECT 1 FROM regions WHERE id=rid AND tenant_id=tid AND enabled)
        AND EXISTS (SELECT 1 FROM control_plane_principals WHERE id=who AND enabled AND principal_type='user'
          AND tenant_id=tid AND jsonb_typeof(allowed_region_ids::jsonb)='array'
          AND (allowed_region_ids::jsonb='[]'::jsonb OR allowed_region_ids::jsonb ? rid))
        AND EXISTS (SELECT 1 FROM control_plane_role_bindings b JOIN control_plane_roles r ON r.id=b.role_id
          WHERE b.principal_id=who AND b.tenant_id=tid AND b.region_id=rid AND b.scope::jsonb->'all'='true'::jsonb
            AND (r.system OR (r.tenant_id=tid AND r.region_id=rid)) AND jsonb_typeof(r.permissions::jsonb)='array'
            AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(r.permissions::jsonb) item WHERE jsonb_typeof(item)<>'string')
            AND jsonb_typeof(b.scope::jsonb)='object'
            AND jsonb_typeof(coalesce(b.scope::jsonb->'sites','[]'::jsonb))='array'
            AND jsonb_typeof(coalesce(b.scope::jsonb->'device_ids','[]'::jsonb))='array')
        AND NOT EXISTS (SELECT 1 FROM unnest(ARRAY['tools.admin','changes.approve']) permission
          WHERE NOT EXISTS (SELECT 1 FROM control_plane_role_bindings b JOIN control_plane_roles r ON r.id=b.role_id
            WHERE b.principal_id=who AND b.tenant_id=tid AND b.region_id=rid
              AND (r.system OR (r.tenant_id=tid AND r.region_id=rid)) AND jsonb_typeof(r.permissions::jsonb)='array'
              AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(r.permissions::jsonb) item WHERE jsonb_typeof(item)<>'string')
              AND jsonb_typeof(b.scope::jsonb)='object'
              AND jsonb_typeof(coalesce(b.scope::jsonb->'sites','[]'::jsonb))='array'
              AND jsonb_typeof(coalesce(b.scope::jsonb->'device_ids','[]'::jsonb))='array'
              AND r.permissions::jsonb ? permission));
    END $$"""))
    op.execute(sa.text(f"""CREATE FUNCTION icheck_family_local_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE p jsonb; q jsonb; f jsonb; scope jsonb; allowed jsonb; head bigint; source bigint; mode text;
    BEGIN
      IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Local family custody cannot be deleted'; END IF;
      p:=NEW.plan::jsonb; q:=NEW.receipt::jsonb; f:=NEW.completion::jsonb; mode:=p->>'mode';
      IF TG_OP='INSERT' THEN
        IF NEW.status<>'admitted' OR NEW.deleted_versions::jsonb<>'[]'::jsonb
          OR NOT icheck_family_local_human(NEW.admitted_by,NEW.auth_method,NEW.credential_id,NEW.tenant_id,NEW.region_id)
        THEN RAISE EXCEPTION 'Local plan requires current independent human authority'; END IF;
        SELECT jsonb_build_object('recovery_id',r.id,'attempt_id',c.id,'generation',c.generation,
          'locator',r.snapshot::jsonb->'locator','issuer',c.issuer,'client_id',c.client_id,'resource',c.resource,
          'target',c.target::jsonb,'historical',c.status IN ('superseded','revoked'),
          'vault_address',r.snapshot::jsonb->'consent'->'vault_address',
          'vault_namespace',r.snapshot::jsonb->'consent'->'vault_namespace',
          'secret_ref',r.snapshot::jsonb->'consent'->'token_profile'->'secret_ref') INTO scope
          FROM {FAMILY} r JOIN {CONSENT} c ON c.id=r.attempt_id
          WHERE r.id=NEW.recovery_id AND r.status='issuer_verified' AND c.family_recovery_id=r.id
            AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id
            AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id
            AND NEW.proof::jsonb=r.proof::jsonb AND NEW.admitted_by<>r.initiated_by;
        IF (scope IS NULL OR p->'scope' IS DISTINCT FROM scope OR p->>'plan_id'<>NEW.id
          OR NEW.id!~'^[0-9a-f]{{32}}$' OR p->'format_version'<>'1'::jsonb
          OR NOT (p ?& ARRAY['format_version','plan_id','scope','mode','head_version','head_generation','owned_versions','allow_late_publish'])
          OR p-ARRAY['format_version','plan_id','scope','mode','head_version','head_generation','owned_versions','allow_late_publish']<>'{{}}'::jsonb
          OR mode NOT IN ('preserve_previous','reserve_empty','retire_head','retired_elsewhere')
          OR jsonb_typeof(p->'head_version')<>'number' OR (p->>'head_version')!~'^[0-9]+$'
          OR jsonb_typeof(p->'allow_late_publish')<>'boolean'
          OR jsonb_typeof(p->'owned_versions')<>'array' OR jsonb_array_length(p->'owned_versions')>256) IS NOT FALSE
        THEN RAISE EXCEPTION 'Local plan differs from exact original proof and target'; END IF;
        head:=(p->>'head_version')::bigint;
        IF (head<(scope->'target'->>'vault_version')::bigint OR head>2147483645
          OR (mode='preserve_previous' AND (scope->'historical'='true'::jsonb OR scope->'target'->'present'<>'true'::jsonb))
          OR (mode='reserve_empty' AND (scope->'historical'='true'::jsonb OR scope->'target'->'present'<>'false'::jsonb))
          OR (mode='retire_head' AND scope->'historical'<>'true'::jsonb)
          OR (mode='retired_elsewhere' AND (head<=(scope->'target'->>'vault_version')::bigint OR p->'head_generation'=scope->'generation'))
          OR (p->'allow_late_publish'='true'::jsonb AND (head<>(scope->'target'->>'vault_version')::bigint
            OR mode NOT IN ('preserve_previous','reserve_empty') OR (mode='preserve_previous' AND head>2147483644)))
          OR EXISTS (SELECT 1 FROM jsonb_array_elements(p->'owned_versions') v WHERE jsonb_typeof(v)<>'number'
            OR v::text!~'^[0-9]+$' OR (v::text)::bigint NOT BETWEEN 1 AND head)
          OR p->'owned_versions' IS DISTINCT FROM (SELECT coalesce(jsonb_agg(v ORDER BY v),'[]'::jsonb)
            FROM (SELECT DISTINCT v FROM jsonb_array_elements(p->'owned_versions') v) inventory)) IS NOT FALSE
        THEN RAISE EXCEPTION 'Local plan has invalid mode or bounded version inventory'; END IF;
      ELSE
        IF ROW(NEW.id,NEW.tenant_id,NEW.region_id,NEW.recovery_id,NEW.plan::jsonb,NEW.proof::jsonb,
          NEW.admitted_by,NEW.auth_method,NEW.credential_id,NEW.admitted_at)
          IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.region_id,OLD.recovery_id,OLD.plan::jsonb,OLD.proof::jsonb,
          OLD.admitted_by,OLD.auth_method,OLD.credential_id,OLD.admitted_at)
        THEN RAISE EXCEPTION 'Original local plan and proof custody is immutable'; END IF;
        IF OLD.receipt IS NOT NULL AND q IS DISTINCT FROM OLD.receipt::jsonb
        THEN RAISE EXCEPTION 'Owned local fence receipt is immutable'; END IF;
        IF OLD.status='complete' AND ROW(NEW.status,NEW.deleted_versions::jsonb,f,NEW.completed_at)
          IS DISTINCT FROM ROW(OLD.status,OLD.deleted_versions::jsonb,OLD.completion::jsonb,OLD.completed_at)
        THEN RAISE EXCEPTION 'Completed local receipt is immutable'; END IF;
        IF (OLD.status='fenced' AND NEW.status='admitted') OR NOT (NEW.deleted_versions::jsonb @> OLD.deleted_versions::jsonb)
        THEN RAISE EXCEPTION 'Local operation custody cannot regress'; END IF;
      END IF;
      IF q IS NOT NULL THEN
        head:=(p->>'head_version')::bigint; source:=(q->>'source_version')::bigint;
        allowed:=p->'owned_versions';
        IF p->'allow_late_publish'='true'::jsonb AND source=head+1 THEN allowed:=allowed||jsonb_build_array(source); END IF;
        IF (q->>'plan_id'<>NEW.id OR q->>'recovery_id'<>NEW.recovery_id OR q->>'mode'<>mode
          OR jsonb_typeof(q->'source_version')<>'number' OR (q->>'source_version')!~'^[0-9]+$'
          OR jsonb_typeof(q->'fence_version')<>'number' OR (q->>'fence_version')!~'^[0-9]+$'
          OR source NOT BETWEEN 0 AND 2147483646 OR (q->>'fence_version')::bigint NOT BETWEEN 1 AND 2147483647
          OR q->'owned_versions' IS DISTINCT FROM allowed
          OR (source<>head AND NOT (p->'allow_late_publish'='true'::jsonb AND source=head+1))
          OR (mode='retired_elsewhere' AND (q->'reservation_version'<>'null'::jsonb OR (q->>'fence_version')::bigint<>source))
          OR (mode<>'retired_elsewhere' AND (jsonb_typeof(q->'reservation_version')<>'number'
            OR (q->>'reservation_version')!~'^[0-9]+$' OR (q->>'reservation_version')::bigint<>source+1
            OR (q->>'fence_version')::bigint<>source+1 OR NOT EXISTS (SELECT 1 FROM {MUTATION} m
              WHERE m.execution_id=NEW.id AND m.phase='reserve' AND m.version=source
                AND m.tenant_id=NEW.tenant_id AND m.region_id=NEW.region_id)))
          OR NOT (q ?& ARRAY['plan_id','recovery_id','mode','source_version','fence_version','reservation_version','owned_versions'])
          OR q-ARRAY['plan_id','recovery_id','mode','source_version','fence_version','reservation_version','owned_versions']<>'{{}}'::jsonb) IS NOT FALSE
        THEN RAISE EXCEPTION 'Local fence lacks exact plan and admitted mutation custody'; END IF;
        IF mode IN ('reserve_empty','retire_head') THEN allowed:=allowed||jsonb_build_array((q->>'reservation_version')::bigint); END IF;
      ELSE allowed:='[]'::jsonb;
      END IF;
      IF jsonb_typeof(NEW.deleted_versions::jsonb)<>'array' OR NOT (allowed @> NEW.deleted_versions::jsonb)
        OR NEW.deleted_versions::jsonb IS DISTINCT FROM (SELECT coalesce(jsonb_agg(v ORDER BY v),'[]'::jsonb)
          FROM (SELECT DISTINCT v FROM jsonb_array_elements(NEW.deleted_versions::jsonb) v) inventory)
      THEN RAISE EXCEPTION 'Local deletion receipts exceed the reviewed family'; END IF;
      IF f IS NOT NULL THEN
        IF (f->>'plan_id'<>NEW.id OR f->>'recovery_id'<>NEW.recovery_id
          OR jsonb_typeof(f->'head_version')<>'number' OR (f->>'head_version')!~'^[0-9]+$'
          OR (f->>'head_version')::bigint NOT BETWEEN 1 AND 2147483647
          OR NEW.completed_at IS NULL OR NEW.completed_at<NEW.admitted_at
          OR f->'fence_version' IS DISTINCT FROM q->'fence_version'
          OR (f->>'head_version')::bigint<(q->>'fence_version')::bigint
          OR f->'deleted_versions' IS DISTINCT FROM NEW.deleted_versions::jsonb
          OR NOT (f->'deleted_versions' @> allowed)
          OR f->'restored_previous' IS DISTINCT FROM to_jsonb(mode='preserve_previous')
          OR (mode='preserve_previous' AND ((f->>'head_version')::bigint<>(q->>'reservation_version')::bigint+1
            OR jsonb_typeof(f->'previous_expires_at')<>'string'
            OR (f->>'previous_expires_at')!~'[Tt].*([Zz]|[+-][0-9]{{2}}:[0-9]{{2}})$'
            OR NOT EXISTS (SELECT 1 FROM {MUTATION} m
              WHERE m.execution_id=NEW.id AND m.phase='restore' AND m.version=(q->>'reservation_version')::bigint
                AND m.tenant_id=NEW.tenant_id AND m.region_id=NEW.region_id)))
          OR (mode<>'preserve_previous' AND f->'previous_expires_at'<>'null'::jsonb)
          OR NOT (f ?& ARRAY['plan_id','recovery_id','fence_version','head_version','restored_previous','previous_expires_at','deleted_versions'])
          OR f-ARRAY['plan_id','recovery_id','fence_version','head_version','restored_previous','previous_expires_at','deleted_versions']<>'{{}}'::jsonb) IS NOT FALSE
        THEN RAISE EXCEPTION 'Local completion lacks exact owned operation receipts'; END IF;
      END IF;
      RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_family_local_guard BEFORE INSERT OR UPDATE OR DELETE ON {EXECUTION} FOR EACH ROW EXECUTE FUNCTION icheck_family_local_guard()"))
    op.execute(sa.text(f"""CREATE FUNCTION icheck_family_mutation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Local mutation admissions are immutable'; END IF;
      IF NOT icheck_family_local_human(NEW.authorized_by,NEW.auth_method,NEW.credential_id,NEW.tenant_id,NEW.region_id)
        OR NOT EXISTS (SELECT 1 FROM {EXECUTION} e JOIN {FAMILY} r ON r.id=e.recovery_id
          WHERE e.id=NEW.execution_id AND e.status<>'complete' AND NEW.authorized_by<>r.initiated_by
            AND e.tenant_id=NEW.tenant_id AND e.region_id=NEW.region_id
            AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id AND r.status='issuer_verified'
            AND ((NEW.phase='reserve' AND e.receipt IS NULL AND (NEW.version=(e.plan::jsonb->>'head_version')::bigint
              OR (e.plan::jsonb->'allow_late_publish'='true'::jsonb AND NEW.version=(e.plan::jsonb->>'head_version')::bigint+1)))
              OR (NEW.phase='delete_version' AND e.receipt::jsonb->'owned_versions' @> jsonb_build_array(NEW.version))
              OR (NEW.phase='restore' AND e.plan::jsonb->>'mode'='preserve_previous'
                AND NEW.version=(e.receipt::jsonb->>'reservation_version')::bigint)
              OR (NEW.phase='delete_reservation' AND e.plan::jsonb->>'mode' IN ('reserve_empty','retire_head')
                AND NEW.version=(e.receipt::jsonb->>'reservation_version')::bigint)))
      THEN RAISE EXCEPTION 'Local mutation lacks current human authority and exact admitted plan'; END IF;
      RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_family_mutation_guard BEFORE INSERT OR UPDATE OR DELETE ON {MUTATION} FOR EACH ROW EXECUTE FUNCTION icheck_family_mutation_guard()"))
    op.execute(sa.text(f"""CREATE FUNCTION icheck_family_contained_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP='INSERT' AND NEW.family_contained_at IS NOT NULL
      THEN RAISE EXCEPTION 'Local containment must finish retained consent custody'; END IF;
      IF TG_OP='UPDATE' THEN
        IF OLD.family_contained_at IS NOT NULL AND NEW.family_contained_at IS DISTINCT FROM OLD.family_contained_at
        THEN RAISE EXCEPTION 'Retained family containment receipt is immutable'; END IF;
        IF NEW.family_contained_at IS NOT NULL AND NOT EXISTS (
          SELECT 1 FROM {EXECUTION} e JOIN {FAMILY} r ON r.id=e.recovery_id
          WHERE r.id=NEW.family_recovery_id AND r.attempt_id=NEW.id AND r.generation=NEW.generation
            AND r.status='issuer_verified' AND e.status='complete' AND e.completed_at=NEW.family_contained_at
            AND e.tenant_id=NEW.tenant_id AND e.region_id=NEW.region_id
            AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id)
        THEN RAISE EXCEPTION 'Consent containment requires retained exact local completion'; END IF;
      END IF;
      RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_family_contained_guard BEFORE INSERT OR UPDATE ON {CONSENT} FOR EACH ROW EXECUTE FUNCTION icheck_family_contained_guard()"))


def downgrade():
    bind = _visible(CONSENT, FAMILY, EXECUTION, MUTATION)
    if (bind.execute(sa.text(f"SELECT 1 FROM {EXECUTION} LIMIT 1")).first()
            or bind.execute(sa.text(f"SELECT 1 FROM {MUTATION} LIMIT 1")).first()
            or bind.execute(sa.text(f"SELECT 1 FROM {CONSENT} WHERE family_contained_at IS NOT NULL LIMIT 1")).first()):
        raise RuntimeError("Retained local family custody prevents downgrade")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER icheck_family_contained_guard ON {CONSENT}"))
        op.execute(sa.text("DROP FUNCTION icheck_family_contained_guard()"))
    op.drop_table(MUTATION); op.drop_table(EXECUTION)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_family_mutation_guard()"))
        op.execute(sa.text("DROP FUNCTION icheck_family_local_guard()"))
        op.execute(sa.text("DROP FUNCTION icheck_family_local_human(text,text,text,text,text)"))
    op.drop_column(CONSENT, "family_contained_at")
