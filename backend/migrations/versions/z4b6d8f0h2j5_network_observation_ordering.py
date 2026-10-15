"""Source-local IP/attachment clocks without invented legacy observation bodies."""
from datetime import UTC
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision = "z4b6d8f0h2j5"
down_revision = "y3a5c7e9g1i4"
branch_labels = depends_on = None
TABLE = "network_observation_states"


def upgrade():
    bind = op.get_bind()
    tables = ("devices", "endpoints", "ip_address_observations", "endpoint_attachments",
        "collector_deployments", "collector_runs", "knowledge_projections", "agent_executions")
    if bind.dialect.name == "postgresql":
        for table in tables:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
                raise RuntimeError("Network inventory migration requires visibility of all namespaces")
        op.execute(sa.text("SET LOCAL lock_timeout='10s'"))
        op.execute(sa.text("LOCK TABLE "+", ".join(tables)+" IN SHARE ROW EXCLUSIVE MODE"))
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("Network inventory migration requires PostgreSQL or SQLite")
    for sql in (
        "SELECT 1 FROM collector_deployments WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collector_runs WHERE status='RUNNING' LIMIT 1",
        "SELECT 1 FROM knowledge_projections WHERE lease_worker_id IS NOT NULL OR lease_token_hash IS NOT NULL OR status='PROCESSING' LIMIT 1",
        "SELECT 1 FROM agent_executions WHERE lease_token_hash IS NOT NULL OR status='RUNNING' LIMIT 1",
    ):
        if bind.execute(sa.text(sql)).first():
            raise RuntimeError("Drain Collector, Projection and Agent producers before network inventory upgrade")
    for table in ("ip_address_observations", "endpoint_attachments"):
        if bind.execute(sa.text(f"""SELECT 1 FROM {table} x LEFT JOIN endpoints e ON e.id=x.endpoint_id
            LEFT JOIN devices d ON d.id=x.collector_device_id
            WHERE e.id IS NULL OR e.tenant_id<>x.tenant_id OR e.region_id<>x.region_id
            OR (x.collector_device_id IS NOT NULL AND (d.id IS NULL OR d.tenant_id<>x.tenant_id OR d.region_id<>x.region_id))
            OR x.first_seen>x.last_seen OR x.observed_at>x.last_seen LIMIT 1""")).first():
            raise RuntimeError("Reconcile legacy network references/clocks without deleting history before migration")
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("region_id", sa.String(36), nullable=False),
        sa.Column("endpoint_id", sa.String(36), sa.ForeignKey("endpoints.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("collector_device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("collector_key", sa.String(36), nullable=False), sa.Column("dimension", sa.String(16), nullable=False),
        sa.Column("state", sa.String(32), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.Text(), nullable=False), sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "endpoint_id", "source", "collector_key", "dimension", name="uq_network_observation_source_dimension"),
        sa.CheckConstraint("revision>0", name="ck_network_observation_revision"),
        sa.CheckConstraint("source IN ('ARP','MAC_TABLE','DHCP','MANUAL')", name="ck_network_observation_source"),
        sa.CheckConstraint("dimension IN ('metadata','ipv4','ipv6','attachment')", name="ck_network_observation_dimension"),
        sa.CheckConstraint("state IN ('unobserved','accepted','conflict','legacy_unknown')", name="ck_network_observation_state"),
        sa.CheckConstraint("(state='unobserved' AND observed_at IS NULL) OR (state<>'unobserved' AND observed_at IS NOT NULL)", name="ck_network_observation_time"),
        sa.CheckConstraint("length(payload)<=65536", name="ck_network_observation_payload_bound"),
        sa.CheckConstraint("(state IN ('accepted','conflict') AND length(payload)>0) OR (state IN ('unobserved','legacy_unknown') AND payload='')", name="ck_network_observation_payload_state"),
        sa.CheckConstraint("(collector_device_id IS NULL AND collector_key='unbound') OR (collector_device_id IS NOT NULL AND collector_key=collector_device_id)", name="ck_network_observation_collector_key"))
    for field in ("tenant_id", "region_id", "endpoint_id"):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    op.create_index("ix_network_observation_collector_source", TABLE, ["tenant_id", "region_id", "collector_key", "source"])
    # Read the known source clocks, including inactive history; do not invent
    # a last accepted body from the mutable current inventory.
    metadata = sa.MetaData()
    ips = sa.Table("ip_address_observations", metadata, autoload_with=bind)
    attachments = sa.Table("endpoint_attachments", metadata, autoload_with=bind)
    states = sa.Table(TABLE, metadata, autoload_with=bind)
    selects = []
    for model in (ips, attachments):
        clock = sa.case((model.c.last_seen > model.c.observed_at, model.c.last_seen), else_=model.c.observed_at)
        dimension = (sa.case((model.c.ip_address.contains(":"), "ipv6"), else_="ipv4") if model is ips else sa.literal("attachment"))
        columns = [model.c.tenant_id, model.c.region_id, model.c.endpoint_id, model.c.source, model.c.collector_device_id]
        for channel in (dimension, sa.literal("metadata")):
            selects.append(sa.select(*columns, channel.label("dimension"), clock.label("clock"))
                .where(model.c.source.in_(["ARP", "MAC_TABLE", "DHCP", "MANUAL"])))
    known = sa.union_all(*selects).subquery()
    columns = [known.c[name] for name in ("tenant_id", "region_id", "endpoint_id", "source", "collector_device_id", "dimension")]
    rows = bind.execute(sa.select(*columns, sa.func.max(known.c.clock).label("clock")).group_by(*columns)
        .execution_options(stream_results=True, yield_per=250)).mappings()
    for row in rows:
        stamp = row["clock"].replace(tzinfo=UTC) if row["clock"].tzinfo is None else row["clock"].astimezone(UTC)
        values = {key: row[key] for key in ("tenant_id", "region_id", "endpoint_id", "source", "collector_device_id", "dimension")}
        bind.execute(states.insert().values(**values, id=str(uuid4()), collector_key=row["collector_device_id"] or "unbound",
            state="legacy_unknown", observed_at=stamp, payload="", revision=1, created_at=stamp, updated_at=stamp))
    rows.close()
    op.create_index("ix_ip_observation_source_history", "ip_address_observations",
        ["tenant_id", "region_id", "endpoint_id", "source", "collector_device_id", "ip_address", "vlan_id", "last_seen"])
    op.create_index("ix_ip_observation_source_current", "ip_address_observations",
        ["tenant_id", "region_id", "endpoint_id", "source", "collector_device_id"], postgresql_where=sa.text("active"), sqlite_where=sa.text("active"))
    op.create_index("ix_attachment_source_current", "endpoint_attachments",
        ["tenant_id", "region_id", "endpoint_id", "source", "collector_device_id"], postgresql_where=sa.text("active"), sqlite_where=sa.text("active"))
    references = """NOT EXISTS(SELECT 1 FROM endpoints e WHERE e.id=NEW.endpoint_id AND e.tenant_id=NEW.tenant_id AND e.region_id=NEW.region_id)
        OR (NEW.collector_device_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM devices d WHERE d.id=NEW.collector_device_id
            AND d.tenant_id=NEW.tenant_id AND d.region_id=NEW.region_id))"""
    changed = """NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id OR NEW.region_id<>OLD.region_id
        OR NEW.endpoint_id<>OLD.endpoint_id OR NEW.source<>OLD.source OR NEW.collector_key<>OLD.collector_key
        OR NEW.collector_device_id IS DISTINCT FROM OLD.collector_device_id OR NEW.dimension<>OLD.dimension
        OR NEW.revision<>OLD.revision+1
        OR (OLD.observed_at IS NOT NULL AND (NEW.observed_at IS NULL OR NEW.observed_at<OLD.observed_at))
        OR (NEW.observed_at=OLD.observed_at AND NOT (OLD.state='accepted' AND NEW.state='conflict' AND NEW.payload=OLD.payload))"""
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"""CREATE POLICY icheck_namespace_isolation ON {TABLE}
            USING (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))
            WITH CHECK (tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true))"""))
        op.execute(sa.text(f"""CREATE FUNCTION icheck_guard_network_observation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Network observation watermarks cannot be deleted'; END IF;
            IF TG_OP='UPDATE' AND ({changed}) THEN RAISE EXCEPTION 'Network observation identity, revision or ordering has drifted'; END IF;
            IF {references} THEN RAISE EXCEPTION 'Network observation reference crosses namespace'; END IF;
            RETURN NEW; END; $$"""))
        op.execute(sa.text(f"CREATE TRIGGER icheck_guard_network_observation BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_guard_network_observation()"))
    else:
        changed = changed.replace("IS DISTINCT FROM", "IS NOT")
        op.execute(sa.text(f"CREATE TRIGGER icheck_network_observation_delete BEFORE DELETE ON {TABLE} BEGIN SELECT RAISE(ABORT,'Network observation watermarks cannot be deleted'); END"))
        op.execute(sa.text(f"""CREATE TRIGGER icheck_network_observation_update BEFORE UPDATE ON {TABLE} WHEN {changed}
            BEGIN SELECT RAISE(ABORT,'Network observation identity, revision or ordering has drifted'); END"""))
        for action in ("INSERT", "UPDATE"):
            op.execute(sa.text(f"""CREATE TRIGGER icheck_network_observation_reference_{action.lower()} BEFORE {action} ON {TABLE} WHEN {references}
                BEGIN SELECT RAISE(ABORT,'Network observation reference crosses namespace'); END"""))
            op.execute(sa.text(f"""CREATE TRIGGER icheck_network_observation_time_{action.lower()} BEFORE {action} ON {TABLE}
                WHEN NEW.observed_at IS NOT NULL AND (length(NEW.observed_at)<>26
                OR NEW.observed_at NOT GLOB '????-??-?? ??:??:??.??????' OR substr(NEW.observed_at,21,6) GLOB '*[^0-9]*'
                OR strftime('%Y-%m-%d %H:%M:%S',substr(NEW.observed_at,1,19)) IS NOT substr(NEW.observed_at,1,19))
                BEGIN SELECT RAISE(ABORT,'Network observation time must be canonical UTC'); END"""))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": TABLE}).scalar():
        raise RuntimeError("Network inventory downgrade requires visibility of all namespaces")
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade recorded network observation watermarks")
    op.drop_table(TABLE)
    op.drop_index("ix_ip_observation_source_history", table_name="ip_address_observations")
    op.drop_index("ix_ip_observation_source_current", table_name="ip_address_observations")
    op.drop_index("ix_attachment_source_current", table_name="endpoint_attachments")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_network_observation()"))
