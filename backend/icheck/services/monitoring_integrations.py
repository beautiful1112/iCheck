"""Protected connections and bounded inventory steps; no native enrollment."""
import base64
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..config import get_settings
from ..database import require_locking_transaction, validate_session_namespace
from ..integration_custody import decrypt_token, encrypt_token, IntegrationCustodyUnavailable
from ..integration_schemas import ConnectionTestResult, validate_basic
from ..models import (MonitoringIntegrationConnection as Connection, MonitoringIntegrationSync as Sync,
                      MonitoringIntegrationResource as Resource, MonitoringIntegrationSchedule as Schedule, new_id, utcnow)
from ..monitoring_connectors.contracts import ReadScope, SourceIdentity
from ..monitoring_connectors.https_transport import ZabbixHTTPSTransport, OrionHTTPSTransport, BridgeHTTPSTransport, approved_endpoint
from ..monitoring_connectors.zabbix import ConnectorError, ZabbixConnector
from ..monitoring_connectors.orion import OrionConnector
from ..monitoring_connectors.bridge import BridgeConnector
from .audit import record_audit_event
from .authorization_scope import has_global_scope, namespace_clause


TRANSPORT = ZabbixHTTPSTransport
ORION_TRANSPORT = OrionHTTPSTransport
BRIDGE_TRANSPORT = BridgeHTTPSTransport


class IntegrationConflict(ValueError):
    pass


def guard(db, principal, *, manage=False):
    permission = "metrics.manage" if manage else "metrics.read"
    if not principal.permits("metrics.read", permission) or not has_global_scope(principal):
        raise PermissionError("Integrations require workspace-wide " + permission + " permission")
    namespace = validate_session_namespace(db)
    if namespace != (principal.tenant_id, principal.region_id):
        raise PermissionError("Integration workspace does not match the authenticated namespace")
    development = (get_settings().control_plane_auth_mode == "disabled" and principal.subject == "development"
                   and principal.principal_type == "development" and principal.auth_method == "disabled")
    if manage and not development and (principal.principal_type != "user"
                                      or principal.auth_method not in {"browser_session", "bearer"}):
        raise PermissionError("Only a signed-in human can configure or test an integration")
    return namespace


def connection(db, identifier, principal, *, lock=False):
    guard(db, principal)
    query = select(Connection).where(Connection.id == identifier, namespace_clause(Connection, principal))
    if lock:
        require_locking_transaction(db, purpose="Integration revision guards")
        query = query.with_for_update().execution_options(populate_existing=True)
    row = db.scalar(query)
    if row is None:
        raise LookupError("Integration connection not found")
    return row


def listing(db, principal, *, limit=50, offset=0):
    guard(db, principal)
    return db.scalars(select(Connection).where(namespace_clause(Connection, principal))
                      .order_by(Connection.name, Connection.id).limit(limit).offset(offset)).all()


def audit(db, row, principal, event, details):
    record_audit_event(db, event_type="monitoring_integration." + event,
        actor_type=principal.principal_type, actor_id=principal.subject,
        entity_type=row.__tablename__, entity_id=row.id, details=details)


def _commit(db):
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise IntegrationConflict("An integration with this name already exists") from None


def create_connection(db, payload, principal):
    tenant, region = guard(db, principal, manage=True)
    endpoint = approved_endpoint(payload.api_url, payload.provider)
    token = credential_material(payload.provider, payload)
    if any(secret in field for secret in credential_secrets(payload.provider, token)
           for field in (payload.name, endpoint, *payload.group_ids)):
        raise ValueError("Tokens belong only in the protected token field")
    row = Connection(id=new_id(), tenant_id=tenant, region_id=region, name=payload.name,
                     provider=payload.provider, api_url=endpoint, group_ids=payload.group_ids,
                     enabled=False, revision=1, created_by=principal.subject)
    row.encrypted_token = encrypt_token(row, token)
    db.add(row)
    audit(db, row, principal, "created", {"provider": row.provider, "revision": 1, "enabled": False})
    _commit(db)
    return row


def credential_material(provider, payload):
    if provider == "solarwinds_orion":
        if payload.token is not None:
            raise ValueError("SolarWinds uses username/password authentication")
        validate_basic(payload.username, payload.password)
        return base64.b64encode((payload.username.get_secret_value() + ":" +
                                 payload.password.get_secret_value()).encode()).decode()
    if payload.username is not None or payload.password is not None or payload.token is None:
        raise ValueError("Use a token for this provider")
    return payload.token.get_secret_value()


def credential_secrets(provider, token):
    if provider == "solarwinds_orion":
        value = base64.b64decode(token, validate=True).decode()
        return [token, value, value.split(":", 1)[1]]
    return [token]


def _revision(row, expected):
    if row.revision != expected:
        raise IntegrationConflict("Connection changed; refresh before continuing")


def update_connection(db, identifier, payload, principal):
    guard(db, principal, manage=True)
    row = connection(db, identifier, principal, lock=True)
    _revision(row, payload.expected_revision)
    if payload.enabled and not (payload.group_ids or row.group_ids):
        raise ValueError("Select at least one source group before enabling")
    # Disabling is always possible without decrypting a token or contacting the
    # source. Rename/rotation inspect the secret to prevent plaintext reflection.
    rotating = any(value is not None for value in (payload.token, payload.username, payload.password))
    replacement = credential_material(row.provider, payload) if rotating else None
    if rotating or payload.name is not None or payload.group_ids is not None:
        tokens = []
        if payload.name is not None or payload.group_ids is not None:
            tokens.extend(credential_secrets(row.provider, decrypt_token(row)))
        if rotating:
            tokens.extend(credential_secrets(row.provider, replacement))
        fields = (payload.name or row.name, row.api_url, *(payload.group_ids or row.group_ids))
        if any(token in field for token in tokens for field in fields):
            raise ValueError("Tokens belong only in the protected token field")
        if rotating:
            row.encrypted_token = encrypt_token(row, replacement)
    if payload.name is not None:
        row.name = payload.name
    if payload.group_ids is not None:
        row.group_ids = payload.group_ids
    row.enabled = payload.enabled
    row.revision += 1
    from ..models import MonitoringIntegrationAlertFeed
    from .integration_alerts import stop_connection
    feed = db.scalar(select(MonitoringIntegrationAlertFeed).where(
        MonitoringIntegrationAlertFeed.connection_id == row.id, namespace_clause(MonitoringIntegrationAlertFeed, principal))
        .with_for_update().execution_options(populate_existing=True))
    if feed:
        feed.enabled, feed.next_run_at = False, None
        feed.revision += 1
        feed.last_error = "connection_changed"
        stop_connection(db, row, "External monitoring connection changed")
    row.last_test_status = row.last_test_error = row.last_test_at = row.last_test_revision = None
    for run in db.scalars(select(Sync).where(Sync.connection_id == row.id, namespace_clause(Sync, principal),
                                           Sync.status.in_(["in_progress", "failed"]))):
        run.status = "superseded"
        run.finished_at = run.updated_at = utcnow()
    schedule = db.scalar(select(Schedule).where(Schedule.connection_id == row.id, namespace_clause(Schedule, principal))
                         .with_for_update().execution_options(populate_existing=True))
    if schedule:
        schedule.enabled = False
        schedule.revision += 1
        schedule.next_run_at = schedule.lease_token = schedule.lease_expires_at = schedule.active_run_id = None
        schedule.last_error = "connection_changed"
        schedule.last_success_at = schedule.last_attempt_at = None
        schedule.failures = 0
        schedule.updated_at, schedule.updated_by = utcnow(), principal.subject
    audit(db, row, principal, "updated", {"revision": row.revision, "enabled": row.enabled,
          "token_rotated": rotating})
    _commit(db)
    return row


def test_connection(db, identifier, payload, principal):
    guard(db, principal, manage=True)
    # Serialize configuration changes against this bounded test. No unattended
    # job is launched; a disabled connection may be tested by explicit consent.
    row = connection(db, identifier, principal, lock=True)
    _revision(row, payload.expected_revision)
    selected = scope(row)
    result = ConnectionTestResult(connection_id=row.id, revision=row.revision,
                                  status="failed", checked_at=utcnow())
    try:
        batch = reader(row).discover_resources(selected)
        result.status = "succeeded"
        result.resource_count, result.truncated = len(batch.items), batch.truncated
    except ConnectorError as error:
        # Transport and adapter expose fixed codes only. Defense in depth against
        # a future connector accidentally returning raw upstream diagnostics.
        code = str(error)
        allowed = {"source_unavailable", "source_timeout", "source_tls_failed", "source_endpoint_not_approved",
                   "source_address_rejected", "source_http_rejected", "source_encoding_rejected",
                   "source_response_too_large", "source_secret_echo", "invalid_source_request",
                   "invalid_source_response", "unsupported_operation", "invalid_rpc_envelope",
                   "source_rejected_request", "unsupported_source_version", "duplicate_source_identity",
                   "source_scope_mismatch"}
        result.error_code = code if code in allowed else "source_unavailable"
    result.checked_at = utcnow()
    row.last_test_status, row.last_test_error = result.status, result.error_code
    row.last_test_at, row.last_test_revision = result.checked_at, row.revision
    audit(db, row, principal, "tested", {"revision": row.revision, "status": result.status,
          "error_code": result.error_code, "resource_count": result.resource_count, "truncated": result.truncated})
    _commit(db)
    return result


def reader(row):
    adapter, transport = {"zabbix": (ZabbixConnector, TRANSPORT),
        "solarwinds_orion": (OrionConnector, ORION_TRANSPORT),
        "rest_webhook": (BridgeConnector, BRIDGE_TRANSPORT)}[row.provider]
    return adapter(SourceIdentity(tenant_id=row.tenant_id, region_id=row.region_id,
        connection_id=row.id, provider=row.provider), transport(row.api_url, decrypt_token(row), budget_seconds=30))


def scope(row):
    if not row.group_ids:
        raise ValueError("Select at least one source group")
    return ReadScope(group_ids=tuple(row.group_ids), limit=20, timeout_seconds=10)


def safe_error(error):
    if isinstance(error, IntegrationCustodyUnavailable):
        return "credential_unavailable"
    code = str(error)
    return code if code in {"source_unavailable", "source_timeout", "source_tls_failed", "source_endpoint_not_approved",
        "source_address_rejected", "source_http_rejected", "source_encoding_rejected", "source_response_too_large",
        "source_secret_echo", "invalid_source_request", "invalid_source_response", "unsupported_operation",
        "invalid_rpc_envelope", "source_rejected_request", "unsupported_source_version", "duplicate_source_identity",
        "source_scope_mismatch", "source_scope_too_large"} else "source_unavailable"


def discover_groups(db, identifier, payload, principal):
    guard(db, principal, manage=True)
    row = connection(db, identifier, principal, lock=True)
    _revision(row, payload.expected_revision)
    # Group names are connection setup metadata, not unrestricted host discovery.
    token = decrypt_token(row)
    if any(secret in payload.search for secret in credential_secrets(row.provider, token)):
        raise ValueError("Tokens belong only in the protected token field")
    result = reader(row).discover_groups(payload.search.strip())
    audit(db, row, principal, "groups_discovered", {"revision": row.revision, "count": len(result["items"])})
    db.commit()
    return result


def preview(db, identifier, payload, principal):
    guard(db, principal, manage=True)
    row = connection(db, identifier, principal, lock=True)
    _revision(row, payload.expected_revision)
    selected = scope(row)
    batch = reader(row).discover_resources(selected)
    audit(db, row, principal, "previewed", {"revision": row.revision, "count": len(batch.items), "truncated": batch.truncated})
    db.commit()
    return batch


def sync_history(db, identifier, principal):
    connection(db, identifier, principal)
    return db.scalars(select(Sync).where(Sync.connection_id == identifier, namespace_clause(Sync, principal))
                      .order_by(Sync.started_at.desc(), Sync.id.desc()).limit(20)).all()


def start_sync(db, identifier, payload, principal):
    guard(db, principal, manage=True)
    row = connection(db, identifier, principal, lock=True)
    _revision(row, payload.expected_revision)
    if not row.enabled:
        raise IntegrationConflict("Enable the connection before synchronizing")
    _manual_only(db, row, principal)
    run = _start_locked(db, row, principal)
    db.commit()
    return run


def _manual_only(db, row, principal):
    schedule = db.scalar(select(Schedule).where(Schedule.connection_id == row.id, namespace_clause(Schedule, principal)))
    if schedule and schedule.enabled:
        raise IntegrationConflict("Automatic sync is enabled; pause its schedule before a manual sync")


def _start_locked(db, row, principal):
    """Caller owns the connection lock, authorization and transaction."""
    selected = scope(row)
    latest = db.scalar(select(Sync).where(Sync.connection_id == row.id, namespace_clause(Sync, principal))
                       .order_by(Sync.started_at.desc(), Sync.id.desc()).limit(1))
    if latest and latest.can_resume and latest.connection_revision == row.revision:
        return latest  # A lost response or double click does not start a second scan.
    run = Sync(id=new_id(), tenant_id=row.tenant_id, region_id=row.region_id, connection_id=row.id,
        connection_revision=row.revision, status="in_progress", cursor=0, observed=0, total=0,
        created_by=principal.subject)
    try:
        run.host_ids = reader(row).resource_manifest(selected)
        run.total = len(run.host_ids)
        if not run.total:
            run.status, run.finished_at = "completed", utcnow()
    except (ConnectorError, IntegrationCustodyUnavailable) as error:
        run.status, run.error_code = "failed", safe_error(error)
    db.add(run)
    audit(db, row, principal, "sync_started", {"run_id": run.id, "revision": row.revision,
        "status": run.status, "total": run.total, "error_code": run.error_code})
    db.flush()
    return run


def sync_step(db, identifier, run_id, payload, principal):
    guard(db, principal, manage=True)
    row = connection(db, identifier, principal, lock=True)
    _revision(row, payload.expected_revision)
    if not row.enabled:
        raise IntegrationConflict("Connection is disabled")
    _manual_only(db, row, principal)
    run = _step_locked(db, row, run_id, payload.expected_cursor, principal)
    db.commit()  # Imported rows and cursor advance are one atomic transaction.
    return run


def _step_locked(db, row, run_id, expected_cursor, principal):
    """Caller owns the connection lock, authorization and transaction."""
    run = db.scalar(select(Sync).where(Sync.id == run_id, Sync.connection_id == row.id,
        namespace_clause(Sync, principal)).execution_options(populate_existing=True).with_for_update())
    if run is None:
        raise LookupError("Synchronization not found")
    if (run.connection_revision != row.revision or not run.can_resume or run.cursor != expected_cursor):
        raise IntegrationConflict("Synchronization changed; refresh before resuming")
    ids = run.host_ids[run.cursor:run.cursor + 250]
    try:
        batch = reader(row).read_resource_batch(scope(row), ids)
    except (ConnectorError, IntegrationCustodyUnavailable) as error:
        run.status, run.error_code = "failed", safe_error(error)
    else:
        existing = {item.remote_id: item for item in db.scalars(select(Resource).where(
            Resource.connection_id == row.id, namespace_clause(Resource, principal), Resource.remote_id.in_(ids)))}
        for observation in batch.items:
            item = existing.get(observation.ref.remote_id)
            if item is None:
                item = Resource(id=new_id(), tenant_id=row.tenant_id, region_id=row.region_id,
                    connection_id=row.id, remote_id=observation.ref.remote_id)
                db.add(item)
            item.name, item.monitoring_enabled = observation.name, observation.monitoring_enabled
            item.observed_at, item.last_run_id, item.connection_revision = batch.fetched_at, run.id, row.revision
        run.cursor += len(ids)
        run.observed += len(batch.items)
        run.error_code = None
        run.status = "completed" if run.cursor == run.total else "in_progress"
        if run.status == "completed":
            run.finished_at = utcnow()
        # Missing IDs are intentionally not deleted, resolved or marked healthy.
    run.updated_at = utcnow()
    audit(db, row, principal, "sync_step", {"run_id": run.id, "cursor": run.cursor, "observed": run.observed,
        "status": run.status, "error_code": run.error_code})
    db.flush()
    return run


def resources(db, identifier, principal, *, offset=0, limit=50, search=""):
    row = connection(db, identifier, principal)
    from sqlalchemy import func
    query = select(Resource).where(Resource.connection_id == row.id, namespace_clause(Resource, principal),
                                   Resource.connection_revision == row.revision)
    if search:
        query = query.where(Resource.name.icontains(search, autoescape=True))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    items = db.scalars(query.order_by(Resource.name, Resource.remote_id).offset(offset).limit(limit)).all()
    from ..integration_schemas import ImportedResourceRead
    return {"items": [ImportedResourceRead.model_validate(item) for item in items], "total": total,
            "offset": offset, "limit": limit, "connection_revision": row.revision,
            "boundary": "Source inventory only; no native polling, canonical asset mapping or device-health claim"}
