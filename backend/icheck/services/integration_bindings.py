"""Reviewed local identity mapping, never enrollment or remote execution authority."""
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from ..models import (Device, MonitoringIntegrationBinding as Binding,
                      MonitoringIntegrationResource as Resource, MonitoringIntegrationSync as Sync, utcnow)
from . import monitoring_integrations as integrations
from .authorization_scope import namespace_clause


def guard(db, actor, *, manage=False):
    integrations.guard(db, actor, manage=manage)
    permissions = ("assets.read", "assets.write") if manage else ("assets.read",)
    if not actor.permits(*permissions):
        raise PermissionError("Asset mapping requires assets.read" + (" and assets.write" if manage else ""))


def latest_scan(db, row):
    return db.scalar(select(Sync).where(Sync.connection_id == row.id,
        Sync.tenant_id == row.tenant_id, Sync.region_id == row.region_id,
        Sync.connection_revision == row.revision).order_by(Sync.started_at.desc(), Sync.id.desc()).limit(1))


def device_read(device):
    return {"id": device.id, "name": device.name, "management_ip": device.management_ip, "site": device.site,
            "revision": device.revision, "identity_revision": device.identity_revision, "enabled": device.enabled}


def binding_state(row, resource, binding, device, scan):
    if binding is None or binding.device_id is None:
        return "unlinked", None
    checks = [
        (not row.enabled, "connection_disabled"),
        (binding.connection_revision != row.revision, "connection_changed"),
        (resource.connection_revision != row.revision, "source_scope_unconfirmed"),
        (scan is None or scan.status != "completed", "complete_inventory_sync_required"),
        (scan is not None and resource.last_run_id != scan.id, "not_seen_in_latest_scan"),
        (binding.source_name != resource.name, "source_name_changed"),
        (device is None or not device.enabled, "asset_unavailable"),
        (device is not None and binding.device_identity_revision != device.identity_revision, "asset_identity_changed"),
    ]
    reason = next((reason for failed, reason in checks if failed), None)
    return ("needs_review", reason) if reason else ("linked", None)


def listing(db, identifier, actor, *, offset=0, limit=100):
    guard(db, actor)
    row = integrations.connection(db, identifier, actor)
    scan = latest_scan(db, row)
    # Include previously linked resources after a scope change so their review
    # state and unlink action remain visible, without claiming current scope.
    query = select(Resource, Binding, Device).outerjoin(Binding,
        (Binding.resource_id == Resource.id) & namespace_clause(Binding, actor)).outerjoin(Device,
        (Device.id == Binding.device_id) & namespace_clause(Device, actor)).where(
        Resource.connection_id == row.id, namespace_clause(Resource, actor),
        (Resource.connection_revision == row.revision) | Binding.device_id.is_not(None))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    page = db.execute(query.order_by(Resource.name, Resource.id).offset(offset).limit(limit)).all()
    names = {resource.name for resource, _, _ in page}
    # Exact names are suggestions, not trusted identities. Duplicate source
    # names anywhere in the current scope cannot be bulk-suggested, even if only
    # one of those rows appears on this page. No IP or substring guessing.
    duplicates = dict(db.execute(select(Resource.name, func.count()).where(
        Resource.connection_id == row.id, Resource.connection_revision == row.revision,
        namespace_clause(Resource, actor), Resource.name.in_(names)).group_by(Resource.name)).all())
    candidates = {}
    for device in db.scalars(select(Device).where(namespace_clause(Device, actor),
            Device.enabled.is_(True), Device.name.in_(names))):
        candidates.setdefault(device.name, []).append(device)
    occupied = set(db.scalars(select(Binding.device_id).where(Binding.connection_id == row.id,
        namespace_clause(Binding, actor), Binding.device_id.is_not(None))))
    items = []
    for resource, binding, device in page:
        state, reason = binding_state(row, resource, binding, device, scan)
        current = bool(row.enabled and scan and scan.status == "completed"
                       and resource.last_run_id == scan.id and resource.connection_revision == row.revision)
        suggestions = candidates.get(resource.name, [])
        suggestion = None
        match = "not_current" if not current else "no_match"
        if current and state == "unlinked":
            if duplicates.get(resource.name, 0) > 1 or len(suggestions) > 1:
                match = "ambiguous"
            elif suggestions:
                if suggestions[0].id in occupied:
                    match = "asset_already_linked"
                else:
                    match, suggestion = "exact_name", device_read(suggestions[0])
        elif state != "unlinked":
            match = "already_linked"
        items.append({"resource_id": resource.id, "remote_id": resource.remote_id, "name": resource.name,
            "observed_at": resource.observed_at, "current": current,
            "binding_revision": binding.revision if binding else 0, "state": state, "reason": reason,
            "device": device_read(device) if device else None, "suggestion": suggestion, "match": match,
            "reviewed_at": binding.reviewed_at if binding else None})
    return {"items": items, "total": total, "offset": offset, "limit": limit,
            "connection_revision": row.revision, "scan_id": scan.id if scan else None,
            "can_link": bool(row.enabled and scan and scan.status == "completed"),
            "boundary": "Reviewed identity links only; no asset creation, polling or investigation authority"}


def search_assets(db, identifier, actor, *, search, limit=20):
    guard(db, actor)
    integrations.connection(db, identifier, actor)
    if not search.strip():
        return {"items": [], "truncated": False}
    from sqlalchemy import or_
    query = select(Device).where(namespace_clause(Device, actor), Device.enabled.is_(True),
        or_(Device.name.icontains(search.strip(), autoescape=True),
            Device.management_ip.icontains(search.strip(), autoescape=True))).order_by(Device.name, Device.id).limit(limit + 1)
    rows = db.scalars(query).all()
    return {"items": [device_read(device) for device in rows[:limit]], "truncated": len(rows) > limit}


def update(db, identifier, payload, actor):
    guard(db, actor, manage=True)
    row = integrations.connection(db, identifier, actor, lock=True)
    integrations._revision(row, payload.expected_revision)
    scan = latest_scan(db, row)
    linking = any(item.device_id is not None for item in payload.items)
    if linking and (not row.enabled or scan is None or scan.status != "completed"
                    or scan.id != str(payload.expected_scan_id)):
        raise integrations.IntegrationConflict("Refresh asset mapping after a completed inventory sync")
    ids = [str(item.resource_id) for item in payload.items]
    resources = {resource.id: resource for resource in db.scalars(select(Resource).where(
        Resource.id.in_(ids), Resource.connection_id == row.id, namespace_clause(Resource, actor)))}
    bindings = {binding.resource_id: binding for binding in db.scalars(select(Binding).where(
        Binding.resource_id.in_(ids), Binding.connection_id == row.id, namespace_clause(Binding, actor)))}
    device_ids = sorted(str(item.device_id) for item in payload.items if item.device_id is not None)
    # Hold selected identities through approval. Connection locking serializes
    # sync, scope changes and other mapping batches; device locks fence corrections.
    devices = {device.id: device for device in db.scalars(select(Device).where(
        Device.id.in_(device_ids), namespace_clause(Device, actor)).order_by(Device.id)
        .with_for_update().execution_options(populate_existing=True))}
    occupied = {binding.device_id: binding.resource_id for binding in db.scalars(select(Binding).where(
        Binding.connection_id == row.id, namespace_clause(Binding, actor), Binding.device_id.in_(device_ids)))}
    # Validate the entire batch before changing any row. Swaps require explicit
    # unlinking first; a bulk request cannot silently steal another resource's link.
    for item in payload.items:
        resource = resources.get(str(item.resource_id))
        binding = bindings.get(str(item.resource_id))
        if resource is None:
            raise LookupError("Source resource not found")
        if (binding.revision if binding else 0) != item.expected_binding_revision or resource.name != item.source_name:
            raise integrations.IntegrationConflict("Resource or mapping changed; refresh before approving")
        if item.device_id is None:
            continue
        if resource.connection_revision != row.revision or resource.last_run_id != scan.id:
            raise integrations.IntegrationConflict("Source resource was not observed in the reviewed scan")
        device = devices.get(str(item.device_id))
        if device is None or not device.enabled:
            raise LookupError("Enabled asset not found")
        if (device.revision != item.expected_device_revision
                or device.identity_revision != item.expected_device_identity_revision):
            raise integrations.IntegrationConflict("Asset changed; review its identity again")
        if device.id in occupied and occupied[device.id] != resource.id:
            raise integrations.IntegrationConflict("Asset is already linked in this connection; unlink it first")
    for item in payload.items:
        resource = resources[str(item.resource_id)]
        binding = bindings.get(resource.id)
        if binding is None:
            binding = Binding(resource_id=resource.id, connection_id=row.id, tenant_id=row.tenant_id,
                              region_id=row.region_id, revision=0)
            db.add(binding)
        previous = binding.device_id
        binding.device_id = str(item.device_id) if item.device_id else None
        binding.device_identity_revision = item.expected_device_identity_revision
        binding.revision += 1
        binding.connection_revision, binding.source_name = row.revision, resource.name
        binding.reviewed_at, binding.reviewed_by = utcnow(), actor.subject
        integrations.audit(db, row, actor, "asset_binding_reviewed", {"resource_id": resource.id,
            "remote_id": resource.remote_id, "previous_device_id": previous, "device_id": binding.device_id,
            "binding_revision": binding.revision, "connection_revision": row.revision})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise integrations.IntegrationConflict("Mapping changed concurrently; refresh before approving") from None
    return {"updated": len(payload.items), "linked": len(device_ids), "unlinked": len(payload.items) - len(device_ids)}
