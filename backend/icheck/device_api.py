from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import Field
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, selectinload

from .auth import require_permissions
from .database import get_db
from .device_schemas import (
    DeviceConnectionPreflightRead,
    DeviceNativeSSHCreate,
    DeviceIdentityCorrectionCommit,
    DeviceIdentityCorrectionInput,
    DeviceIdentityCorrectionPreview,
    DeviceMetadataUpdate,
    DeviceConnectionStateChange,
    DeviceSNMPConfigurationUpdate,
    DeviceHTTPConfigurationUpdate,
    HTTPRequestPreview,
    DeviceOnboardCreate,
    DeviceOnboardPage,
    DeviceOnboardRead,
    DeviceHealthPage,
    AssetCategory,
    DevicePreflightAssignment,
    DevicePreflightClaim,
    DevicePreflightComplete,
    DeviceVerificationRetry,
)
from .models import (
    CollectorWorker,
    Device,
    DeviceConnection,
    DeviceConnectionPreflight,
)
from .services.devices import (
    claim_device_preflights,
    complete_device_preflight,
    get_onboarded_device,
    onboard_device,
    add_native_ssh_connection,
    retry_device_connection,
    update_device_metadata,
    set_device_connection_enabled,
    update_snmp_configuration,
    update_http_configuration,
)
from .services.device_identity_correction import (
    IdentityCorrectionConflict,
    commit_device_identity_correction,
    preview_device_identity_correction,
)
from .services.authorization_scope import (
    device_scope_clause,
    request_actor,
    require_device_access,
    require_site_access,
)
from .services.control_plane_auth import PrincipalContext
from .worker_auth import WorkerAuthenticationError, authenticate_worker


router = APIRouter(prefix="/api/v1/assets", tags=["assets"])
worker_router = APIRouter(prefix="/api/v1", tags=["device-preflight"])


db_session = get_db


def _worker(db: Session, worker_id: str) -> CollectorWorker:
    worker = db.get(CollectorWorker, worker_id)
    if worker is None:
        raise HTTPException(status_code=404, detail="Collector worker not found")
    return worker


def _authorize_worker(
    worker: CollectorWorker,
    authorization: str | None,
) -> None:
    try:
        authenticate_worker(worker, authorization)
    except WorkerAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.post(
    "/devices",
    response_model=DeviceOnboardRead,
    status_code=status.HTTP_201_CREATED,
)
def onboard_device_route(
    payload: DeviceOnboardCreate,
    principal: PrincipalContext = Depends(require_permissions("assets.write")),
    db: Session = Depends(db_session),
) -> Device:
    require_site_access(principal, payload.site)
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return onboard_device(db, trusted_payload)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


def _device_inventory_query(
    principal: PrincipalContext,
    search: str | None,
    kind: str | None,
    site: str | None,
    onboarding_status: str | None,
    category: str | None = None,
):
    query = select(Device).where(device_scope_clause(principal)).options(
        selectinload(Device.connections).selectinload(
            DeviceConnection.activations
        )
    )
    if search:
        escaped = (
            search.strip()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        value = f"%{escaped}%"
        query = query.where(
            or_(
                Device.name.ilike(value, escape="\\"),
                Device.management_ip.ilike(value, escape="\\"),
                Device.kind.ilike(value, escape="\\"),
                Device.site.ilike(value, escape="\\"),
                Device.vendor.ilike(value, escape="\\"),
                Device.model.ilike(value, escape="\\"),
                Device.connections.any(and_(DeviceConnection.protocol == "snmp",
                    DeviceConnection.enabled.is_(True), DeviceConnection.verification_status == "verified",
                    DeviceConnection.last_verification_evidence["target_host"].as_string() == Device.management_ip,
                    DeviceConnection.last_verification_evidence["identity_revision"].as_integer() == Device.identity_revision,
                    DeviceConnection.last_verification_evidence["discovered_name"].as_string().ilike(value, escape="\\"))),
            )
        )
    if kind:
        query = query.where(Device.kind == kind)
    if site:
        query = query.where(Device.site == site)
    if onboarding_status:
        query = query.where(Device.onboarding_status == onboarding_status)
    if category:
        from .services.asset_health import category_clause
        query = query.where(category_clause(category))
    return query


def _device_page_fingerprint(
    principal: PrincipalContext,
    filters: tuple[str | None, ...],
) -> str:
    context = json.dumps(
        [
            principal.tenant_id,
            principal.region_id,
            principal.subject,
            principal.authorization_scope,
            filters,
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(context.encode("utf-8")).hexdigest()


def _encode_device_cursor(fingerprint: str, device: Device) -> str:
    payload = json.dumps(
        [1, fingerprint, device.name, device.id],
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_device_cursor(cursor: str, fingerprint: str) -> tuple[str, str]:
    try:
        raw = base64.b64decode(
            cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
        )
        value = json.loads(raw)
        if (
            not isinstance(value, list)
            or len(value) != 4
            or value[0] != 1
            or value[1] != fingerprint
            or not isinstance(value[2], str)
            or not 1 <= len(value[2]) <= 255
            or not isinstance(value[3], str)
            or str(UUID(value[3])) != value[3]
        ):
            raise ValueError("invalid cursor")
    except (binascii.Error, UnicodeDecodeError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=422, detail="Invalid device page cursor"
        ) from exc
    return value[2], value[3]


@router.get("/devices/page", response_model=DeviceOnboardPage)
def page_onboarded_devices(
    search: str | None = Query(default=None, max_length=255),
    kind: str | None = Query(default=None, max_length=64),
    site: str | None = Query(default=None, max_length=128),
    onboarding_status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, min_length=1, max_length=4096),
    principal: PrincipalContext = Depends(require_permissions("assets.read")),
    db: Session = Depends(db_session),
    category: AssetCategory | None = None,
) -> DeviceOnboardPage:
    normalized_search = search.strip() if search else None
    filters = (normalized_search, kind, site, onboarding_status, category)
    fingerprint = _device_page_fingerprint(principal, filters)
    query = _device_inventory_query(principal, *filters)
    if cursor:
        last_name, last_id = _decode_device_cursor(cursor, fingerprint)
        query = query.where(
            or_(
                Device.name > last_name,
                and_(Device.name == last_name, Device.id > last_id),
            )
        )
    rows = list(
        db.scalars(query.order_by(Device.name, Device.id).limit(limit + 1)).all()
    )
    has_more = len(rows) > limit
    items = rows[:limit]
    return DeviceOnboardPage(
        items=items,
        next_cursor=(
            _encode_device_cursor(fingerprint, items[-1]) if has_more else None
        ),
    )


@router.get("/devices/summary")
def summarize_device_inventory(principal: PrincipalContext = Depends(require_permissions("assets.read")),
    db: Session = Depends(db_session)):
    from .services.asset_health import asset_summary
    return asset_summary(db, principal)


@router.get("/devices/health", response_model=DeviceHealthPage)
def read_device_health(response: Response,
    device_ids: Annotated[list[Annotated[str, Field(min_length=1, max_length=36, pattern=r"^[A-Za-z0-9_-]+$")]], Query(min_length=1, max_length=50)],
    backend_id: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(require_permissions("assets.read")), db: Session = Depends(db_session)):
    from .services.asset_health import device_health
    response.headers["Cache-Control"] = "no-store"
    return device_health(db, principal, list(dict.fromkeys(device_ids)), backend_id=backend_id)


@router.get("/devices", response_model=list[DeviceOnboardRead])
def list_onboarded_devices(
    search: str | None = Query(default=None, max_length=255),
    kind: str | None = Query(default=None, max_length=64),
    site: str | None = Query(default=None, max_length=128),
    onboarding_status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(require_permissions("assets.read")),
    db: Session = Depends(db_session),
    category: AssetCategory | None = None,
) -> list[Device]:
    query = _device_inventory_query(
        principal, search, kind, site, onboarding_status, category
    )
    return list(db.scalars(query.order_by(Device.name).limit(limit)).all())


@router.get("/devices/{device_id}", response_model=DeviceOnboardRead)
def get_onboarded_device_route(
    device_id: str,
    principal: PrincipalContext = Depends(require_permissions("assets.read")),
    db: Session = Depends(db_session),
) -> Device:
    require_device_access(db, principal, device_id)
    try:
        return get_onboarded_device(db, device_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/devices/{device_id}/native-ssh", response_model=DeviceOnboardRead, status_code=201)
def add_native_ssh_route(device_id: str, payload: DeviceNativeSSHCreate,
    principal: PrincipalContext = Depends(require_permissions("assets.write")), db: Session = Depends(db_session)):
    require_device_access(db, principal, device_id)
    try:
        return add_native_ssh_connection(db, principal, device_id, payload)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@router.patch("/devices/{device_id}/metadata", response_model=DeviceOnboardRead)
def update_device_metadata_route(
    device_id: str,
    payload: DeviceMetadataUpdate,
    principal: PrincipalContext = Depends(require_permissions("assets.write")),
    db: Session = Depends(db_session),
) -> Device:
    require_device_access(db, principal, device_id)
    try:
        return update_device_metadata(
            db,
            device_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/snmp-modules")
def get_snmp_modules(principal: PrincipalContext = Depends(require_permissions("assets.read"))):
    from .snmp_modules import module_catalog
    return {"modules": module_catalog(), "default_modules": ["if_mib"],
        "identity_query": "Four scalar GETs: sysName, sysDescr, sysObjectID, sysUpTime",
        "note": "Collector adapters are not module names. Collector validates its local catalog too."}


@router.patch("/devices/{device_id}/connections/{connection_id}/snmp-configuration", response_model=DeviceOnboardRead)
def update_snmp_configuration_route(device_id: str, connection_id: str, payload: DeviceSNMPConfigurationUpdate,
    principal: PrincipalContext = Depends(require_permissions("assets.write")), db: Session = Depends(db_session)):
    require_device_access(db, principal, device_id)
    try:
        return update_snmp_configuration(db, device_id, connection_id, payload, actor=request_actor(principal, payload.actor))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "changed" in str(exc) or "running" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.patch("/devices/{device_id}/connections/{connection_id}/enabled", response_model=DeviceOnboardRead)
def update_connection_state_route(device_id: str, connection_id: str, payload: DeviceConnectionStateChange,
    principal: PrincipalContext = Depends(require_permissions("assets.write")), db: Session = Depends(db_session)):
    require_device_access(db, principal, device_id)
    try:
        return set_device_connection_enabled(db, principal, device_id, connection_id, payload)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409 if "changed" in str(exc) else 422, str(exc)) from exc


@router.post("/http-monitor/preview-request")
def preview_http_request(payload: HTTPRequestPreview,
    principal: PrincipalContext = Depends(require_permissions("assets.write"))):
    from .http_metrics import parse_curl
    try:
        return {**parse_curl(payload.curl), "tested": False,
            "note": "Request parsed only; select a registered IP target and protected credential before testing."}
    except ValueError:
        raise HTTPException(422, "Unsupported or credential-bearing curl request; use a read-only GET/HEAD URL and select authentication separately") from None


@router.patch("/devices/{device_id}/connections/{connection_id}/http-configuration", response_model=DeviceOnboardRead)
def update_http_configuration_route(device_id: str, connection_id: str, payload: DeviceHTTPConfigurationUpdate,
    principal: PrincipalContext = Depends(require_permissions("assets.write")), db: Session = Depends(db_session)):
    require_device_access(db, principal, device_id)
    try:
        return update_http_configuration(db, device_id, connection_id, payload, actor=request_actor(principal, payload.actor))
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409 if "changed" in str(exc) or "running" in str(exc) else 422, str(exc)) from exc


@router.post(
    "/devices/{device_id}/identity-correction/preview",
    response_model=DeviceIdentityCorrectionPreview,
)
def preview_device_identity_correction_route(
    device_id: str,
    payload: DeviceIdentityCorrectionInput,
    principal: PrincipalContext = Depends(require_permissions("assets.write")),
    db: Session = Depends(db_session),
) -> DeviceIdentityCorrectionPreview:
    device = require_device_access(db, principal, device_id)
    require_site_access(principal, device.site)
    require_site_access(principal, payload.site)
    try:
        return preview_device_identity_correction(db, device_id, payload)
    except IdentityCorrectionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/devices/{device_id}/identity-correction/commit",
    response_model=DeviceOnboardRead,
)
def commit_device_identity_correction_route(
    device_id: str,
    payload: DeviceIdentityCorrectionCommit,
    principal: PrincipalContext = Depends(require_permissions("assets.write")),
    db: Session = Depends(db_session),
) -> Device:
    device = require_device_access(db, principal, device_id)
    require_site_access(principal, device.site)
    require_site_access(principal, payload.site)
    try:
        return commit_device_identity_correction(
            db, device_id, payload,
            actor=request_actor(principal, payload.actor),
        )
    except IdentityCorrectionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/devices/{device_id}/connections/{connection_id}/preflights",
    response_model=list[DeviceConnectionPreflightRead],
)
def list_device_connection_preflights(
    device_id: str,
    connection_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    principal: PrincipalContext = Depends(require_permissions("assets.read")),
    db: Session = Depends(db_session),
) -> list[DeviceConnectionPreflight]:
    require_device_access(db, principal, device_id)
    connection = db.scalar(
        select(DeviceConnection.id).where(
            DeviceConnection.id == connection_id,
            DeviceConnection.device_id == device_id,
        )
    )
    if connection is None:
        raise HTTPException(status_code=404, detail="Device connection not found")
    return list(
        db.scalars(
            select(DeviceConnectionPreflight)
            .where(DeviceConnectionPreflight.connection_id == connection_id)
            .order_by(DeviceConnectionPreflight.started_at.desc())
            .limit(limit)
        ).all()
    )


@router.post(
    "/devices/{device_id}/connections/{connection_id}/verification/retry",
    response_model=DeviceOnboardRead,
)
def retry_device_connection_route(
    device_id: str,
    connection_id: str,
    payload: DeviceVerificationRetry,
    principal: PrincipalContext = Depends(require_permissions("assets.write")),
    db: Session = Depends(db_session),
) -> Device:
    require_device_access(db, principal, device_id)
    try:
        return retry_device_connection(
            db,
            device_id,
            connection_id,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@worker_router.post(
    "/collector-workers/{worker_id}/device-preflights/claim",
    response_model=list[DevicePreflightAssignment],
)
def claim_device_preflights_route(
    worker_id: str,
    payload: DevicePreflightClaim,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
) -> list[DevicePreflightAssignment]:
    worker = _worker(db, worker_id)
    _authorize_worker(worker, authorization)
    try:
        return claim_device_preflights(db, worker, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@worker_router.post(
    "/collector-workers/{worker_id}/device-preflights/{preflight_id}/complete",
    response_model=DeviceConnectionPreflightRead,
)
def complete_device_preflight_route(
    worker_id: str,
    preflight_id: str,
    payload: DevicePreflightComplete,
    db: Session = Depends(db_session),
    authorization: Annotated[str | None, Header()] = None,
):
    worker = _worker(db, worker_id)
    _authorize_worker(worker, authorization)
    try:
        return complete_device_preflight(db, worker, preflight_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
