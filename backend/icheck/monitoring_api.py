from fastapi import APIRouter, Depends, HTTPException, Response, Query
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .monitoring_schemas import (MonitoringApproval, MonitoringEnrollmentRead, MonitoringPreview,
    MonitoringSnapshot, MonitoringTarget, MonitoringWithdrawal)
from .services import monitoring
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext

router = APIRouter(prefix="/api/v1", tags=["continuous-monitoring"])
PATH = "/assets/devices/{device_id}/connections/{connection_id}/monitoring"


@router.get("/monitoring/overview")
def overview(response: Response, category: str | None = Query(default=None, pattern="^(network|linux|windows|http|containers|vmware|services|other)$"),
             search: str = Query(default="", max_length=128), offset: int = Query(default=0, ge=0, le=1000000),
             limit: int = Query(default=25, ge=1, le=50), backend_id: str | None = Query(default=None, max_length=36),
             principal: PrincipalContext = Depends(require_permissions("assets.read")), db: Session = Depends(get_db)):
    from .services.monitoring_overview import overview as read
    response.headers["Cache-Control"] = "no-store"
    return read(db, principal, category=category, search=search, offset=offset, limit=limit, backend_id=backend_id)


@router.get(PATH + "/measurements")
def measurements(response: Response, device_id: str, connection_id: str, backend_id: str | None = Query(default=None, max_length=36),
                 principal: PrincipalContext = Depends(require_permissions("assets.read", "metrics.read")), db: Session = Depends(get_db)):
    from .services.monitoring_overview import measurements as read
    response.headers["Cache-Control"] = "no-store"
    return _call(read, db, principal, device_id, connection_id, backend_id=backend_id)


def _call(function, *args, **kwargs):
    try: return function(*args, **kwargs)
    except LookupError as exc: raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409 if "changed" in str(exc) else 422, detail=str(exc)) from exc


@router.get(PATH, response_model=MonitoringPreview)
def preview(device_id: str, connection_id: str,
            principal: PrincipalContext = Depends(require_permissions("assets.read")), db: Session = Depends(get_db)):
    return _call(monitoring.monitoring_preview, db, principal, device_id, connection_id)


@router.post(PATH + "/approve", response_model=MonitoringEnrollmentRead)
def approve(device_id: str, connection_id: str, payload: MonitoringApproval,
            principal: PrincipalContext = Depends(require_permissions("assets.write")), db: Session = Depends(get_db)):
    payload = payload.model_copy(update={"actor": request_actor(principal, payload.actor)})
    return _call(monitoring.approve_monitoring, db, principal, device_id, connection_id, payload)


@router.post(PATH + "/withdraw", response_model=MonitoringEnrollmentRead)
def withdraw(device_id: str, connection_id: str, payload: MonitoringWithdrawal,
             principal: PrincipalContext = Depends(require_permissions("assets.write")), db: Session = Depends(get_db)):
    payload = payload.model_copy(update={"actor": request_actor(principal, payload.actor)})
    return _call(monitoring.withdraw_monitoring, db, principal, device_id, connection_id, payload)


@router.get("/monitoring/targets", response_model=MonitoringSnapshot)
def targets(principal: PrincipalContext = Depends(require_permissions("assets.read")), db: Session = Depends(get_db)):
    return _call(monitoring.monitoring_snapshot, db, principal)


@router.get("/monitoring/enrollments/{enrollment_id}/target", response_model=MonitoringTarget)
def target(enrollment_id: str, principal: PrincipalContext = Depends(require_permissions("assets.read")), db: Session = Depends(get_db)):
    return _call(monitoring.monitoring_target, db, principal, enrollment_id)


@router.get("/monitoring/enrollments/{enrollment_id}/managed-credential")
def managed_credential(enrollment_id: str, response: Response,
                       principal: PrincipalContext = Depends(require_permissions("assets.read")), db: Session = Depends(get_db)):
    from .config import get_settings
    from .services.device_credentials import profile, resolve, DeviceCredentialUnavailable
    from .models import ManagedDeviceCredential
    from sqlalchemy import select
    subject = get_settings().managed_monitoring_gateway_subject
    response.headers["Cache-Control"] = "no-store"
    if not subject or principal.subject != subject or principal.principal_type != "service":
        raise HTTPException(403, "Only the protected monitoring gateway may resolve enrollment credentials")
    current = _call(monitoring.monitoring_target, db, principal, enrollment_id)
    p = profile(db, current.credential_profile_id or "", lock=True)
    row = db.scalar(select(ManagedDeviceCredential).where(ManagedDeviceCredential.credential_profile_id == current.credential_profile_id))
    spec = current.exporter_monitor or current.http_monitor
    expected_kind = "snmp_v2c" if current.protocol == "snmp" else (
        "http_basic" if spec and spec.auth_mode == "basic" else "https_token")
    if (current.protocol not in {"snmp", "https_api", "node_exporter", "windows_exporter", "cadvisor", "vmware_exporter"} or row is None or row.kind != expected_kind
            or (current.credential_revision is not None and (p is None or p.revision!=current.credential_revision))
            or row.site != current.site or (current.protocol != "snmp"
                and (not spec or spec.auth_mode == "none"
                    or p is None or p.revision != current.credential_revision))):
        raise HTTPException(409, "Enrollment does not bind a compatible managed credential")
    try:
        values = resolve(db, p)
    except DeviceCredentialUnavailable:
        raise HTTPException(409, "Enrollment credential is unavailable") from None
    return {"values": values, "expires_at": current.expires_at, "profile_revision": p.revision}
