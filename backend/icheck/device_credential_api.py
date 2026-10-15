from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from .auth import require_permissions
from .config import get_settings
from .database import get_db
from .device_credential_schemas import DeviceCredentialCreate, DeviceCredentialRevoke, DeviceCredentialUpdate
from .services import device_credentials as service
from .services.authorization_scope import require_site_access

router = APIRouter(prefix="/api/v1/device-credentials", tags=["device-credentials"])


def administrator(principal=Depends(require_permissions("credentials.manage"))):
    if get_settings().control_plane_auth_mode != "disabled" and principal.principal_type != "user":
        raise HTTPException(403, "A human credential administrator is required")
    return principal


def call(response, operation, *args, **kwargs):
    response.headers["Cache-Control"] = "no-store"
    try:
        return operation(*args, **kwargs)
    except LookupError:
        raise HTTPException(404, "Managed device credential not found") from None
    except service.DeviceCredentialUnavailable as exc:
        raise HTTPException(503, str(exc), headers={"Cache-Control": "no-store"}) from None
    except ValueError as exc:
        raise HTTPException(409, str(exc), headers={"Cache-Control": "no-store"}) from None


@router.get("")
def listing(response: Response, principal=Depends(administrator), db: Session = Depends(get_db)):
    rows = call(response, service.list_credentials, db)
    from .services.authorization_scope import has_global_scope
    return [row for row in rows if has_global_scope(principal) or row["site"] in principal.authorization_scope.get("sites", [])]


@router.get("/status")
def status(response: Response, principal=Depends(administrator)):
    response.headers["Cache-Control"] = "no-store"
    try:
        service.key(); ready = True
    except service.DeviceCredentialUnavailable:
        ready = False
    return {"storage_ready": ready}


@router.post("", status_code=201)
def create(payload: DeviceCredentialCreate, response: Response, principal=Depends(administrator), db: Session = Depends(get_db)):
    require_site_access(principal, payload.site)
    return call(response, service.create, db, payload, principal.subject)


@router.put("/{profile_id}")
def rotate(profile_id: str, payload: DeviceCredentialUpdate, response: Response,
           principal=Depends(administrator), db: Session = Depends(get_db)):
    p = service.profile(db, profile_id)
    if p is None:
        raise HTTPException(404, "Managed device credential not found")
    require_site_access(principal, p.worker_selector.get("site", ""))
    require_site_access(principal, payload.site)
    return call(response, service.update, db, profile_id, payload, principal.subject)


@router.post("/{profile_id}/revoke")
def revoke(profile_id: str, payload: DeviceCredentialRevoke, response: Response,
           principal=Depends(administrator), db: Session = Depends(get_db)):
    p = service.profile(db, profile_id)
    if p is None:
        raise HTTPException(404, "Managed device credential not found")
    require_site_access(principal, p.worker_selector.get("site", ""))
    return call(response, service.update, db, profile_id, payload, principal.subject, revoke=True)
