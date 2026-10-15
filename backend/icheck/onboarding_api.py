from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .auth import require_permissions
from .config import get_settings
from .database import get_db
from .onboarding_schemas import OnboardingApprove, OnboardingInput
from .services import device_onboarding as service

router = APIRouter(prefix="/api/v1/assets/onboarding", tags=["device-onboarding"])


@router.post("/preview")
def preview(payload: OnboardingInput, principal=Depends(require_permissions("assets.read")), db: Session = Depends(get_db)):
    try:
        return service.preview(db, payload, principal)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/approve")
def approve(payload: OnboardingApprove, principal=Depends(require_permissions("assets.write")), db: Session = Depends(get_db)):
    if get_settings().control_plane_auth_mode != "disabled" and principal.principal_type != "user":
        raise HTTPException(403, "A human inventory approver is required")
    try:
        return service.approve(db, payload, principal)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
