"""Human-facing management of the existing native Alertmanager."""
from uuid import UUID
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from .auth import current_principal
from .database import get_db
from .alertmanager_schemas import SilenceCreate, SilenceExpire
from .metric_alert_api import invoke
from .services import alertmanager as service
from .services.control_plane_auth import PrincipalContext

router = APIRouter(prefix="/api/v1/alertmanager", tags=["Alertmanager management"])


@router.get("/overview")
def overview(response: Response, actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.overview, db, actor)


@router.post("/silences")
def create(payload: SilenceCreate, response: Response, actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.create, db, actor, payload)


@router.post("/silences/{identifier}/expire")
def expire(identifier: UUID, payload: SilenceExpire, response: Response, actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.expire, db, actor, str(identifier), payload)


@router.post("/requests/{identifier}/inspect")
def inspect(identifier: UUID, response: Response, actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.inspect, db, actor, str(identifier))
