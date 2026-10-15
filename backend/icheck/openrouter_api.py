"""Human-only managed provider setup, with backward-compatible OpenRouter routes."""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .config import get_settings
from .database import get_db
from .openrouter_schemas import (
    OpenRouterCheckRead, OpenRouterConfigure, OpenRouterConfiguredRead,
    OpenRouterConnect, OpenRouterConnectionRead, OpenRouterConnectionUpdate, OpenRouterSetupRead,
    OpenRouterProbe, OpenRouterProbeRead,
    ManagedAIConnect, ManagedAIConfigure,
)
from .services import openrouter_setup as service
from .services.ai_settings import AIProviderUnavailable
from .services.control_plane_auth import PrincipalContext

router = APIRouter(prefix="/api/v1/ai/openrouter", tags=["ai-settings"])
managed_router = APIRouter(prefix="/api/v1/ai/managed", tags=["ai-settings"])


def administrator(principal: PrincipalContext = Depends(require_global_permissions("ai.manage", "credentials.manage"))):
    if get_settings().control_plane_auth_mode != "disabled" and (
        principal.principal_id is None or principal.principal_type != "user"
    ):
        raise HTTPException(status_code=403, detail="A human AI and credential administrator is required")
    return principal


def no_store(response: Response):
    response.headers["Cache-Control"] = "no-store"


def invoke(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except LookupError:
        raise HTTPException(status_code=404, detail="Managed AI connection not found") from None
    except service.ManagedAIConflict as error:
        raise HTTPException(status_code=409, detail=str(error)) from None
    except service.ManagedAIUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error), headers={"Cache-Control": "no-store"}) from None
    except AIProviderUnavailable as error:
        raise HTTPException(status_code=422, detail=str(error), headers={"Cache-Control": "no-store"}) from None


@router.get("/setup", response_model=OpenRouterSetupRead)
@managed_router.get("/setup", response_model=OpenRouterSetupRead)
def status(response: Response, _: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return service.setup_status(db)


@router.post("/connections", response_model=OpenRouterConnectionRead, status_code=201)
def connect(payload: OpenRouterConnect, response: Response,
            principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return invoke(service.connect, db, payload, actor=principal.subject)


@router.put("/{provider_id}/connection", response_model=OpenRouterConnectionRead)
@managed_router.put("/{provider_id}/connection", response_model=OpenRouterConnectionRead)
def update(provider_id: str, payload: OpenRouterConnectionUpdate, response: Response,
           principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return invoke(service.update_connection, db, provider_id, payload, actor=principal.subject)


@router.post("/{provider_id}/check", response_model=OpenRouterCheckRead)
@managed_router.post("/{provider_id}/check", response_model=OpenRouterCheckRead)
def check(provider_id: str, response: Response,
          principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return invoke(service.check_connection, db, provider_id, actor=principal.subject)


@router.post("/{provider_id}/configure", response_model=OpenRouterConfiguredRead)
def configure(provider_id: str, payload: OpenRouterConfigure, response: Response,
              principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return invoke(service.configure, db, provider_id, payload, actor=principal.subject)


@router.post("/{provider_id}/probe", response_model=OpenRouterProbeRead)
@managed_router.post("/{provider_id}/probe", response_model=OpenRouterProbeRead)
def probe(provider_id: str, payload: OpenRouterProbe, response: Response,
          principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    from .services.ai_authoring_quota import AuthoringQuotaExceeded
    try:
        return invoke(service.probe_model, db, provider_id, payload, actor=principal.subject)
    except AuthoringQuotaExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from None


@managed_router.post("/connections", response_model=OpenRouterConnectionRead, status_code=201)
def managed_connect(payload: ManagedAIConnect, response: Response,
                    principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return invoke(service.connect, db, payload, actor=principal.subject)


@managed_router.post("/{provider_id}/configure", response_model=OpenRouterConfiguredRead)
def managed_configure(provider_id: str, payload: ManagedAIConfigure, response: Response,
                      principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return invoke(service.configure, db, provider_id, payload, actor=principal.subject)
