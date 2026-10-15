from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from .auth import require_global_permissions, require_permissions
from .database import get_db
from .monitoring_template_schemas import TemplateTargetTest, TemplateEnable, TemplateModuleInstall
from .services import monitoring_templates
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext

router = APIRouter(prefix="/api/v1/capability-studio", tags=["monitoring-templates"])
PATH = "/sessions/{session_id}/monitoring"


def call(operation, *args):
    try: return operation(*args)
    except PermissionError as exc: raise HTTPException(403, str(exc)) from exc
    except LookupError as exc: raise HTTPException(404, str(exc)) from exc
    except ValueError as exc: raise HTTPException(409 if "changed" in str(exc) else 422, str(exc)) from exc


@router.get(PATH + "/targets")
def choices(session_id: str, search: str = Query(default="", max_length=200),
    principal: PrincipalContext = Depends(require_global_permissions("capabilities.read")),
    assets: PrincipalContext = Depends(require_permissions("assets.read")), db: Session = Depends(get_db)):
    from .services.capability_studio import get_studio_session
    call(get_studio_session, db, session_id)
    return call(monitoring_templates.target_choices, db, assets, session_id, search)


@router.get(PATH+"/module-preview")
def module_preview(session_id:str,artifact_version_id:str,
    principal:PrincipalContext=Depends(require_global_permissions("capabilities.read")),db:Session=Depends(get_db)):
    return call(monitoring_templates.module_preview,db,principal,session_id,artifact_version_id)


@router.post(PATH+"/install-module")
def install_module(session_id:str,payload:TemplateModuleInstall,
    principal:PrincipalContext=Depends(require_global_permissions("capabilities.manage")),db:Session=Depends(get_db)):
    human(principal)
    payload=payload.model_copy(update={"actor":request_actor(principal,payload.actor)})
    return call(monitoring_templates.install_module,db,principal,session_id,payload)


@router.get(PATH + "/state")
def state(session_id: str, artifact_version_id: str, device_id: str, connection_id: str,
    verify_samples: bool = False, backend_id: str | None = None,
    principal: PrincipalContext = Depends(require_global_permissions("capabilities.read")),
    assets: PrincipalContext = Depends(require_permissions("assets.read")), db: Session = Depends(get_db)):
    if verify_samples:
        return call(monitoring_templates.verify_samples, db, assets, session_id, artifact_version_id, device_id, connection_id, backend_id)
    return call(monitoring_templates.binding_state, db, assets, session_id, artifact_version_id, device_id, connection_id)


@router.post(PATH + "/dashboard-proposal")
def dashboard(session_id: str, artifact_version_id: str, device_id: str, connection_id: str, grafana_connection_id: str,
    backend_id: str | None = None, principal: PrincipalContext = Depends(require_global_permissions("metrics.read")),
    assets: PrincipalContext = Depends(require_permissions("assets.read")),
    author: PrincipalContext = Depends(require_global_permissions("capabilities.manage")), db: Session = Depends(get_db)):
    human(author)
    from .grafana_client import GrafanaError
    try:
        return call(monitoring_templates.dashboard_proposal, db, assets, session_id, artifact_version_id, device_id, connection_id,
            grafana_connection_id, backend_id)
    except GrafanaError:
        raise HTTPException(422, "Grafana proposal unavailable; inspect the connection and declared metrics before retrying") from None


def human(principal):
    if principal.principal_type != "user": raise HTTPException(403, "Only a human operator can test or enable a monitoring template")


@router.post(PATH + "/test")
def test(session_id: str, payload: TemplateTargetTest,
    principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage")),
    assets: PrincipalContext = Depends(require_permissions("assets.write")), db: Session = Depends(get_db)):
    human(principal)
    payload = payload.model_copy(update={"actor": request_actor(principal, payload.actor)})
    return call(monitoring_templates.test_target, db, assets, session_id, payload)


@router.post(PATH + "/enable")
def enable(session_id: str, payload: TemplateEnable,
    principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage")),
    assets: PrincipalContext = Depends(require_permissions("assets.write")), db: Session = Depends(get_db)):
    human(principal)
    payload = payload.model_copy(update={"actor": request_actor(principal, payload.actor)})
    return call(monitoring_templates.enable_target, db, assets, session_id, payload)
