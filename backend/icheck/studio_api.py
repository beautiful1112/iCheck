from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import select, or_

from .auth import require_global_permissions, require_permissions
from .database import get_db
from .models import CapabilityStudioGenerationAttempt, CapabilityStudioSession
from .projection_schemas import projection_contract_catalog
from .sandbox import SandboxUnavailable
from .services.authorization_scope import request_actor
from .services.capability_studio import (
    create_skill_studio_session,
    create_runtime_revision_session,
    create_report_studio_session,
    create_studio_session,
    create_topology_studio_session,
    create_tool_studio_session,
    create_visualization_studio_session,
    create_workflow_studio_session,
    generate_studio_collector,
    generate_studio_report,
    generate_studio_skill,
    generate_studio_topology,
    generate_studio_tool,
    generate_studio_visualization,
    generate_studio_workflow,
    get_studio_session,
    publish_studio_capability,
    restore_studio_capability,
    studio_session_query,
)
from .services.control_plane_auth import PrincipalContext
from .services.structured_model import StructuredModelUnavailable
from .services.ai_authoring_quota import AuthoringQuotaConflict, AuthoringQuotaExceeded
from .services.studio_generation import StudioGenerationConflict
from .services.studio_generation import digest
from .services.capability_studio import _generate_kind
from .studio_schemas import (
    CapabilityStudioGenerate,
    CapabilityStudioGenerationRead,
    CapabilityStudioMessageCreate,
    CapabilityStudioPublish,
    CapabilityStudioRestore,
    CapabilityStudioReportCreate,
    CapabilityStudioRevisionCreate,
    CapabilityStudioSessionCreate,
    CapabilityStudioSessionRead,
    CapabilityStudioSkillCreate,
    CapabilityStudioTopologyCreate,
    CapabilityStudioToolCreate,
    CapabilityStudioVisualizationCreate,
    CapabilityStudioWorkflowCreate,
)


router = APIRouter(prefix="/api/v1/capability-studio", tags=["capability-studio"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get("/extensions")
def list_extensions_route(db: DBSession, artifact_id: str | None = Query(default=None, max_length=36),
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    from .config import get_settings
    from .models import ManagedExtensionInstallation
    from .services.authorization_scope import namespace_clause
    from .services.managed_extensions import installation_view
    query = select(ManagedExtensionInstallation).where(namespace_clause(ManagedExtensionInstallation, principal))
    if artifact_id: query = query.where(ManagedExtensionInstallation.artifact_id == artifact_id)
    return {"storage_configured": bool(get_settings().extension_packages_root), "items": [installation_view(row)
        for row in db.scalars(query
            .order_by(ManagedExtensionInstallation.updated_at.desc()).limit(200))]}


@router.get("/extensions/targets")
def extension_targets_route(db: DBSession, search: str = Query(default="", max_length=128),
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage", "assets.read"))):
    from .models import Device, DeviceConnection
    from .services.authorization_scope import device_scope_clause, namespace_clause
    query = select(Device, DeviceConnection).join(DeviceConnection, DeviceConnection.device_id == Device.id).where(
        device_scope_clause(principal), namespace_clause(DeviceConnection, principal), DeviceConnection.protocol == "ssh")
    if search:
        query = query.where(or_(Device.name.icontains(search, autoescape=True),
            Device.management_ip.contains(search, autoescape=True)))
    from .services.device_credentials import profile
    return [{"device_id": device.id, "connection_id": connection.id, "name": device.name,
        "host": device.management_ip, "site": device.site, "enabled": device.enabled and connection.enabled,
        "credential_reference": connection.credential_profile_ref,
        "credential_name": credential.name if (credential := profile(db, connection.credential_profile_ref)) else None,
        "connection_scope": connection.worker_selector.get("site")}
        for device, connection in db.execute(query.order_by(Device.name, Device.id).limit(200))]


def _extension_error(exc):
    from .services.managed_extensions import ExtensionReviewConflict
    if isinstance(exc, ExtensionReviewConflict): return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, PermissionError): return HTTPException(status_code=403, detail="Extension operation is not authorized")
    if isinstance(exc, LookupError): return HTTPException(status_code=404, detail="Extension record not found")
    # Package/credential errors must not disclose driver output or secret-provider diagnostics.
    return HTTPException(status_code=409, detail="Extension operation could not complete. Check package validation and runtime availability. For optional device tests, check device access in Assets.")


from .extension_schemas import ExtensionTargetTest, ExtensionInstall, ExtensionLifecycleChange, SSHHostIdentityConfirm, SSHCompatibilityChange


@router.post("/extensions/targets/{connection_id}/identity/compatibility")
def change_ssh_compatibility_route(connection_id: str, payload: SSHCompatibilityChange, db: DBSession,
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage", "assets.read", "assets.activate", "tools.admin"))):
    from .services.ssh_host_identity import change_profile
    try:
        return change_profile(db, principal, connection_id, payload)
    except (ValueError, LookupError, PermissionError) as exc:
        db.rollback()
        raise _extension_error(exc) from None


@router.get("/extensions/targets/{connection_id}/identity")
def ssh_identity_route(connection_id: str, db: DBSession,
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage", "assets.read", "assets.activate", "tools.admin"))):
    from .services.ssh_host_identity import status as identity_status
    try:
        return identity_status(db, principal, connection_id)
    except (ValueError, LookupError, PermissionError) as exc:
        raise _extension_error(exc) from None


@router.post("/extensions/targets/{connection_id}/identity/probe")
def probe_ssh_identity_route(connection_id: str, db: DBSession,
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage", "assets.read", "assets.activate", "tools.admin"))):
    from .services.ssh_host_identity import probe
    try:
        return probe(db, principal, connection_id)
    except (ValueError, LookupError, PermissionError) as exc:
        db.rollback()
        raise _extension_error(exc) from None


@router.post("/extensions/targets/{connection_id}/identity/confirm")
def confirm_ssh_identity_route(connection_id: str, payload: SSHHostIdentityConfirm, db: DBSession,
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage", "assets.read", "assets.activate", "tools.admin"))):
    from .services.ssh_host_identity import confirm
    try:
        return confirm(db, principal, connection_id, payload)
    except (ValueError, LookupError, PermissionError) as exc:
        db.rollback()
        raise _extension_error(exc) from None


@router.post("/extensions/tests")
def test_extension_route(payload: ExtensionTargetTest, db: DBSession,
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage", "assets.read", "assets.activate"))):
    from .services.managed_extensions import test_target, test_view
    try:
        return test_view(test_target(db, principal, payload))
    except (ValueError, LookupError, PermissionError) as exc:
        db.rollback()
        raise _extension_error(exc) from None


@router.get("/extensions/tests")
def list_extension_tests_route(artifact_version_id: str, db: DBSession,
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    from .models import ManagedExtensionTest
    from .services.authorization_scope import namespace_clause
    from .services.managed_extensions import test_view
    return [test_view(row) for row in db.scalars(select(ManagedExtensionTest).where(
        ManagedExtensionTest.artifact_version_id == artifact_version_id, namespace_clause(ManagedExtensionTest, principal))
        .order_by(ManagedExtensionTest.created_at.desc()).limit(100))]


@router.post("/extensions/install")
def install_extension_route(payload: ExtensionInstall, db: DBSession,
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage", "assets.read", "assets.activate"))):
    from .services.managed_extensions import install, installation_view
    try:
        return installation_view(install(db, principal, payload))
    except (ValueError, LookupError, PermissionError) as exc:
        db.rollback()
        raise _extension_error(exc) from None


@router.post("/extensions/{installation_id}/{action}")
def extension_lifecycle_route(installation_id: str, action: str, payload: ExtensionLifecycleChange, db: DBSession,
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage", "assets.read", "assets.activate"))):
    from .services.managed_extensions import lifecycle, installation_view
    try:
        return installation_view(lifecycle(db, principal, installation_id, payload.expected_revision, action))
    except (ValueError, LookupError, PermissionError) as exc:
        db.rollback()
        raise _extension_error(exc) from None


@router.get("/configuration-backups/{backup_id}/download")
def download_extension_backup_route(backup_id: str, db: DBSession,
        principal: PrincipalContext = Depends(require_permissions("capabilities.manage", "assets.read"))):
    from uuid import UUID
    from .services.extension_backups import download_configuration_backup
    try:
        identifier = str(UUID(backup_id))
        body = download_configuration_backup(db, principal, identifier)
    except LookupError:
        raise HTTPException(status_code=404, detail="Configuration backup not found") from None
    except PermissionError:
        raise HTTPException(status_code=403, detail="Configuration backup download is not authorized") from None
    except ValueError:
        raise HTTPException(status_code=422, detail="Configuration backup is unavailable") from None
    return Response(body, media_type="application/octet-stream", headers={
        "Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'attachment; filename="configuration-{identifier}.txt"'})


@router.post("/sessions/extensions", response_model=CapabilityStudioSessionRead, status_code=201)
def create_extension_session_route(payload: CapabilityStudioToolCreate, db: DBSession,
        principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    from .services.capability_studio import _create_contract_studio_session
    try:
        return _create_contract_studio_session(db, payload,
            actor=request_actor(principal, payload.created_by), artifact_kind="tool", extension=True)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/collector-contracts")
def collector_contracts_route(
    principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage")),
) -> list[dict]:
    return projection_contract_catalog()


def _session(db: Session, session_id: str) -> CapabilityStudioSession:
    try:
        return get_studio_session(db, session_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _generation_error(exc: Exception) -> HTTPException:
    if isinstance(exc, AuthoringQuotaExceeded):
        return HTTPException(status_code=429, detail=str(exc))
    if isinstance(exc, AuthoringQuotaConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, StudioGenerationConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, (StructuredModelUnavailable, SandboxUnavailable)):
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=str(exc),
    )


@router.post(
    "/sessions",
    response_model=CapabilityStudioSessionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_session_route(
    payload: CapabilityStudioSessionCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return create_studio_session(
            db,
            trusted_payload,
            actor=trusted_payload.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/sessions/workflows",
    response_model=CapabilityStudioSessionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_workflow_session_route(
    payload: CapabilityStudioWorkflowCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    actor = request_actor(principal, payload.created_by)
    try:
        return create_workflow_studio_session(db, payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/sessions/topologies",
    response_model=CapabilityStudioSessionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_topology_session_route(
    payload: CapabilityStudioTopologyCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    actor = request_actor(principal, payload.created_by)
    try:
        return create_topology_studio_session(db, payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/sessions/visualizations",
    response_model=CapabilityStudioSessionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_visualization_session_route(
    payload: CapabilityStudioVisualizationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    actor = request_actor(principal, payload.created_by)
    try:
        return create_visualization_studio_session(db, payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/sessions/reports",
    response_model=CapabilityStudioSessionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_report_session_route(
    payload: CapabilityStudioReportCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    actor = request_actor(principal, payload.created_by)
    try:
        return create_report_studio_session(db, payload, actor=actor, principal=principal)
    except (LookupError, PermissionError) as exc:
        raise HTTPException(status_code=404, detail="Retained report proof is unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/sessions/tools",
    response_model=CapabilityStudioSessionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_tool_session_route(
    payload: CapabilityStudioToolCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    actor = request_actor(principal, payload.created_by)
    try:
        return create_tool_studio_session(db, payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/sessions/skills",
    response_model=CapabilityStudioSessionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_skill_session_route(
    payload: CapabilityStudioSkillCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    actor = request_actor(principal, payload.created_by)
    try:
        return create_skill_studio_session(db, payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/sessions/from-runtime",
    response_model=CapabilityStudioSessionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_runtime_revision_session_route(
    payload: CapabilityStudioRevisionCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    try:
        return create_runtime_revision_session(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/sessions", response_model=list[CapabilityStudioSessionRead])
def list_sessions_route(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=500),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[CapabilityStudioSession]:
    query = studio_session_query().order_by(
        CapabilityStudioSession.updated_at.desc()
    )
    return list(db.scalars(query.limit(limit)).unique().all())


@router.get(
    "/sessions/{session_id}",
    response_model=CapabilityStudioSessionRead,
)
def get_session_route(
    session_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> CapabilityStudioSession:
    return _session(db, session_id)


@router.get("/sessions/{session_id}/generations", response_model=list[CapabilityStudioGenerationRead])
def list_generation_attempts(session_id: str, db: DBSession,
    limit: int = Query(default=50, ge=1, le=100),
    _: PrincipalContext = Depends(require_global_permissions("capabilities.read"))):
    _session(db, session_id)
    return list(db.scalars(select(CapabilityStudioGenerationAttempt)
        .where(CapabilityStudioGenerationAttempt.session_id == session_id)
        .order_by(CapabilityStudioGenerationAttempt.created_at.desc(), CapabilityStudioGenerationAttempt.id.desc())
        .limit(limit)))


@router.post("/sessions/{session_id}/generations/{request_key}/retry", response_model=CapabilityStudioSessionRead)
def retry_generation_route(session_id: str, request_key: str, payload: CapabilityStudioGenerate,
    db: DBSession, principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    session = _session(db, session_id)
    attempt = db.scalar(select(CapabilityStudioGenerationAttempt).where(
        CapabilityStudioGenerationAttempt.session_id == session_id,
        CapabilityStudioGenerationAttempt.request_key == request_key))
    if attempt is None:
        raise HTTPException(status_code=404, detail="Studio generation request not found")
    actor = request_actor(principal, payload.actor)
    try:
        if payload.request_key and payload.request_key != request_key:
            raise StudioGenerationConflict("Retry path and request key differ")
        if (attempt.actor != actor or digest(attempt.request_document) != attempt.request_sha256
            or attempt.request_document.get("actor") != actor
            or attempt.request_document.get("kind") != session.artifact_kind):
            raise StudioGenerationConflict("Recorded request is not owned by this author or failed integrity verification")
        return _generate_kind(db, session, kind=session.artifact_kind, actor=actor,
            followup=attempt.request_document.get("followup"), request_key=request_key, report_principal=principal)
    except (
        ValueError, StructuredModelUnavailable, SandboxUnavailable,
        AuthoringQuotaExceeded, AuthoringQuotaConflict,
    ) as exc:
        raise _generation_error(exc) from exc


@router.post(
    "/sessions/{session_id}/generate",
    response_model=CapabilityStudioSessionRead,
)
def generate_session_route(
    session_id: str,
    payload: CapabilityStudioGenerate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    session = _session(db, session_id)
    try:
        actor = request_actor(principal, payload.actor)
        if session.artifact_kind == "collector":
            return generate_studio_collector(db, session, actor=actor, request_key=payload.request_key)
        if session.artifact_kind == "workflow":
            return generate_studio_workflow(db, session, actor=actor, request_key=payload.request_key)
        if session.artifact_kind == "topology":
            return generate_studio_topology(db, session, actor=actor, request_key=payload.request_key)
        if session.artifact_kind == "visualization":
            return generate_studio_visualization(db, session, actor=actor, request_key=payload.request_key)
        if session.artifact_kind == "report":
            return generate_studio_report(db, session, actor=actor, request_key=payload.request_key, principal=principal)
        if session.artifact_kind == "tool":
            return generate_studio_tool(db, session, actor=actor, request_key=payload.request_key)
        if session.artifact_kind == "skill":
            return generate_studio_skill(db, session, actor=actor, request_key=payload.request_key)
        raise ValueError("Unsupported Capability Studio artifact kind")
    except (
        ValueError, StructuredModelUnavailable, SandboxUnavailable,
        AuthoringQuotaExceeded, AuthoringQuotaConflict,
    ) as exc:
        raise _generation_error(exc) from exc


@router.post(
    "/sessions/{session_id}/messages",
    response_model=CapabilityStudioSessionRead,
)
def refine_session_route(
    session_id: str,
    payload: CapabilityStudioMessageCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    session = _session(db, session_id)
    try:
        actor = request_actor(principal, payload.actor)
        if session.artifact_kind == "collector":
            return generate_studio_collector(
                db,
                session,
                actor=actor,
                followup=payload.content,
                request_key=payload.request_key,
            )
        if session.artifact_kind == "workflow":
            return generate_studio_workflow(
                db,
                session,
                actor=actor,
                followup=payload.content,
                request_key=payload.request_key,
            )
        if session.artifact_kind == "topology":
            return generate_studio_topology(
                db,
                session,
                actor=actor,
                followup=payload.content,
                request_key=payload.request_key,
            )
        if session.artifact_kind == "visualization":
            return generate_studio_visualization(
                db,
                session,
                actor=actor,
                followup=payload.content,
                request_key=payload.request_key,
            )
        if session.artifact_kind == "report":
            return generate_studio_report(
                db,
                session,
                actor=actor,
                followup=payload.content,
                request_key=payload.request_key,
                principal=principal,
            )
        if session.artifact_kind == "tool":
            return generate_studio_tool(
                db,
                session,
                actor=actor,
                followup=payload.content,
                request_key=payload.request_key,
            )
        if session.artifact_kind == "skill":
            return generate_studio_skill(
                db,
                session,
                actor=actor,
                followup=payload.content,
                request_key=payload.request_key,
            )
        raise ValueError("Unsupported Capability Studio artifact kind")
    except (
        ValueError, StructuredModelUnavailable, SandboxUnavailable,
        AuthoringQuotaExceeded, AuthoringQuotaConflict,
    ) as exc:
        raise _generation_error(exc) from exc


@router.post(
    "/sessions/{session_id}/publish",
    response_model=CapabilityStudioSessionRead,
)
def publish_session_route(
    session_id: str,
    payload: CapabilityStudioPublish,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityStudioSession:
    session = _session(db, session_id)
    try:
        return publish_studio_capability(
            db,
            session,
            actor=request_actor(principal, payload.actor),
            expected_artifact_version_id=payload.expected_artifact_version_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/sessions/{session_id}/restore-preview",response_model=CapabilityStudioSessionRead,status_code=201)
def restore_session_route(session_id:str,payload:CapabilityStudioRestore,db:DBSession,
        principal:PrincipalContext=Depends(require_global_permissions("capabilities.manage"))):
    session=_session(db,session_id)
    try:
        return restore_studio_capability(db,session,payload,actor=request_actor(principal,payload.actor))
    except LookupError as error: raise HTTPException(404,str(error)) from None
    except StudioGenerationConflict as error: raise HTTPException(409,str(error)) from None
    except ValueError as error: raise HTTPException(422,str(error)) from None
