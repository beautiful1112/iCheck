from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .agent_schemas import (
    AgentWorkerRead,
    AgentWorkerRegister,
    AgentWorkerRegistration,
)
from .config import get_settings
from .database import get_db
from .mcp_schemas import (
    MCPFleetTelemetryRead,
    MCPServerCreate,
    MCPServerHealth,
    MCPServerRead,
    MCPClientMetadataRead,
    MCPAttestationClaim,
    MCPOAuthRevoke,
    MCPOAuthScopeChallengeApproval,
    MCPOAuthScopeChallengeRead,
    MCPToolAttestationAssignment,
    MCPToolAttestationComplete,
    MCPToolAttestationCreate,
    MCPToolAttestationRead,
    MCPToolActivationCreate,
    MCPToolActivationRead,
    MCPToolCircuitRecovery,
    MCPToolDeactivation,
    MCPToolRolloutAction,
)
from .mcp_oauth_recovery_schemas import MCPOAuthRecoveryConfirm, MCPOAuthRecoveryRead, MCPOAuthRecoveryStart
from .oauth_family_recovery import MCPOAuthFamilyRecoveryConfirm, MCPOAuthFamilyRecoveryRead, MCPOAuthFamilyRecoveryStart
from .oauth_family_local import MCPOAuthFamilyLocalExecute, MCPOAuthFamilyLocalRead, MCPOAuthFamilyLocalStart
from .oauth_consent import MCPOAuthConsentRead
from .models import (
    AgentWorker,
    MCPOAuthScopeChallenge,
    MCPOAuthConsentAttempt,
    MCPServer,
    MCPToolActivation,
    MCPToolAttestation,
)
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext
from .services.mcp_gateway import (
    MCPContractError,
    MCPGatewayError,
    activate_mcp_tool,
    check_mcp_server,
    create_mcp_server,
    deactivate_mcp_tool,
    promote_mcp_tool,
    recover_mcp_tool_circuit,
)
from .services.mcp_fleet_telemetry import mcp_fleet_telemetry
from .services.mcp_attestations import (
    MCPAttestationLeaseLost,
    claim_mcp_tool_attestations,
    complete_mcp_tool_attestation,
    request_mcp_tool_attestation,
)
from .services.mcp_oauth import (
    MCPOAuthError,
    begin_mcp_oauth,
    finish_mcp_oauth,
    mcp_oauth_browser_location,
    revoke_mcp_oauth,
)
from .services.mcp_scope_challenges import approve_mcp_scope_challenge
from .services.mcp_oauth_recovery import confirm_oauth_recovery, read_oauth_recovery, start_oauth_recovery
from .services.mcp_family_recovery import confirm_family_recovery, read_family_recovery, start_family_recovery
from .services.mcp_family_local import execute_family_local, read_family_local, start_family_local
from .credentials import CredentialUnavailable
from .services.agent_execution import register_agent_worker
from .services.worker_mtls import verify_worker_peer
from .worker_auth import WorkerAuthenticationError, authenticate_agent_worker
from .worker_mtls import WorkerPeerIdentity, worker_peer_identity


router = APIRouter(prefix="/api/v1/mcp", tags=["mcp-gateway"])
DBSession = Annotated[Session, Depends(get_db)]
MCP_OAUTH_TRANSACTION_COOKIE = "icheck_mcp_oauth_txn"
WorkerPeer = Annotated[WorkerPeerIdentity | None, Depends(worker_peer_identity)]


def _server(db: Session, server_id: str) -> MCPServer:
    server = db.get(MCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return server


def _activation(db: Session, activation_id: str) -> MCPToolActivation:
    activation = db.get(MCPToolActivation, activation_id)
    if activation is None:
        raise HTTPException(status_code=404, detail="MCP activation not found")
    return activation


def _attestation(db: Session, attestation_id: str) -> MCPToolAttestation:
    attestation = db.get(MCPToolAttestation, attestation_id)
    if attestation is None:
        raise HTTPException(status_code=404, detail="MCP attestation not found")
    return attestation


def _scope_challenge(
    db: Session,
    challenge_id: str,
) -> MCPOAuthScopeChallenge:
    challenge = db.get(MCPOAuthScopeChallenge, challenge_id)
    if challenge is None:
        raise HTTPException(
            status_code=404,
            detail="MCP OAuth scope challenge not found",
        )
    return challenge


def _agent_worker(db: Session, worker_id: str) -> AgentWorker:
    worker = db.get(AgentWorker, worker_id)
    if worker is None:
        raise HTTPException(status_code=404, detail="Agent worker not found")
    return worker


def _authorize_attestor_worker(
    db: Session,
    worker: AgentWorker,
    authorization: str | None,
    peer_identity: WorkerPeerIdentity | None,
) -> None:
    try:
        authenticate_agent_worker(worker, authorization)
        verify_worker_peer(
            db,
            worker,
            peer_identity,
            kind="agent",
            mode=get_settings().worker_mtls_mode,
        )
    except (WorkerAuthenticationError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _require_attestor_registration_token(token: str | None) -> None:
    configured = get_settings().mcp_attestor_registration_token
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MCP attestor registration is not configured",
        )
    if token is None or not secrets.compare_digest(configured, token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MCP attestor registration token",
        )


@router.post(
    "/servers",
    response_model=MCPServerRead,
    status_code=status.HTTP_201_CREATED,
)
def create_mcp_server_route(
    payload: MCPServerCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPServer:
    trusted = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return create_mcp_server(
            db,
            trusted,
            allowed_hosts=get_settings().mcp_allowed_host_list,
        )
    except (ValueError, MCPGatewayError) as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/servers", response_model=list[MCPServerRead])
def list_mcp_servers_route(
    db: DBSession,
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> list[MCPServer]:
    query = select(MCPServer)
    if enabled is not None:
        query = query.where(MCPServer.enabled == enabled)
    return list(db.scalars(query.order_by(MCPServer.name).limit(limit)).all())


@router.get("/fleet/telemetry", response_model=MCPFleetTelemetryRead)
def get_mcp_fleet_telemetry_route(
    db: DBSession,
    stale_after_seconds: int = Query(default=900, ge=60, le=86400),
    server_limit: int = Query(default=200, ge=1, le=500),
    _: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPFleetTelemetryRead:
    return mcp_fleet_telemetry(
        db,
        stale_after_seconds=stale_after_seconds,
        server_limit=server_limit,
    )


@router.get("/servers/{server_id}", response_model=MCPServerRead)
def get_mcp_server_route(
    server_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPServer:
    return _server(db, server_id)


@router.get(
    "/oauth/client-metadata",
    response_model=MCPClientMetadataRead,
    include_in_schema=True,
)
def mcp_oauth_client_metadata() -> MCPClientMetadataRead:
    settings = get_settings()
    if not settings.mcp_oauth_client_metadata_url or not settings.mcp_oauth_redirect_uri:
        raise HTTPException(status_code=404, detail="MCP OAuth client metadata is disabled")
    return MCPClientMetadataRead(
        client_id=settings.mcp_oauth_client_metadata_url,
        client_name="iCheck MCP Agent",
        redirect_uris=[settings.mcp_oauth_redirect_uri],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
    )


@router.post(
    "/attestors/register",
    response_model=AgentWorkerRegistration,
)
def register_mcp_attestor_route(
    payload: AgentWorkerRegister,
    peer_identity: WorkerPeer,
    db: DBSession,
    x_icheck_registration_token: Annotated[
        str | None,
        Header(alias="X-iCheck-Registration-Token"),
    ] = None,
) -> AgentWorkerRegistration:
    _require_attestor_registration_token(x_icheck_registration_token)
    trusted = payload.model_copy(
        update={
            "capabilities": ["mcp_attestation"],
            "labels": {
                **payload.labels,
                "role": "mcp_attestor",
            },
        }
    )
    try:
        worker, access_token = register_agent_worker(
            db,
            trusted,
            peer_identity=peer_identity,
            mtls_mode=get_settings().worker_mtls_mode,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return AgentWorkerRegistration(
        worker=AgentWorkerRead.model_validate(worker),
        access_token=access_token,
    )


@router.get(
    "/servers/{server_id}/oauth/start",
    response_class=RedirectResponse,
)
def start_mcp_oauth_route(
    server_id: str,
    db: DBSession,
    return_to: str = Query(default="/settings/mcp", max_length=2048),
    scope_challenge_id: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> RedirectResponse:
    try:
        login = begin_mcp_oauth(
            db,
            _server(db, server_id),
            actor=principal.subject,
            principal=principal,
            return_to=return_to,
            scope_challenge_id=scope_challenge_id,
        )
    except MCPOAuthError as exc:
        code = 403 if exc.code == "authorization_withdrawn" else 503
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    settings = get_settings()
    response = RedirectResponse(login.authorization_url, status_code=302)
    response.set_cookie(
        key=MCP_OAUTH_TRANSACTION_COOKIE,
        value=login.browser_token,
        max_age=login.max_age_seconds,
        path="/api/v1/mcp/oauth",
        secure=settings.control_plane_session_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get(
    "/oauth/scope-challenges",
    response_model=list[MCPOAuthScopeChallengeRead],
)
def list_mcp_oauth_scope_challenges_route(
    db: DBSession,
    server_id: str | None = None,
    challenge_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> list[MCPOAuthScopeChallenge]:
    query = select(MCPOAuthScopeChallenge)
    if server_id:
        query = query.where(MCPOAuthScopeChallenge.server_id == server_id)
    if challenge_status:
        if challenge_status not in {"pending", "authorizing", "resolved"}:
            raise HTTPException(
                status_code=422,
                detail="Unsupported MCP OAuth scope challenge status",
            )
        query = query.where(MCPOAuthScopeChallenge.status == challenge_status)
    return list(
        db.scalars(
            query.order_by(MCPOAuthScopeChallenge.last_seen_at.desc()).limit(limit)
        ).all()
    )


@router.post(
    "/oauth/scope-challenges/{challenge_id}/approve",
    response_model=MCPOAuthScopeChallengeRead,
)
def approve_mcp_oauth_scope_challenge_route(
    challenge_id: str,
    payload: MCPOAuthScopeChallengeApproval,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPOAuthScopeChallenge:
    trusted = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return approve_mcp_scope_challenge(
            db,
            _scope_challenge(db, challenge_id),
            trusted,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/servers/{server_id}/oauth/consents", response_model=list[MCPOAuthConsentRead])
def list_mcp_oauth_consents_route(
    server_id: str, db: DBSession,
    limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0, le=100_000),
    _: PrincipalContext = Depends(require_global_permissions("tools.admin")),
):
    server = _server(db, server_id)
    return list(db.scalars(select(MCPOAuthConsentAttempt).where(
        MCPOAuthConsentAttempt.server_id == server.id,
        MCPOAuthConsentAttempt.tenant_id == server.tenant_id,
        MCPOAuthConsentAttempt.region_id == server.region_id,
    ).order_by(MCPOAuthConsentAttempt.admitted_at.desc(), MCPOAuthConsentAttempt.id.desc()).offset(offset).limit(limit)))


@router.get("/oauth/callback", response_class=RedirectResponse)
def complete_mcp_oauth_route(
    db: DBSession,
    state: str | None = Query(default=None, max_length=2048),
    code: str | None = Query(default=None, max_length=8192),
    error: str | None = Query(default=None, max_length=255),
    iss: str | None = Query(default=None, max_length=2048),
    browser_token: str | None = Cookie(
        default=None,
        alias=MCP_OAUTH_TRANSACTION_COOKIE,
    ),
) -> RedirectResponse:
    settings = get_settings()
    try:
        result = finish_mcp_oauth(
            db,
            state=state,
            browser_token=browser_token,
            code=code,
            issuer=iss,
            provider_error=error,
        )
        location = mcp_oauth_browser_location(
            settings,
            return_to=result.return_to,
            server_id=result.server_id,
        )
    except MCPOAuthError as exc:
        try:
            location = mcp_oauth_browser_location(
                settings,
                error_code=exc.code,
            )
        except MCPOAuthError as config_exc:
            raise HTTPException(status_code=503, detail=str(config_exc)) from exc
    response = RedirectResponse(location, status_code=303)
    response.delete_cookie(
        MCP_OAUTH_TRANSACTION_COOKIE,
        path="/api/v1/mcp/oauth",
        secure=settings.control_plane_session_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.post(
    "/servers/{server_id}/oauth/revoke",
    response_model=MCPServerRead,
)
def revoke_mcp_oauth_route(
    server_id: str,
    payload: MCPOAuthRevoke,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPServer:
    trusted = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return revoke_mcp_oauth(
            db,
            _server(db, server_id),
            actor=trusted.actor,
            reason=trusted.reason,
        )
    except MCPOAuthError as exc:
        code = 503 if exc.code == "revocation_pending" else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/servers/{server_id}/oauth/consents/{attempt_id}/family-recovery", response_model=MCPOAuthFamilyRecoveryRead)
def get_mcp_family_recovery_route(
    server_id: str, attempt_id: str, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("tools.admin")),
) -> MCPOAuthFamilyRecoveryRead:
    try:
        return read_family_recovery(db, _server(db, server_id), attempt_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Consent family recovery not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/servers/{server_id}/oauth/consents/{attempt_id}/family-recovery", response_model=MCPOAuthFamilyRecoveryRead)
def start_mcp_family_recovery_route(
    server_id: str, attempt_id: str, payload: MCPOAuthFamilyRecoveryStart, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("tools.admin")),
) -> MCPOAuthFamilyRecoveryRead:
    try:
        return start_family_recovery(db, _server(db, server_id), attempt_id, payload, actor=principal)
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="Consent attempt not found") from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/servers/{server_id}/oauth/consents/{attempt_id}/family-recovery/confirm", response_model=MCPOAuthFamilyRecoveryRead)
def confirm_mcp_family_recovery_route(
    server_id: str, attempt_id: str, payload: MCPOAuthFamilyRecoveryConfirm, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("tools.admin", "changes.approve")),
) -> MCPOAuthFamilyRecoveryRead:
    try:
        return confirm_family_recovery(db, _server(db, server_id), attempt_id, payload, actor=principal)
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="Consent attempt not found") from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/servers/{server_id}/oauth/consents/{attempt_id}/family-recovery/local", response_model=MCPOAuthFamilyLocalRead)
def get_mcp_family_local_route(
    server_id: str, attempt_id: str, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("tools.admin")),
) -> MCPOAuthFamilyLocalRead:
    try:
        return read_family_local(db, _server(db, server_id), attempt_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Local family recovery not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/servers/{server_id}/oauth/consents/{attempt_id}/family-recovery/local", response_model=MCPOAuthFamilyLocalRead)
def start_mcp_family_local_route(
    server_id: str, attempt_id: str, payload: MCPOAuthFamilyLocalStart, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("tools.admin", "changes.approve")),
) -> MCPOAuthFamilyLocalRead:
    try:
        return start_family_local(db, _server(db, server_id), attempt_id, payload, actor=principal)
    except (PermissionError, LookupError, ValueError, CredentialUnavailable, MCPOAuthError) as exc:
        db.rollback()
        code = 403 if isinstance(exc, PermissionError) else 404 if isinstance(exc, LookupError) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post("/servers/{server_id}/oauth/consents/{attempt_id}/family-recovery/local/execute", response_model=MCPOAuthFamilyLocalRead)
def execute_mcp_family_local_route(
    server_id: str, attempt_id: str, payload: MCPOAuthFamilyLocalExecute, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("tools.admin", "changes.approve")),
) -> MCPOAuthFamilyLocalRead:
    try:
        return execute_family_local(db, _server(db, server_id), attempt_id, payload, actor=principal)
    except (PermissionError, LookupError, ValueError, CredentialUnavailable, MCPOAuthError) as exc:
        db.rollback()
        code = 403 if isinstance(exc, PermissionError) else 404 if isinstance(exc, LookupError) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/servers/{server_id}/oauth/recovery", response_model=MCPOAuthRecoveryRead)
def get_mcp_oauth_recovery_route(
    server_id: str, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("tools.admin")),
) -> MCPOAuthRecoveryRead:
    server = _server(db, server_id)
    if server.oauth_recovery_custody is None:
        raise HTTPException(status_code=404, detail="OAuth recovery has not been started")
    try:
        return read_oauth_recovery(server)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/servers/{server_id}/oauth/recovery", response_model=MCPOAuthRecoveryRead)
def start_mcp_oauth_recovery_route(
    server_id: str, payload: MCPOAuthRecoveryStart, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("tools.admin")),
) -> MCPOAuthRecoveryRead:
    try:
        return start_oauth_recovery(db, _server(db, server_id), payload, actor=principal)
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="MCP server not found") from exc
    except (ValueError, CredentialUnavailable, MCPOAuthError) as exc:
        db.rollback()
        # Vault diagnostics are deliberately not exposed by this route.
        detail = "OAuth recovery target cannot be verified; cleanup remains fenced" if isinstance(exc, CredentialUnavailable) else str(exc)
        raise HTTPException(status_code=409, detail=detail) from exc


@router.post("/servers/{server_id}/oauth/recovery/confirm", response_model=MCPOAuthRecoveryRead)
def confirm_mcp_oauth_recovery_route(
    server_id: str, payload: MCPOAuthRecoveryConfirm, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("tools.admin", "changes.approve")),
) -> MCPOAuthRecoveryRead:
    try:
        return confirm_oauth_recovery(db, _server(db, server_id), payload, actor=principal)
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except MCPOAuthError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (ValueError, LookupError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/servers/{server_id}/check", response_model=MCPServerHealth)
def check_mcp_server_route(
    server_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPServerHealth:
    try:
        return check_mcp_server(
            db,
            _server(db, server_id),
            actor=principal.subject,
        )
    except MCPGatewayError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/servers/{server_id}/attestations",
    response_model=MCPToolAttestationRead,
    status_code=status.HTTP_201_CREATED,
)
def request_mcp_tool_attestation_route(
    server_id: str,
    payload: MCPToolAttestationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPToolAttestation:
    trusted = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return request_mcp_tool_attestation(
            db,
            _server(db, server_id),
            trusted,
            allowed_hosts=get_settings().mcp_allowed_host_list,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (MCPContractError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/attestations", response_model=list[MCPToolAttestationRead])
def list_mcp_tool_attestations_route(
    db: DBSession,
    server_id: str | None = None,
    artifact_version_id: str | None = None,
    attestation_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> list[MCPToolAttestation]:
    query = select(MCPToolAttestation)
    if server_id:
        query = query.where(MCPToolAttestation.server_id == server_id)
    if artifact_version_id:
        query = query.where(
            MCPToolAttestation.artifact_version_id == artifact_version_id
        )
    if attestation_status:
        allowed = {
            "pending",
            "processing",
            "passed",
            "failed",
            "dead_letter",
            "consumed",
        }
        if attestation_status not in allowed:
            raise HTTPException(status_code=422, detail="Unsupported attestation status")
        query = query.where(MCPToolAttestation.status == attestation_status)
    return list(
        db.scalars(
            query.order_by(MCPToolAttestation.created_at.desc()).limit(limit)
        ).all()
    )


@router.post(
    "/attestors/{worker_id}/attestations/claim",
    response_model=list[MCPToolAttestationAssignment],
)
def claim_mcp_tool_attestations_route(
    worker_id: str,
    payload: MCPAttestationClaim,
    peer_identity: WorkerPeer,
    db: DBSession,
    authorization: Annotated[str | None, Header()] = None,
) -> list[MCPToolAttestationAssignment]:
    worker = _agent_worker(db, worker_id)
    _authorize_attestor_worker(db, worker, authorization, peer_identity)
    try:
        return claim_mcp_tool_attestations(
            db,
            worker,
            payload,
            allowed_hosts=get_settings().mcp_allowed_host_list,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/attestors/{worker_id}/attestations/{attestation_id}/complete",
    response_model=MCPToolAttestationRead,
)
def complete_mcp_tool_attestation_route(
    worker_id: str,
    attestation_id: str,
    payload: MCPToolAttestationComplete,
    peer_identity: WorkerPeer,
    db: DBSession,
    authorization: Annotated[str | None, Header()] = None,
) -> MCPToolAttestation:
    worker = _agent_worker(db, worker_id)
    _authorize_attestor_worker(db, worker, authorization, peer_identity)
    try:
        return complete_mcp_tool_attestation(
            db,
            attestation_id,
            worker,
            payload,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (MCPAttestationLeaseLost, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/servers/{server_id}/activations",
    response_model=MCPToolActivationRead,
    status_code=status.HTTP_201_CREATED,
)
def activate_mcp_tool_route(
    server_id: str,
    payload: MCPToolActivationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPToolActivation:
    trusted = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return activate_mcp_tool(db, _server(db, server_id), trusted)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except MCPGatewayError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except MCPContractError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/activations", response_model=list[MCPToolActivationRead])
def list_mcp_activations_route(
    db: DBSession,
    server_id: str | None = None,
    activation_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> list[MCPToolActivation]:
    query = select(MCPToolActivation)
    if server_id:
        query = query.where(MCPToolActivation.server_id == server_id)
    if activation_status:
        if activation_status not in {"active", "inactive"}:
            raise HTTPException(status_code=422, detail="Unsupported activation status")
        query = query.where(MCPToolActivation.status == activation_status)
    return list(
        db.scalars(
            query.order_by(MCPToolActivation.created_at.desc()).limit(limit)
        ).all()
    )


@router.post(
    "/activations/{activation_id}/promote",
    response_model=MCPToolActivationRead,
)
def promote_mcp_tool_route(
    activation_id: str,
    payload: MCPToolRolloutAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPToolActivation:
    trusted = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return promote_mcp_tool(db, _activation(db, activation_id), trusted)
    except MCPContractError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/activations/{activation_id}/recover",
    response_model=MCPToolActivationRead,
)
def recover_mcp_tool_circuit_route(
    activation_id: str,
    payload: MCPToolCircuitRecovery,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPToolActivation:
    trusted = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return recover_mcp_tool_circuit(
            db,
            _activation(db, activation_id),
            trusted,
        )
    except MCPContractError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/activations/{activation_id}/deactivate",
    response_model=MCPToolActivationRead,
)
def deactivate_mcp_tool_route(
    activation_id: str,
    payload: MCPToolDeactivation,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("tools.admin")
    ),
) -> MCPToolActivation:
    trusted = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return deactivate_mcp_tool(
            db,
            _activation(db, activation_id),
            trusted,
        )
    except MCPContractError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
