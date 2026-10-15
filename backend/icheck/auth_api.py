from __future__ import annotations

import secrets

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import RedirectResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .auth import (
    current_principal,
    require_global_permissions,
)
from .auth_schemas import (
    AccessTokenCreate,
    AccessTokenIssue,
    AccessTokenRead,
    BrowserCsrfToken,
    BrowserSessionIssue,
    BrowserSessionRead,
    BrowserSessionRevoke,
    BrowserSessionsRevokeResult,
    BootstrapRequest,
    BootstrapResult,
    OIDCFederationConfigRead,
    OIDCIdentityCreate,
    OIDCIdentityRead,
    OIDCIdentityUpdate,
    PrincipalContextRead,
    PrincipalCreate,
    PrincipalRead,
    PrincipalUpdate,
    PasswordLogin,
    PasswordLoginConfig,
    PasswordChange,
    PrincipalPasswordSet,
    RoleBindingCreate,
    RoleBindingRead,
    RoleCreate,
    RoleRead,
    TokenRevoke,
    TrustedProxyFederationConfigRead,
    TrustedProxyIdentityCreate,
    TrustedProxyIdentityRead,
    TrustedProxyIdentityUpdate,
    WorkloadFederationConfigRead,
    WorkloadIdentityCreate,
    WorkloadIdentityRead,
    WorkloadIdentityUpdate,
    WorkloadTokenExchange,
    WorkloadTokenIssue,
)
from .config import get_settings
from .database import get_db
from .models import (
    ControlPlaneAccessToken,
    ControlPlaneBrowserSession,
    ControlPlaneOIDCIdentity,
    ControlPlanePrincipal,
    ControlPlaneRole,
    ControlPlaneRoleBinding,
    ControlPlaneTrustedProxyIdentity,
    ControlPlaneWorkloadIdentity,
    utcnow,
)
from .services.control_plane_auth import (
    ControlPlaneAuthenticationError,
    PrincipalContext,
    bootstrap_admin,
    create_browser_session,
    create_principal,
    create_role,
    create_role_binding,
    issue_access_token,
    revoke_browser_session,
    revoke_principal_browser_sessions,
    revoke_access_token,
    rotate_browser_csrf,
    revoke_role_binding,
    update_principal,
)
from .services.oidc_federation import (
    OIDCFederationError,
    begin_oidc_login,
    create_oidc_identity,
    finish_oidc_login,
    oidc_browser_location,
    update_oidc_identity,
)
from .services.trusted_proxy_federation import (
    TrustedProxyFederationError,
    create_trusted_proxy_identity,
    finish_trusted_proxy_login,
    trusted_proxy_browser_location,
    update_trusted_proxy_identity,
)
from .services.workload_federation import (
    WorkloadFederationError,
    create_workload_identity,
    exchange_workload_token,
    update_workload_identity,
)
from .services.local_password_auth import authenticate_password, set_principal_password


router = APIRouter(prefix="/api/v1/auth", tags=["control-plane-auth"])
OIDC_TRANSACTION_COOKIE = "icheck_oidc_txn"


def _browser_session_response(
    response: Response, db: Session, stored_principal: ControlPlanePrincipal,
    principal: PrincipalContext, *, auth_source: str,
) -> dict[str, object]:
    settings = get_settings()
    session, raw_token, csrf_token = create_browser_session(
        db, stored_principal,
        ttl_hours=settings.control_plane_browser_session_ttl_hours,
        actor=principal, auth_source=auth_source,
    )
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(
        key="icheck_session", value=raw_token,
        max_age=settings.control_plane_browser_session_ttl_hours * 3600,
        path="/", secure=settings.control_plane_session_cookie_secure,
        httponly=True, samesite=settings.control_plane_session_cookie_samesite,
    )
    return {"principal": _context_read(principal), "expires_at": session.expires_at,
            "csrf_token": csrf_token}


@router.get("/login/config", response_model=PasswordLoginConfig)
def password_login_config() -> PasswordLoginConfig:
    return PasswordLoginConfig(enabled=get_settings().control_plane_password_login_enabled)


@router.post("/login", response_model=BrowserSessionIssue, status_code=201)
def password_login(
    payload: PasswordLogin, request: Request, response: Response,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    settings = get_settings()
    if not settings.control_plane_password_login_enabled:
        raise HTTPException(status_code=403, detail="Password sign-in is disabled")
    origin = request.headers.get("origin")
    if origin is not None and origin not in settings.cors_origin_list:
        raise HTTPException(status_code=403, detail="Sign-in origin is not allowed")
    try:
        stored, principal = authenticate_password(
            db, username=payload.username, password=payload.password.get_secret_value(),
            tenant_selector=payload.tenant or settings.control_plane_password_login_tenant,
        )
    except ControlPlaneAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc), headers={"Cache-Control": "no-store"}) from exc
    return _browser_session_response(response, db, stored, principal, auth_source="local_password")


@router.put("/principals/{principal_id}/password", response_model=PrincipalRead)
def admin_set_password(
    principal_id: str, payload: PrincipalPasswordSet,
    actor: PrincipalContext = Depends(require_global_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> ControlPlanePrincipal:
    try:
        return set_principal_password(
            db, principal_id=principal_id, password=payload.password.get_secret_value(),
            actor=actor, reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/password/change", response_model=BrowserSessionIssue, status_code=201)
def change_own_password(
    payload: PasswordChange, response: Response,
    actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db),
) -> dict[str, object]:
    if actor.principal_id is None or actor.principal_type != "user":
        raise HTTPException(status_code=403, detail="A human account is required")
    try:
        stored, _ = authenticate_password(
            db, username=actor.subject, password=payload.current_password.get_secret_value(),
            tenant_selector=actor.tenant_id,
        )
        stored = set_principal_password(
            db, principal_id=stored.id, password=payload.new_password.get_secret_value(),
            actor=actor, reason="self_service_password_change", commit=False,
        )
    except ControlPlaneAuthenticationError as exc:
        # A failed reauthentication is not an expired browser session.
        raise HTTPException(status_code=400, detail="Current password is incorrect", headers={"Cache-Control": "no-store"}) from exc
    return _browser_session_response(response, db, stored, actor, auth_source="local_password")


def _principal(
    db: Session,
    principal_id: str,
    tenant_id: str,
) -> ControlPlanePrincipal:
    principal = db.scalar(
        select(ControlPlanePrincipal).where(
            ControlPlanePrincipal.id == principal_id,
            ControlPlanePrincipal.tenant_id == tenant_id,
        )
    )
    if principal is None:
        raise HTTPException(status_code=404, detail="Principal not found")
    return principal


def _context_read(context: PrincipalContext) -> PrincipalContextRead:
    return PrincipalContextRead(
        principal_id=context.principal_id,
        subject=context.subject,
        principal_type=context.principal_type,
        permissions=sorted(context.permissions),
        role_names=list(context.role_names),
        authorization_scope=context.authorization_scope,
        auth_method=context.auth_method,
        tenant_id=context.tenant_id,
        tenant_slug=context.tenant_slug,
        region_id=context.region_id,
        region_code=context.region_code,
        platform_admin=context.platform_admin,
    )


def _oidc_identity(
    db: Session,
    identity_id: str,
    tenant_id: str,
) -> ControlPlaneOIDCIdentity:
    identity = db.scalar(
        select(ControlPlaneOIDCIdentity).where(
            ControlPlaneOIDCIdentity.id == identity_id,
            ControlPlaneOIDCIdentity.tenant_id == tenant_id,
        )
    )
    if identity is None:
        raise HTTPException(status_code=404, detail="OIDC identity not found")
    return identity


def _trusted_proxy_identity(
    db: Session,
    identity_id: str,
    tenant_id: str,
) -> ControlPlaneTrustedProxyIdentity:
    identity = db.scalar(
        select(ControlPlaneTrustedProxyIdentity).where(
            ControlPlaneTrustedProxyIdentity.id == identity_id,
            ControlPlaneTrustedProxyIdentity.tenant_id == tenant_id,
        )
    )
    if identity is None:
        raise HTTPException(
            status_code=404,
            detail="Trusted-proxy identity not found",
        )
    return identity


def _workload_identity(
    db: Session,
    identity_id: str,
    tenant_id: str,
) -> ControlPlaneWorkloadIdentity:
    identity = db.scalar(
        select(ControlPlaneWorkloadIdentity).where(
            ControlPlaneWorkloadIdentity.id == identity_id,
            ControlPlaneWorkloadIdentity.tenant_id == tenant_id,
        )
    )
    if identity is None:
        raise HTTPException(status_code=404, detail="Workload identity not found")
    return identity


def _browser_session(
    db: Session,
    session_id: str,
    tenant_id: str,
) -> ControlPlaneBrowserSession:
    session = db.scalar(
        select(ControlPlaneBrowserSession).where(
            ControlPlaneBrowserSession.id == session_id,
            ControlPlaneBrowserSession.tenant_id == tenant_id,
        )
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Browser session not found")
    return session


@router.get(
    "/oidc/config",
    response_model=OIDCFederationConfigRead,
)
def oidc_federation_config() -> OIDCFederationConfigRead:
    settings = get_settings()
    return OIDCFederationConfigRead(
        enabled=settings.control_plane_oidc_enabled,
        display_name=(
            settings.control_plane_oidc_display_name
            if settings.control_plane_oidc_enabled
            else None
        ),
        start_url=(
            "/auth/oidc/start"
            if settings.control_plane_oidc_enabled
            else None
        ),
        local_token_login_enabled=(
            settings.control_plane_local_browser_login_enabled
        ),
    )


@router.get(
    "/trusted-proxy/config",
    response_model=TrustedProxyFederationConfigRead,
)
def trusted_proxy_federation_config() -> TrustedProxyFederationConfigRead:
    settings = get_settings()
    return TrustedProxyFederationConfigRead(
        enabled=settings.control_plane_trusted_proxy_enabled,
        display_name=(
            settings.control_plane_trusted_proxy_display_name
            if settings.control_plane_trusted_proxy_enabled
            else None
        ),
        start_url=(
            "/auth/trusted-proxy/callback"
            if settings.control_plane_trusted_proxy_enabled
            else None
        ),
    )


@router.get(
    "/workload/config",
    response_model=WorkloadFederationConfigRead,
)
def workload_federation_config() -> WorkloadFederationConfigRead:
    settings = get_settings()
    enabled = settings.control_plane_workload_oidc_enabled
    return WorkloadFederationConfigRead(
        enabled=enabled,
        issuer=(
            settings.control_plane_workload_oidc_issuer if enabled else None
        ),
        audience=(
            settings.control_plane_workload_oidc_audience if enabled else None
        ),
        token_ttl_minutes=(
            settings.control_plane_workload_token_ttl_minutes
            if enabled
            else None
        ),
    )


@router.post(
    "/workload/token",
    response_model=WorkloadTokenIssue,
)
def exchange_workload_token_route(
    payload: WorkloadTokenExchange,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    source_address = request.client.host if request.client is not None else None
    try:
        result = exchange_workload_token(
            db,
            payload.subject_token,
            source_address=source_address,
        )
    except WorkloadFederationError as exc:
        unavailable = exc.code in {"disabled", "provider_unavailable"}
        raise HTTPException(
            status_code=503 if unavailable else 401,
            detail=str(exc),
            headers=(
                {}
                if unavailable
                else {"WWW-Authenticate": 'Bearer error="invalid_token"'}
            ),
        ) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {
        "access_token": result.access_token,
        "issued_token_type": (
            "urn:ietf:params:oauth:token-type:access_token"
        ),
        "token_type": "Bearer",
        "expires_in": result.expires_in,
    }


@router.get("/oidc/start", response_class=RedirectResponse)
def start_oidc_login(
    return_to: str = Query(default="/", max_length=2048),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    try:
        login = begin_oidc_login(db, return_to)
    except OIDCFederationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    response = RedirectResponse(login.authorization_url, status_code=302)
    response.set_cookie(
        key=OIDC_TRANSACTION_COOKIE,
        value=login.browser_token,
        max_age=login.max_age_seconds,
        path="/api/v1/auth/oidc",
        secure=get_settings().control_plane_session_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/oidc/callback", response_class=RedirectResponse)
def complete_oidc_login(
    state: str | None = Query(default=None, max_length=2048),
    code: str | None = Query(default=None, max_length=8192),
    error: str | None = Query(default=None, max_length=255),
    browser_token: str | None = Cookie(
        default=None,
        alias=OIDC_TRANSACTION_COOKIE,
    ),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    settings = get_settings()
    try:
        result = finish_oidc_login(
            db,
            state=state,
            browser_token=browser_token,
            code=code,
            provider_error=error,
        )
        location = oidc_browser_location(
            settings,
            return_to=result.return_to,
        )
        response = RedirectResponse(location, status_code=303)
        response.set_cookie(
            key="icheck_session",
            value=result.session_token,
            max_age=settings.control_plane_browser_session_ttl_hours * 3600,
            path="/",
            secure=settings.control_plane_session_cookie_secure,
            httponly=True,
            samesite=settings.control_plane_session_cookie_samesite,
        )
    except OIDCFederationError as exc:
        try:
            location = oidc_browser_location(settings, error_code=exc.code)
        except OIDCFederationError as config_exc:
            raise HTTPException(status_code=503, detail=str(config_exc)) from exc
        response = RedirectResponse(location, status_code=303)
    response.delete_cookie(
        OIDC_TRANSACTION_COOKIE,
        path="/api/v1/auth/oidc",
        secure=settings.control_plane_session_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get(
    "/trusted-proxy/callback",
    response_class=RedirectResponse,
)
def complete_trusted_proxy_login(
    request: Request,
    return_to: str = Query(default="/", max_length=2048),
    verified: str | None = Header(
        default=None,
        alias="X-Icheck-Trusted-Proxy-Verified",
    ),
    subject: str | None = Header(
        default=None,
        alias="X-Icheck-Trusted-Proxy-Subject",
    ),
    shared_secret: str | None = Header(
        default=None,
        alias="X-Icheck-Trusted-Proxy-Secret",
    ),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    settings = get_settings()
    source_address = request.client.host if request.client is not None else None
    try:
        result = finish_trusted_proxy_login(
            db,
            source_address=source_address,
            verified=verified,
            subject=subject,
            shared_secret=shared_secret,
            return_to=return_to,
            settings=settings,
        )
        response = RedirectResponse(
            trusted_proxy_browser_location(
                settings,
                return_to=result.return_to,
            ),
            status_code=303,
        )
        response.set_cookie(
            key="icheck_session",
            value=result.session_token,
            max_age=settings.control_plane_browser_session_ttl_hours * 3600,
            path="/",
            secure=settings.control_plane_session_cookie_secure,
            httponly=True,
            samesite=settings.control_plane_session_cookie_samesite,
        )
        return response
    except TrustedProxyFederationError as exc:
        if (
            not settings.control_plane_trusted_proxy_enabled
            or not settings.control_plane_trusted_proxy_success_url
        ):
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        try:
            location = trusted_proxy_browser_location(
                settings,
                error_code=exc.code,
            )
        except TrustedProxyFederationError as config_exc:
            raise HTTPException(
                status_code=503,
                detail=str(config_exc),
            ) from exc
        return RedirectResponse(location, status_code=303)


@router.post(
    "/bootstrap",
    response_model=BootstrapResult,
    status_code=status.HTTP_201_CREATED,
)
def bootstrap_control_plane(
    payload: BootstrapRequest,
    bootstrap_token: str | None = Header(
        default=None, alias="X-Icheck-Bootstrap-Token"
    ),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    settings = get_settings()
    configured = settings.control_plane_bootstrap_token
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Control-plane bootstrap is not configured",
        )
    if bootstrap_token is None or not secrets.compare_digest(
        configured, bootstrap_token
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid control-plane bootstrap token",
        )
    if not payload.enabled:
        raise HTTPException(
            status_code=422,
            detail="Bootstrap administrator must be enabled",
        )
    try:
        principal, token, raw_token = bootstrap_admin(
            db,
            payload,
            default_token_ttl_hours=settings.control_plane_default_token_ttl_hours,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "principal": principal,
        "token": {"token": token, "access_token": raw_token},
    }


@router.get("/me", response_model=PrincipalContextRead)
def get_current_principal(
    principal: PrincipalContext = Depends(current_principal),
) -> PrincipalContextRead:
    return _context_read(principal)


@router.post(
    "/browser-sessions",
    response_model=BrowserSessionIssue,
    status_code=status.HTTP_201_CREATED,
)
def issue_browser_session(
    response: Response,
    principal: PrincipalContext = Depends(current_principal),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    if not get_settings().control_plane_local_browser_login_enabled:
        raise HTTPException(
            status_code=403,
            detail="Local token-to-browser session exchange is disabled",
        )
    if principal.auth_method != "bearer" or principal.principal_id is None:
        raise HTTPException(
            status_code=409,
            detail="A control-plane bearer token is required for session exchange",
        )
    stored_principal = _principal(
        db, principal.principal_id, principal.tenant_id
    )
    return _browser_session_response(
        response, db, stored_principal, principal, auth_source="local_token",
    )


@router.get(
    "/browser-sessions/current/csrf",
    response_model=BrowserCsrfToken,
)
def refresh_browser_csrf(
    principal: PrincipalContext = Depends(current_principal),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    if (
        principal.auth_method != "browser_session"
        or principal.session_id is None
    ):
        raise HTTPException(status_code=409, detail="Browser session is required")
    try:
        return {"csrf_token": rotate_browser_csrf(db, principal.session_id)}
    except ControlPlaneAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.delete(
    "/browser-sessions/current",
    status_code=status.HTTP_204_NO_CONTENT,
)
def close_browser_session(
    response: Response,
    principal: PrincipalContext = Depends(current_principal),
    db: Session = Depends(get_db),
) -> Response:
    if (
        principal.auth_method != "browser_session"
        or principal.session_id is None
    ):
        raise HTTPException(status_code=409, detail="Browser session is required")
    revoke_browser_session(db, principal.session_id, actor=principal)
    response.delete_cookie(
        "icheck_session",
        path="/",
        secure=get_settings().control_plane_session_cookie_secure,
        httponly=True,
        samesite=get_settings().control_plane_session_cookie_samesite,
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get(
    "/browser-sessions",
    response_model=list[BrowserSessionRead],
)
def list_browser_sessions(
    principal_id: str | None = None,
    active: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> list[ControlPlaneBrowserSession]:
    query = select(ControlPlaneBrowserSession).where(
        ControlPlaneBrowserSession.tenant_id == actor.tenant_id
    )
    if principal_id:
        query = query.where(
            ControlPlaneBrowserSession.principal_id == principal_id
        )
    if active is True:
        query = query.where(
            ControlPlaneBrowserSession.revoked_at.is_(None),
            ControlPlaneBrowserSession.expires_at > utcnow(),
        )
    elif active is False:
        query = query.where(
            or_(
                ControlPlaneBrowserSession.revoked_at.is_not(None),
                ControlPlaneBrowserSession.expires_at <= utcnow(),
            )
        )
    return list(
        db.scalars(
            query.order_by(ControlPlaneBrowserSession.created_at.desc()).limit(
                limit
            )
        ).all()
    )


@router.post(
    "/browser-sessions/{session_id}/revoke",
    response_model=BrowserSessionRead,
)
def revoke_browser_session_route(
    session_id: str,
    payload: BrowserSessionRevoke,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneBrowserSession:
    session = _browser_session(db, session_id, actor.tenant_id)
    return revoke_browser_session(
        db,
        session.id,
        actor=actor,
        reason=payload.reason,
    )


@router.post(
    "/principals/{principal_id}/browser-sessions/revoke",
    response_model=BrowserSessionsRevokeResult,
)
def revoke_principal_browser_sessions_route(
    principal_id: str,
    payload: BrowserSessionRevoke,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    principal = _principal(db, principal_id, actor.tenant_id)
    return {
        "principal_id": principal.id,
        "revoked_count": revoke_principal_browser_sessions(
            db,
            principal_id=principal.id,
            reason=payload.reason,
            actor=actor,
        ),
    }


@router.post(
    "/principals",
    response_model=PrincipalRead,
    status_code=status.HTTP_201_CREATED,
)
def create_principal_route(
    payload: PrincipalCreate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlanePrincipal:
    try:
        return create_principal(db, payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/principals", response_model=list[PrincipalRead])
def list_principals(
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    actor: PrincipalContext = Depends(require_global_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> list[ControlPlanePrincipal]:
    query = select(ControlPlanePrincipal).where(
        ControlPlanePrincipal.tenant_id == actor.tenant_id
    )
    if enabled is not None:
        query = query.where(ControlPlanePrincipal.enabled == enabled)
    return list(
        db.scalars(query.order_by(ControlPlanePrincipal.subject).limit(limit)).all()
    )


@router.patch("/principals/{principal_id}", response_model=PrincipalRead)
def update_principal_route(
    principal_id: str,
    payload: PrincipalUpdate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlanePrincipal:
    try:
        return update_principal(
            db,
            _principal(db, principal_id, actor.tenant_id),
            payload,
            actor=actor,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/principals/{principal_id}/oidc-identities",
    response_model=OIDCIdentityRead,
    status_code=status.HTTP_201_CREATED,
)
def create_oidc_identity_route(
    principal_id: str,
    payload: OIDCIdentityCreate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneOIDCIdentity:
    try:
        return create_oidc_identity(
            db,
            _principal(db, principal_id, actor.tenant_id),
            payload,
            actor=actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/principals/{principal_id}/oidc-identities",
    response_model=list[OIDCIdentityRead],
)
def list_oidc_identities(
    principal_id: str,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> list[ControlPlaneOIDCIdentity]:
    principal = _principal(db, principal_id, actor.tenant_id)
    return list(
        db.scalars(
            select(ControlPlaneOIDCIdentity)
            .where(
                ControlPlaneOIDCIdentity.principal_id == principal.id,
                ControlPlaneOIDCIdentity.tenant_id == actor.tenant_id,
            )
            .order_by(ControlPlaneOIDCIdentity.created_at)
        ).all()
    )


@router.patch(
    "/oidc-identities/{identity_id}",
    response_model=OIDCIdentityRead,
)
def update_oidc_identity_route(
    identity_id: str,
    payload: OIDCIdentityUpdate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneOIDCIdentity:
    return update_oidc_identity(
        db,
        _oidc_identity(db, identity_id, actor.tenant_id),
        payload,
        actor=actor,
    )


@router.post(
    "/principals/{principal_id}/trusted-proxy-identities",
    response_model=TrustedProxyIdentityRead,
    status_code=status.HTTP_201_CREATED,
)
def create_trusted_proxy_identity_route(
    principal_id: str,
    payload: TrustedProxyIdentityCreate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneTrustedProxyIdentity:
    try:
        return create_trusted_proxy_identity(
            db,
            _principal(db, principal_id, actor.tenant_id),
            payload,
            actor=actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/principals/{principal_id}/trusted-proxy-identities",
    response_model=list[TrustedProxyIdentityRead],
)
def list_trusted_proxy_identities(
    principal_id: str,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> list[ControlPlaneTrustedProxyIdentity]:
    principal = _principal(db, principal_id, actor.tenant_id)
    return list(
        db.scalars(
            select(ControlPlaneTrustedProxyIdentity)
            .where(
                ControlPlaneTrustedProxyIdentity.principal_id == principal.id,
                ControlPlaneTrustedProxyIdentity.tenant_id == actor.tenant_id,
            )
            .order_by(ControlPlaneTrustedProxyIdentity.created_at)
        ).all()
    )


@router.patch(
    "/trusted-proxy-identities/{identity_id}",
    response_model=TrustedProxyIdentityRead,
)
def update_trusted_proxy_identity_route(
    identity_id: str,
    payload: TrustedProxyIdentityUpdate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneTrustedProxyIdentity:
    return update_trusted_proxy_identity(
        db,
        _trusted_proxy_identity(db, identity_id, actor.tenant_id),
        payload,
        actor=actor,
    )


@router.post(
    "/principals/{principal_id}/workload-identities",
    response_model=WorkloadIdentityRead,
    status_code=status.HTTP_201_CREATED,
)
def create_workload_identity_route(
    principal_id: str,
    payload: WorkloadIdentityCreate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneWorkloadIdentity:
    try:
        return create_workload_identity(
            db,
            _principal(db, principal_id, actor.tenant_id),
            payload,
            actor=actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/principals/{principal_id}/workload-identities",
    response_model=list[WorkloadIdentityRead],
)
def list_workload_identities(
    principal_id: str,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> list[ControlPlaneWorkloadIdentity]:
    principal = _principal(db, principal_id, actor.tenant_id)
    return list(
        db.scalars(
            select(ControlPlaneWorkloadIdentity)
            .where(
                ControlPlaneWorkloadIdentity.principal_id == principal.id,
                ControlPlaneWorkloadIdentity.tenant_id == actor.tenant_id,
            )
            .order_by(ControlPlaneWorkloadIdentity.created_at)
        ).all()
    )


@router.patch(
    "/workload-identities/{identity_id}",
    response_model=WorkloadIdentityRead,
)
def update_workload_identity_route(
    identity_id: str,
    payload: WorkloadIdentityUpdate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneWorkloadIdentity:
    return update_workload_identity(
        db,
        _workload_identity(db, identity_id, actor.tenant_id),
        payload,
        actor=actor,
    )


@router.post(
    "/roles",
    response_model=RoleRead,
    status_code=status.HTTP_201_CREATED,
)
def create_role_route(
    payload: RoleCreate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneRole:
    try:
        return create_role(db, payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/roles", response_model=list[RoleRead])
def list_roles(
    limit: int = Query(default=100, ge=1, le=1000),
    actor: PrincipalContext = Depends(require_global_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> list[ControlPlaneRole]:
    return list(
        db.scalars(
            select(ControlPlaneRole)
            .where(
                or_(
                    ControlPlaneRole.system.is_(True),
                    (
                        (ControlPlaneRole.tenant_id == actor.tenant_id)
                        & (ControlPlaneRole.region_id == actor.region_id)
                    ),
                )
            )
            .order_by(ControlPlaneRole.name)
            .limit(limit)
        ).all()
    )


@router.post(
    "/principals/{principal_id}/bindings",
    response_model=RoleBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_role_binding_route(
    principal_id: str,
    payload: RoleBindingCreate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneRoleBinding:
    try:
        return create_role_binding(
            db,
            _principal(db, principal_id, actor.tenant_id),
            payload,
            actor=actor,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "already" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/principals/{principal_id}/bindings",
    response_model=list[RoleBindingRead],
)
def list_role_bindings(
    principal_id: str,
    actor: PrincipalContext = Depends(require_global_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> list[ControlPlaneRoleBinding]:
    _principal(db, principal_id, actor.tenant_id)
    return list(
        db.scalars(
            select(ControlPlaneRoleBinding)
            .where(
                ControlPlaneRoleBinding.principal_id == principal_id,
                ControlPlaneRoleBinding.tenant_id == actor.tenant_id,
                ControlPlaneRoleBinding.region_id == actor.region_id,
            )
            .order_by(ControlPlaneRoleBinding.created_at)
        ).all()
    )


@router.post(
    "/bindings/{binding_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_role_binding_route(
    binding_id: str,
    payload: TokenRevoke,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> Response:
    try:
        revoke_role_binding(
            db,
            binding_id,
            reason=payload.reason,
            actor=actor,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/principals/{principal_id}/tokens",
    response_model=AccessTokenIssue,
    status_code=status.HTTP_201_CREATED,
)
def issue_access_token_route(
    principal_id: str,
    payload: AccessTokenCreate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    settings = get_settings()
    try:
        token, raw_token = issue_access_token(
            db,
            _principal(db, principal_id, actor.tenant_id),
            payload,
            actor=actor,
            default_token_ttl_hours=settings.control_plane_default_token_ttl_hours,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"token": token, "access_token": raw_token}


@router.get(
    "/principals/{principal_id}/tokens",
    response_model=list[AccessTokenRead],
)
def list_access_tokens(
    principal_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    actor: PrincipalContext = Depends(require_global_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> list[ControlPlaneAccessToken]:
    _principal(db, principal_id, actor.tenant_id)
    return list(
        db.scalars(
            select(ControlPlaneAccessToken)
            .where(ControlPlaneAccessToken.principal_id == principal_id)
            .order_by(ControlPlaneAccessToken.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.post("/tokens/{token_id}/revoke", response_model=AccessTokenRead)
def revoke_access_token_route(
    token_id: str,
    payload: TokenRevoke,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> ControlPlaneAccessToken:
    token = db.get(ControlPlaneAccessToken, token_id)
    if (
        token is None
        or token.principal.tenant_id != actor.tenant_id
    ):
        raise HTTPException(status_code=404, detail="Access token not found")
    try:
        return revoke_access_token(db, token, reason=payload.reason, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
