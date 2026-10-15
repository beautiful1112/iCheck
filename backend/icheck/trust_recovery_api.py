from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .database import get_db
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext
from .services.trust_recovery import (
    cancel_root_reanchor,
    create_recovery_policy,
    create_recovery_policy_statement,
    create_root_reanchor_statement,
    execute_root_reanchor,
    export_recovery_policy,
    export_root_reanchor,
    list_recovery_policies,
    list_root_reanchors,
    preview_root_reanchor,
    propose_root_reanchor,
)
from .services.trust_recovery_signing import (
    RecoverySigningPermanentError,
    RecoverySigningUnavailable,
    create_signing_provider,
    list_signing_events,
    list_signing_providers,
    set_signing_provider_state,
    sign_recovery_policy_with_provider,
    sign_root_reanchor_with_providers,
    update_signing_provider_tls,
)
from .trust_recovery_schemas import (
    OrganizationTrustRecoveryPolicyCreate,
    OrganizationTrustRecoveryPolicyRead,
    OrganizationTrustRecoveryPolicyStatement,
    OrganizationTrustRecoveryPolicyStatementCreate,
    OrganizationTrustRootReanchorAction,
    OrganizationTrustRootReanchorPreviewCreate,
    OrganizationTrustRootReanchorPreviewRead,
    OrganizationTrustRootReanchorProposalCreate,
    OrganizationTrustRootReanchorRead,
    OrganizationTrustRootReanchorStatement,
    OrganizationTrustRootReanchorStatementCreate,
    SignedOrganizationTrustRecoveryPolicy,
    SignedOrganizationTrustRootReanchor,
    TrustRecoveryPolicyProviderSignCreate,
    TrustRecoveryReanchorProviderSignCreate,
    TrustRecoverySigningEventRead,
    TrustRecoverySigningProviderCreate,
    TrustRecoverySigningProviderRead,
    TrustRecoverySigningProviderStateCreate,
    TrustRecoverySigningProviderTLSUpdate,
)


router = APIRouter(
    prefix="/api/v1/organization-trust",
    tags=["organization-trust-recovery"],
)
DBSession = Annotated[Session, Depends(get_db)]


def _raise_signing_error(exc: Exception) -> None:
    if isinstance(exc, LookupError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, RecoverySigningUnavailable):
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if isinstance(exc, RecoverySigningPermanentError):
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/recovery-signing/providers",
    response_model=TrustRecoverySigningProviderRead,
    status_code=status.HTTP_201_CREATED,
)
def create_signing_provider_route(
    payload: TrustRecoverySigningProviderCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TrustRecoverySigningProviderRead:
    try:
        provider = create_signing_provider(
            db,
            payload,
            actor=request_actor(principal, payload.created_by),
        )
        return TrustRecoverySigningProviderRead.model_validate(provider)
    except (LookupError, ValueError) as exc:
        _raise_signing_error(exc)


@router.get(
    "/recovery-signing/providers",
    response_model=list[TrustRecoverySigningProviderRead],
)
def list_signing_providers_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[TrustRecoverySigningProviderRead]:
    return [
        TrustRecoverySigningProviderRead.model_validate(item)
        for item in list_signing_providers(db, limit=limit)
    ]


@router.post(
    "/recovery-signing/providers/{provider_id}/state",
    response_model=TrustRecoverySigningProviderRead,
)
def set_signing_provider_state_route(
    provider_id: str,
    payload: TrustRecoverySigningProviderStateCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TrustRecoverySigningProviderRead:
    try:
        provider = set_signing_provider_state(
            db,
            provider_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return TrustRecoverySigningProviderRead.model_validate(provider)
    except (LookupError, ValueError) as exc:
        _raise_signing_error(exc)


@router.put(
    "/recovery-signing/providers/{provider_id}/tls",
    response_model=TrustRecoverySigningProviderRead,
)
def update_signing_provider_tls_route(
    provider_id: str,
    payload: TrustRecoverySigningProviderTLSUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TrustRecoverySigningProviderRead:
    try:
        provider = update_signing_provider_tls(
            db,
            provider_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return TrustRecoverySigningProviderRead.model_validate(provider)
    except (LookupError, ValueError) as exc:
        _raise_signing_error(exc)


@router.get(
    "/recovery-signing/events",
    response_model=list[TrustRecoverySigningEventRead],
)
def list_signing_events_route(
    db: DBSession,
    provider_id: Annotated[str | None, Query(max_length=36)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[TrustRecoverySigningEventRead]:
    return [
        TrustRecoverySigningEventRead.model_validate(item)
        for item in list_signing_events(
            db,
            provider_id=provider_id,
            limit=limit,
        )
    ]


@router.post(
    "/domains/{domain_id}/recovery-policy-statements/sign",
    response_model=SignedOrganizationTrustRecoveryPolicy,
)
def sign_recovery_policy_statement_route(
    domain_id: str,
    payload: TrustRecoveryPolicyProviderSignCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> SignedOrganizationTrustRecoveryPolicy:
    try:
        return sign_recovery_policy_with_provider(
            db,
            domain_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except (
        LookupError,
        RecoverySigningPermanentError,
        RecoverySigningUnavailable,
        ValueError,
    ) as exc:
        _raise_signing_error(exc)


@router.post(
    "/domains/{domain_id}/root-reanchor-statements/sign",
    response_model=SignedOrganizationTrustRootReanchor,
)
def sign_root_reanchor_statement_route(
    domain_id: str,
    payload: TrustRecoveryReanchorProviderSignCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> SignedOrganizationTrustRootReanchor:
    try:
        return sign_root_reanchor_with_providers(
            db,
            domain_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except (
        LookupError,
        RecoverySigningPermanentError,
        RecoverySigningUnavailable,
        ValueError,
    ) as exc:
        _raise_signing_error(exc)



@router.post(
    "/domains/{domain_id}/recovery-policy-statements",
    response_model=OrganizationTrustRecoveryPolicyStatement,
)
def create_recovery_policy_statement_route(
    domain_id: str,
    payload: OrganizationTrustRecoveryPolicyStatementCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustRecoveryPolicyStatement:
    try:
        return create_recovery_policy_statement(
            db,
            domain_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/domains/{domain_id}/recovery-policies",
    response_model=OrganizationTrustRecoveryPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
def create_recovery_policy_route(
    domain_id: str,
    payload: OrganizationTrustRecoveryPolicyCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustRecoveryPolicyRead:
    try:
        return OrganizationTrustRecoveryPolicyRead.model_validate(
            create_recovery_policy(
                db,
                domain_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/recovery-policies",
    response_model=list[OrganizationTrustRecoveryPolicyRead],
)
def list_recovery_policies_route(
    db: DBSession,
    domain_id: Annotated[str | None, Query(max_length=36)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[OrganizationTrustRecoveryPolicyRead]:
    return [
        OrganizationTrustRecoveryPolicyRead.model_validate(item)
        for item in list_recovery_policies(
            db,
            domain_id=domain_id,
            limit=limit,
        )
    ]


@router.get(
    "/recovery-policies/{policy_id}/export",
    response_model=SignedOrganizationTrustRecoveryPolicy,
)
def export_recovery_policy_route(
    policy_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> SignedOrganizationTrustRecoveryPolicy:
    try:
        return SignedOrganizationTrustRecoveryPolicy.model_validate(
            export_recovery_policy(db, policy_id)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/domains/{domain_id}/root-reanchor-statements",
    response_model=OrganizationTrustRootReanchorStatement,
)
def create_root_reanchor_statement_route(
    domain_id: str,
    payload: OrganizationTrustRootReanchorStatementCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustRootReanchorStatement:
    try:
        return create_root_reanchor_statement(
            db,
            domain_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/domains/{domain_id}/root-reanchors/preview",
    response_model=OrganizationTrustRootReanchorPreviewRead,
)
def preview_root_reanchor_route(
    domain_id: str,
    payload: OrganizationTrustRootReanchorPreviewCreate,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustRootReanchorPreviewRead:
    try:
        return preview_root_reanchor(db, domain_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/domains/{domain_id}/root-reanchors",
    response_model=OrganizationTrustRootReanchorRead,
    status_code=status.HTTP_201_CREATED,
)
def propose_root_reanchor_route(
    domain_id: str,
    payload: OrganizationTrustRootReanchorProposalCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustRootReanchorRead:
    try:
        return OrganizationTrustRootReanchorRead.model_validate(
            propose_root_reanchor(
                db,
                domain_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/root-reanchors",
    response_model=list[OrganizationTrustRootReanchorRead],
)
def list_root_reanchors_route(
    db: DBSession,
    domain_id: Annotated[str | None, Query(max_length=36)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[OrganizationTrustRootReanchorRead]:
    return [
        OrganizationTrustRootReanchorRead.model_validate(item)
        for item in list_root_reanchors(
            db,
            domain_id=domain_id,
            limit=limit,
        )
    ]


@router.get(
    "/root-reanchors/{request_id}/export",
    response_model=SignedOrganizationTrustRootReanchor,
)
def export_root_reanchor_route(
    request_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> SignedOrganizationTrustRootReanchor:
    try:
        return SignedOrganizationTrustRootReanchor.model_validate(
            export_root_reanchor(db, request_id)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/root-reanchors/{request_id}/execute",
    response_model=OrganizationTrustRootReanchorRead,
)
def execute_root_reanchor_route(
    request_id: str,
    payload: OrganizationTrustRootReanchorAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustRootReanchorRead:
    try:
        return OrganizationTrustRootReanchorRead.model_validate(
            execute_root_reanchor(
                db,
                request_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/root-reanchors/{request_id}/cancel",
    response_model=OrganizationTrustRootReanchorRead,
)
def cancel_root_reanchor_route(
    request_id: str,
    payload: OrganizationTrustRootReanchorAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustRootReanchorRead:
    try:
        return OrganizationTrustRootReanchorRead.model_validate(
            cancel_root_reanchor(
                db,
                request_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
