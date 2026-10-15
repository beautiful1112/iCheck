from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, selectinload

from .auth import require_global_permissions, require_permissions
from .activation_schemas import (
    ActivationApproval,
    ActivationCollectorOption,
    ActivationCollectorPage,
    ActivationCollectorSummary,
    ActivationDraftScopePreview,
    ActivationDraftScopePreviewRequest,
    ActivationDeactivate,
    ActivationPlanRead,
    ActivationPolicyAction,
    ActivationPolicyDraftUpdate,
    ActivationPolicyProposalRead,
    ActivationProposalScopePreview,
    ActivationPolicyProposalRecordRead,
    ActivationPolicyProposalInterrupt,
    ActivationPolicyProposalAdminInterrupt,
    ActivationPolicyProposalAdminRecoveryRead,
    ActivationPolicyProposalRequest,
    ActivationPreviewRequest,
    DeviceActivationPolicyCreate,
    DeviceActivationPolicyRead,
    DeviceActivationPolicyPage,
    DeviceActivationResult,
)
from .database import get_db
from .models import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    ActivationPolicyProposal,
    CollectorDefinition,
    DeviceActivationPolicy,
)
from .services.activation import (
    ActivationPolicyRevisionConflict,
    approve_activation,
    create_activation_policy,
    deactivate_connection,
    preview_activation,
    publish_activation_policy,
    update_activation_policy_draft,
    validate_activation_policy,
)
from .services.authorization_scope import (
    request_actor,
    require_device_access,
)
from .services.control_plane_auth import PrincipalContext
from .services.devices import PROTOCOL_ACTIVATION_ADAPTERS
from .services.activation_proposals import (
    ProposalConflict,
    admin_proposal_record,
    administratively_interrupt_activation_policy_proposal,
    interrupt_activation_policy_proposal,
    proposal_record,
    propose_activation_policy,
)
from .services.activation_scope_preview import (
    preview_draft_scope,
    preview_proposal_scope,
)
from .services.ai_authoring_quota import (
    AuthoringQuotaConflict,
    AuthoringQuotaExceeded,
)
from .services.structured_model import StructuredModelUnavailable


router = APIRouter(prefix="/api/v1/assets", tags=["asset-activation"])
ACTIVATABLE_ADAPTERS = frozenset().union(*PROTOCOL_ACTIVATION_ADAPTERS.values())


db_session = get_db


@router.get(
    "/activation-collectors",
    response_model=list[ActivationCollectorOption],
)
def list_activation_collectors(
    limit: int = Query(default=500, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> list[ActivationCollectorOption]:
    """Expose published collector contracts, not implementation source, to asset operators."""
    versions = db.scalars(
        select(ArtifactVersion)
        .join(Artifact)
        .join(CollectorDefinition)
        .where(
            Artifact.kind == ArtifactKind.COLLECTOR,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            CollectorDefinition.adapter_type.in_(ACTIVATABLE_ADAPTERS),
        )
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
        .order_by(Artifact.name, ArtifactVersion.version.desc())
        .limit(limit)
    ).all()
    return [
        ActivationCollectorOption(
            artifact_version_id=version.id,
            artifact_name=version.artifact.name,
            version=version.version,
            adapter_type=version.collector_definition.adapter_type,
            target_schema=version.collector_definition.target_schema,
            config_schema=version.collector_definition.config_schema,
            defaults=version.collector_definition.defaults,
        )
        for version in versions
    ]


def _prefix_pattern(value: str | None) -> str | None:
    if value is None:
        return None
    prefix = value.strip()
    if not prefix:
        return None
    return prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/activation-collectors/page", response_model=ActivationCollectorPage)
def page_activation_collectors(
    protocol: str | None = Query(default=None, max_length=32),
    name_prefix: str | None = Query(default=None, max_length=128),
    cursor: str | None = Query(default=None, max_length=36),
    limit: int = Query(default=50, ge=1, le=100),
    _: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> ActivationCollectorPage:
    """Keyset-page published, activatable summaries; contracts load by exact ID."""
    if protocol is not None and protocol not in PROTOCOL_ACTIVATION_ADAPTERS:
        raise HTTPException(status_code=400, detail="Unknown activation protocol")
    adapters = PROTOCOL_ACTIVATION_ADAPTERS[protocol] if protocol else ACTIVATABLE_ADAPTERS
    criteria = [
        Artifact.kind == ArtifactKind.COLLECTOR,
        ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        CollectorDefinition.adapter_type.in_(adapters),
    ]
    pattern = _prefix_pattern(name_prefix)
    if pattern is not None:
        criteria.append(Artifact.name.ilike(pattern, escape="\\"))
    if cursor is not None:
        marker = db.execute(select(ArtifactVersion, Artifact.name)
            .join(Artifact).join(CollectorDefinition)
            .where(ArtifactVersion.id == cursor, *criteria)).first()
        if marker is None:
            raise HTTPException(status_code=400, detail="Activation collector cursor is unavailable")
        version, name = marker
        criteria.append(or_(
            Artifact.name > name,
            and_(Artifact.name == name, ArtifactVersion.version < version.version),
            and_(Artifact.name == name, ArtifactVersion.version == version.version,
                 ArtifactVersion.id > version.id),
        ))
    rows = db.execute(select(
        ArtifactVersion.id, Artifact.name, ArtifactVersion.version,
        CollectorDefinition.adapter_type,
    ).join(Artifact).join(CollectorDefinition)
        .where(*criteria)
        .order_by(Artifact.name, ArtifactVersion.version.desc(), ArtifactVersion.id)
        .limit(limit + 1)).all()
    page = rows[:limit]
    return ActivationCollectorPage(
        items=[ActivationCollectorSummary(
            artifact_version_id=row[0], artifact_name=row[1],
            version=row[2], adapter_type=row[3],
        ) for row in page],
        next_cursor=page[-1][0] if len(rows) > limit else None,
    )


@router.get("/activation-collectors/{version_id}", response_model=ActivationCollectorOption)
def get_activation_collector(
    version_id: str,
    _: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> ActivationCollectorOption:
    version = db.scalar(select(ArtifactVersion)
        .join(Artifact).join(CollectorDefinition)
        .where(
            ArtifactVersion.id == version_id,
            Artifact.kind == ArtifactKind.COLLECTOR,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            CollectorDefinition.adapter_type.in_(ACTIVATABLE_ADAPTERS),
        )
        .options(selectinload(ArtifactVersion.artifact),
                 selectinload(ArtifactVersion.collector_definition)))
    if version is None:
        raise HTTPException(status_code=404, detail="Published activation collector not found")
    return ActivationCollectorOption(
        artifact_version_id=version.id,
        artifact_name=version.artifact.name,
        version=version.version,
        adapter_type=version.collector_definition.adapter_type,
        target_schema=version.collector_definition.target_schema,
        config_schema=version.collector_definition.config_schema,
        defaults=version.collector_definition.defaults,
    )


def _policy(db: Session, policy_id: str) -> DeviceActivationPolicy:
    policy = db.get(DeviceActivationPolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Activation policy not found")
    return policy


@router.post(
    "/activation-policy-proposals",
    response_model=ActivationPolicyProposalRead,
)
def propose_activation_policy_route(
    payload: ActivationPolicyProposalRequest,
    principal: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> ActivationPolicyProposalRead:
    device = (
        require_device_access(db, principal, payload.device_id)
        if payload.device_id is not None
        else None
    )
    trusted_payload = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return propose_activation_policy(db, trusted_payload, device=device)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except StructuredModelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ProposalConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AuthoringQuotaConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AuthoringQuotaExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/activation-policy-proposals",
    response_model=list[ActivationPolicyProposalRecordRead],
)
def list_activation_policy_proposals(
    device_id: str | None = Query(default=None, max_length=36),
    actor: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=30, ge=1, le=100),
    principal: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> list[ActivationPolicyProposalRecordRead]:
    trusted_actor = request_actor(principal, actor)
    if device_id is not None:
        require_device_access(db, principal, device_id)
        query = select(ActivationPolicyProposal).where(
            ActivationPolicyProposal.device_id == device_id,
            ActivationPolicyProposal.actor == trusted_actor,
        )
    else:
        query = select(ActivationPolicyProposal).where(
            ActivationPolicyProposal.device_id.is_(None),
            ActivationPolicyProposal.actor == trusted_actor,
        )
    rows = db.scalars(query.order_by(
        ActivationPolicyProposal.created_at.desc(),
        ActivationPolicyProposal.id.desc(),
    ).limit(limit)).all()
    return [proposal_record(row) for row in rows]


@router.get(
    "/activation-policy-proposals/admin/recovery",
    response_model=list[ActivationPolicyProposalAdminRecoveryRead],
)
def list_admin_activation_policy_recovery(
    actor: str | None = Query(default=None, max_length=255),
    device_id: str | None = Query(default=None, max_length=36),
    limit: int = Query(default=100, ge=1, le=100),
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin", "assets.activate")
    ),
    db: Session = Depends(db_session),
) -> list[ActivationPolicyProposalAdminRecoveryRead]:
    query = select(ActivationPolicyProposal).where(
        ActivationPolicyProposal.status == "generating"
    )
    if actor:
        query = query.where(ActivationPolicyProposal.actor == actor)
    if device_id:
        query = query.where(ActivationPolicyProposal.device_id == device_id)
    rows = db.scalars(query.order_by(
        ActivationPolicyProposal.created_at,
        ActivationPolicyProposal.id,
    ).limit(limit)).all()
    return [admin_proposal_record(row) for row in rows]


@router.get(
    "/activation-policy-proposals/{proposal_id}",
    response_model=ActivationPolicyProposalRecordRead,
)
def get_activation_policy_proposal(
    proposal_id: str,
    actor: str | None = Query(default=None, max_length=255),
    principal: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> ActivationPolicyProposalRecordRead:
    row = db.get(ActivationPolicyProposal, proposal_id)
    if row is None or row.actor != request_actor(principal, actor):
        raise HTTPException(status_code=404, detail="Activation proposal not found")
    if row.device_id is not None:
        require_device_access(db, principal, row.device_id)
    return proposal_record(row)


@router.get(
    "/activation-policy-proposals/{proposal_id}/scope-preview",
    response_model=ActivationProposalScopePreview,
)
def get_activation_policy_proposal_scope_preview(
    proposal_id: str,
    actor: str | None = Query(default=None, max_length=255),
    device_id: str | None = Query(default=None, max_length=36),
    principal: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> ActivationProposalScopePreview:
    row = db.get(ActivationPolicyProposal, proposal_id)
    if row is None or row.actor != request_actor(principal, actor):
        raise HTTPException(status_code=404, detail="Activation proposal not found")
    if row.device_id is not None and device_id not in (None, row.device_id):
        raise HTTPException(status_code=409, detail="A bound proposal cannot be retargeted")
    target_device_id = row.device_id or device_id
    device = (
        require_device_access(db, principal, target_device_id)
        if target_device_id is not None else None
    )
    try:
        return preview_proposal_scope(db, row, device=device)
    except ProposalConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/activation-policy-proposals/{proposal_id}/interrupt",
    response_model=ActivationPolicyProposalRecordRead,
)
def interrupt_activation_policy_proposal_route(
    proposal_id: str,
    payload: ActivationPolicyProposalInterrupt,
    principal: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> ActivationPolicyProposalRecordRead:
    trusted_payload = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    row = db.get(ActivationPolicyProposal, proposal_id)
    if row is None or row.actor != trusted_payload.actor:
        raise HTTPException(status_code=404, detail="Activation proposal not found")
    if row.device_id is not None:
        require_device_access(db, principal, row.device_id)
    try:
        return interrupt_activation_policy_proposal(db, row, trusted_payload)
    except ProposalConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/activation-policy-proposals/{proposal_id}/admin-interrupt",
    response_model=ActivationPolicyProposalAdminRecoveryRead,
)
def admin_interrupt_activation_policy_proposal_route(
    proposal_id: str,
    payload: ActivationPolicyProposalAdminInterrupt,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin", "assets.activate")
    ),
    db: Session = Depends(db_session),
) -> ActivationPolicyProposalAdminRecoveryRead:
    row = db.get(ActivationPolicyProposal, proposal_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Activation proposal not found")
    try:
        return administratively_interrupt_activation_policy_proposal(
            db, row, payload, principal=principal,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ProposalConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/activation-policies",
    response_model=DeviceActivationPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
def create_activation_policy_route(
    payload: DeviceActivationPolicyCreate,
    principal: PrincipalContext = Depends(
        require_permissions("assets.activate")
    ),
    db: Session = Depends(db_session),
) -> DeviceActivationPolicy:
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return create_activation_policy(db, trusted_payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/activation-policies/draft-scope-preview",
    response_model=ActivationDraftScopePreview,
)
def preview_activation_policy_draft_route(
    payload: ActivationDraftScopePreviewRequest,
    principal: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> ActivationDraftScopePreview:
    device = (
        require_device_access(db, principal, payload.device_id)
        if payload.device_id is not None else None
    )
    trusted_draft = payload.draft.model_copy(update={
        "created_by": request_actor(principal, payload.draft.created_by),
    })
    try:
        return preview_draft_scope(db, trusted_draft, device=device)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.patch(
    "/activation-policies/{policy_id}",
    response_model=DeviceActivationPolicyRead,
)
def update_activation_policy_draft_route(
    policy_id: str,
    payload: ActivationPolicyDraftUpdate,
    principal: PrincipalContext = Depends(require_permissions("assets.activate")),
    db: Session = Depends(db_session),
) -> DeviceActivationPolicy:
    trusted_payload = payload.model_copy(update={
        "actor": request_actor(principal, payload.actor),
    })
    try:
        return update_activation_policy_draft(db, policy_id, trusted_payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ActivationPolicyRevisionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/activation-policies",
    response_model=list[DeviceActivationPolicyRead],
)
def list_activation_policies(
    protocol: str | None = Query(default=None, max_length=32),
    policy_status: ArtifactVersionStatus | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("assets.read")),
    db: Session = Depends(db_session),
) -> list[DeviceActivationPolicy]:
    query = select(DeviceActivationPolicy)
    if protocol:
        query = query.where(DeviceActivationPolicy.protocol == protocol)
    if policy_status:
        query = query.where(DeviceActivationPolicy.status == policy_status)
    return list(
        db.scalars(
            query.order_by(
                DeviceActivationPolicy.name,
                DeviceActivationPolicy.version.desc(),
            ).limit(limit)
        ).all()
    )


@router.get("/activation-policies/page", response_model=DeviceActivationPolicyPage)
def page_activation_policies(
    protocol: str | None = Query(default=None, max_length=32),
    policy_status: ArtifactVersionStatus | None = None,
    name_prefix: str | None = Query(default=None, max_length=128),
    cursor: str | None = Query(default=None, max_length=36),
    limit: int = Query(default=50, ge=1, le=100),
    _: PrincipalContext = Depends(require_permissions("assets.read")),
    db: Session = Depends(db_session),
) -> DeviceActivationPolicyPage:
    if protocol is not None and protocol not in PROTOCOL_ACTIVATION_ADAPTERS:
        raise HTTPException(status_code=400, detail="Unknown activation protocol")
    criteria = []
    if protocol is not None:
        criteria.append(DeviceActivationPolicy.protocol == protocol)
    if policy_status is not None:
        criteria.append(DeviceActivationPolicy.status == policy_status)
    pattern = _prefix_pattern(name_prefix)
    if pattern is not None:
        criteria.append(DeviceActivationPolicy.name.ilike(pattern, escape="\\"))
    if cursor is not None:
        marker = db.scalar(select(DeviceActivationPolicy).where(
            DeviceActivationPolicy.id == cursor, *criteria,
        ))
        if marker is None:
            raise HTTPException(status_code=400, detail="Activation policy cursor is unavailable")
        criteria.append(or_(
            DeviceActivationPolicy.name > marker.name,
            and_(DeviceActivationPolicy.name == marker.name,
                 DeviceActivationPolicy.version < marker.version),
            and_(DeviceActivationPolicy.name == marker.name,
                 DeviceActivationPolicy.version == marker.version,
                 DeviceActivationPolicy.id > marker.id),
        ))
    rows = list(db.scalars(select(DeviceActivationPolicy).where(*criteria)
        .order_by(DeviceActivationPolicy.name,
                  DeviceActivationPolicy.version.desc(), DeviceActivationPolicy.id)
        .limit(limit + 1)).all())
    page = rows[:limit]
    return DeviceActivationPolicyPage(
        items=[DeviceActivationPolicyRead.model_validate(row) for row in page],
        next_cursor=page[-1].id if len(rows) > limit else None,
    )


@router.get(
    "/activation-policies/{policy_id}",
    response_model=DeviceActivationPolicyRead,
)
def get_activation_policy_route(
    policy_id: str,
    _: PrincipalContext = Depends(require_permissions("assets.read")),
    db: Session = Depends(db_session),
) -> DeviceActivationPolicy:
    return _policy(db, policy_id)


@router.post(
    "/activation-policies/{policy_id}/validate",
    response_model=DeviceActivationPolicyRead,
)
def validate_activation_policy_route(
    policy_id: str,
    payload: ActivationPolicyAction,
    principal: PrincipalContext = Depends(
        require_permissions("assets.activate")
    ),
    db: Session = Depends(db_session),
) -> DeviceActivationPolicy:
    try:
        return validate_activation_policy(
            db,
            _policy(db, policy_id),
            request_actor(principal, payload.actor),
            expected_revision=payload.expected_revision,
        )
    except ActivationPolicyRevisionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/activation-policies/{policy_id}/publish",
    response_model=DeviceActivationPolicyRead,
)
def publish_activation_policy_route(
    policy_id: str,
    payload: ActivationPolicyAction,
    principal: PrincipalContext = Depends(
        require_permissions("assets.activate")
    ),
    db: Session = Depends(db_session),
) -> DeviceActivationPolicy:
    try:
        return publish_activation_policy(
            db,
            _policy(db, policy_id),
            request_actor(principal, payload.actor),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/devices/{device_id}/connections/{connection_id}/activation/preview",
    response_model=ActivationPlanRead,
)
def preview_activation_route(
    device_id: str,
    connection_id: str,
    payload: ActivationPreviewRequest,
    principal: PrincipalContext = Depends(
        require_permissions("assets.activate")
    ),
    db: Session = Depends(db_session),
) -> ActivationPlanRead:
    require_device_access(db, principal, device_id)
    try:
        return preview_activation(db, device_id, connection_id, payload.policy_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/devices/{device_id}/connections/{connection_id}/activation/approve",
    response_model=DeviceActivationResult,
)
def approve_activation_route(
    device_id: str,
    connection_id: str,
    payload: ActivationApproval,
    principal: PrincipalContext = Depends(
        require_permissions("assets.activate")
    ),
    db: Session = Depends(db_session),
) -> dict[str, object]:
    require_device_access(db, principal, device_id)
    try:
        activation, deployment = approve_activation(
            db,
            device_id,
            connection_id,
            payload.policy_id,
            expected_plan_hash=payload.expected_plan_hash,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
        return {"activation": activation, "deployment": deployment}
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/devices/{device_id}/connections/{connection_id}/activations/"
    "{activation_id}/deactivate",
    response_model=DeviceActivationResult,
)
def deactivate_activation_route(
    device_id: str,
    connection_id: str,
    activation_id: str,
    payload: ActivationDeactivate,
    principal: PrincipalContext = Depends(
        require_permissions("assets.activate")
    ),
    db: Session = Depends(db_session),
) -> dict[str, object]:
    require_device_access(db, principal, device_id)
    try:
        activation, deployment = deactivate_connection(
            db,
            device_id,
            connection_id,
            activation_id=activation_id,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
        return {"activation": activation, "deployment": deployment}
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/devices/{device_id}/connections/{connection_id}/activation/deactivate",
    response_model=DeviceActivationResult,
)
def deactivate_connection_route(
    device_id: str,
    connection_id: str,
    payload: ActivationDeactivate,
    principal: PrincipalContext = Depends(
        require_permissions("assets.activate")
    ),
    db: Session = Depends(db_session),
) -> dict[str, object]:
    require_device_access(db, principal, device_id)
    try:
        activation, deployment = deactivate_connection(
            db,
            device_id,
            connection_id,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
        return {"activation": activation, "deployment": deployment}
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
