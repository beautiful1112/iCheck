from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .capability_promotion_schemas import (
    CapabilityPromotionAcceptCreate,
    CapabilityPromotionAttestation,
    CapabilityPromotionPublicationAction,
    CapabilityPromotionPublicationPreviewRead,
    CapabilityPromotionPublicationRead,
    CapabilityPromotionPolicyRead,
    CapabilityPromotionPolicyUpdate,
    CapabilityPromotionPreviewCreate,
    CapabilityPromotionPreviewRead,
    CapabilityPromotionReceiptRead,
    CapabilityPromotionSourceCreate,
    CapabilityPromotionSourceRead,
    CapabilityPromotionSourceStateCreate,
    CapabilityPromotionStatementCreate,
    SignedCapabilityPromotionAttestation,
    CapabilityPromotionKeyRotationCreate,
    CapabilityPromotionKeyRotationRead,
    CapabilityPromotionKeyRotationStatement,
    CapabilityPromotionKeyRotationStatementCreate,
    SignedCapabilityPromotionKeyRotation,
    PromotionSourceWitnessPolicyRead, PromotionSourceWitnessPolicyUpdate,
    PromotionSourceCheckpointBindingRead, PromotionSourceCheckpointBindingUpdate,
    PromotionSourceWitnessDecisionRead,
)
from .database import get_db
from .services.authorization_scope import request_actor
from .services.capability_promotions import (
    accept_capability_promotion,
    create_promotion_statement,
    export_promotion_receipt,
    get_promotion_policy,
    list_promotion_publications,
    list_promotion_receipts,
    list_promotion_sources,
    preview_capability_promotion,
    preview_promotion_publication,
    publish_promoted_capability,
    register_promotion_source,
    set_promotion_source_state,
    update_promotion_policy,
)
from .services.control_plane_auth import PrincipalContext
from .services.promotion_key_rotation import (
    create_promotion_key_rotation_statement, rotate_promotion_source_key,
    list_promotion_key_rotations, export_promotion_key_rotation,
)
from .services.promotion_witnesses import (
    get_source_witness_policy, update_source_witness_policy, bind_source_checkpoint,
    list_source_checkpoint_bindings, get_source_witness_decision,
)


router = APIRouter(
    prefix="/api/v1/capability-promotions",
    tags=["capability-promotions"],
)
DBSession = Annotated[Session, Depends(get_db)]


@router.get("/source-witness-policy", response_model=PromotionSourceWitnessPolicyRead)
def get_source_witness_policy_route(db: DBSession,
    _: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    return get_source_witness_policy(db) or PromotionSourceWitnessPolicyRead()


@router.put("/source-witness-policy", response_model=PromotionSourceWitnessPolicyRead)
def update_source_witness_policy_route(payload: PromotionSourceWitnessPolicyUpdate, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    try:
        return update_source_witness_policy(db, payload, actor=request_actor(principal, payload.actor))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/source-checkpoint-bindings", response_model=list[PromotionSourceCheckpointBindingRead])
def list_source_checkpoint_bindings_route(db: DBSession,
    _: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    return list_source_checkpoint_bindings(db)


@router.put("/sources/{source_id}/checkpoint-binding", response_model=PromotionSourceCheckpointBindingRead)
def bind_source_checkpoint_route(source_id: str, payload: PromotionSourceCheckpointBindingUpdate, db: DBSession,
    principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    try:
        return bind_source_checkpoint(db, source_id, payload, actor=request_actor(principal, payload.actor))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/receipts/{receipt_id}/source-witness-evidence", response_model=PromotionSourceWitnessDecisionRead | None)
def get_source_witness_decision_route(receipt_id: str, db: DBSession,
    _: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    return get_source_witness_decision(db, receipt_id)


@router.post("/sources/{source_id}/key-rotation-statements", response_model=CapabilityPromotionKeyRotationStatement)
def create_key_rotation_statement_route(source_id: str, payload: CapabilityPromotionKeyRotationStatementCreate,
    db: DBSession, principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    try:
        return create_promotion_key_rotation_statement(db, source_id, payload, actor=request_actor(principal, payload.actor))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/sources/{source_id}/rotate-key", response_model=CapabilityPromotionKeyRotationRead)
def rotate_promotion_source_key_route(source_id: str, payload: CapabilityPromotionKeyRotationCreate,
    db: DBSession, principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    try:
        return rotate_promotion_source_key(db, source_id, payload, actor=request_actor(principal, payload.actor))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/key-rotations", response_model=list[CapabilityPromotionKeyRotationRead])
def list_key_rotations_route(db: DBSession,
    _: PrincipalContext = Depends(require_global_permissions("capabilities.manage")),
    source_id: str | None = None, limit: Annotated[int, Query(ge=1, le=500)] = 100):
    return list_promotion_key_rotations(db, source_id=source_id, limit=limit)


@router.get("/key-rotations/{rotation_id}/export", response_model=SignedCapabilityPromotionKeyRotation)
def export_key_rotation_route(rotation_id: str, db: DBSession,
    _: PrincipalContext = Depends(require_global_permissions("capabilities.manage"))):
    try:
        return export_promotion_key_rotation(db, rotation_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/policy",
    response_model=CapabilityPromotionPolicyRead | None,
)
def get_promotion_policy_route(
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPromotionPolicyRead | None:
    policy = get_promotion_policy(db)
    return (
        CapabilityPromotionPolicyRead.model_validate(policy)
        if policy is not None
        else None
    )


@router.put(
    "/policy",
    response_model=CapabilityPromotionPolicyRead,
)
def update_promotion_policy_route(
    payload: CapabilityPromotionPolicyUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPromotionPolicyRead:
    try:
        return CapabilityPromotionPolicyRead.model_validate(
            update_promotion_policy(
                db,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/sources",
    response_model=CapabilityPromotionSourceRead,
    status_code=status.HTTP_201_CREATED,
)
def register_promotion_source_route(
    payload: CapabilityPromotionSourceCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPromotionSourceRead:
    try:
        return CapabilityPromotionSourceRead.model_validate(
            register_promotion_source(
                db,
                payload,
                actor=request_actor(principal, payload.created_by),
            )
        )
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/sources",
    response_model=list[CapabilityPromotionSourceRead],
)
def list_promotion_sources_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[CapabilityPromotionSourceRead]:
    return [
        CapabilityPromotionSourceRead.model_validate(item)
        for item in list_promotion_sources(db, limit=limit)
    ]


@router.post(
    "/sources/{source_id}/state",
    response_model=CapabilityPromotionSourceRead,
)
def set_promotion_source_state_route(
    source_id: str,
    payload: CapabilityPromotionSourceStateCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPromotionSourceRead:
    try:
        return CapabilityPromotionSourceRead.model_validate(
            set_promotion_source_state(
                db,
                source_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/statements",
    response_model=CapabilityPromotionAttestation,
)
def create_promotion_statement_route(
    payload: CapabilityPromotionStatementCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPromotionAttestation:
    try:
        return create_promotion_statement(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/preview",
    response_model=CapabilityPromotionPreviewRead,
)
def preview_capability_promotion_route(
    payload: CapabilityPromotionPreviewCreate,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPromotionPreviewRead:
    try:
        return preview_capability_promotion(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/accept",
    response_model=CapabilityPromotionReceiptRead,
    status_code=status.HTTP_201_CREATED,
)
def accept_capability_promotion_route(
    payload: CapabilityPromotionAcceptCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPromotionReceiptRead:
    try:
        return CapabilityPromotionReceiptRead.model_validate(
            accept_capability_promotion(
                db,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/receipts",
    response_model=list[CapabilityPromotionReceiptRead],
)
def list_promotion_receipts_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[CapabilityPromotionReceiptRead]:
    return [
        CapabilityPromotionReceiptRead.model_validate(item)
        for item in list_promotion_receipts(db, limit=limit)
    ]


@router.get(
    "/publications",
    response_model=list[CapabilityPromotionPublicationRead],
)
def list_promotion_publications_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[CapabilityPromotionPublicationRead]:
    return [
        CapabilityPromotionPublicationRead.model_validate(item)
        for item in list_promotion_publications(db, limit=limit)
    ]


@router.post(
    "/receipts/{receipt_id}/publication-preview",
    response_model=CapabilityPromotionPublicationPreviewRead,
)
def preview_promotion_publication_route(
    receipt_id: str,
    payload: CapabilityPromotionPublicationAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPromotionPublicationPreviewRead:
    try:
        return preview_promotion_publication(
            db,
            receipt_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/receipts/{receipt_id}/publish",
    response_model=CapabilityPromotionPublicationRead,
    status_code=status.HTTP_201_CREATED,
)
def publish_promoted_capability_route(
    receipt_id: str,
    payload: CapabilityPromotionPublicationAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPromotionPublicationRead:
    try:
        return CapabilityPromotionPublicationRead.model_validate(
            publish_promoted_capability(
                db,
                receipt_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/receipts/{receipt_id}/export",
    response_model=SignedCapabilityPromotionAttestation,
)
def export_promotion_receipt_route(
    receipt_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> SignedCapabilityPromotionAttestation:
    try:
        return SignedCapabilityPromotionAttestation.model_validate(
            export_promotion_receipt(db, receipt_id)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
