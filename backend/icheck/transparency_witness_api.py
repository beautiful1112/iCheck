from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .database import get_db
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext
from .services.transparency_witnessing import (
    create_checkpoint_offer,
    export_checkpoint_gossip,
    get_witness_policy,
    ingest_checkpoint_attestation,
    ingest_transparency_gossip,
    list_checkpoint_attestations,
    list_checkpoint_offers,
    list_transparency_gossip,
    list_transparency_witnesses,
    reconcile_transparency_fork_alerts,
    register_transparency_witness,
    set_transparency_witness_state,
    update_witness_policy,
)
from .transparency_witness_schemas import (
    TransparencyAttestationIngestCreate,
    TransparencyCheckpointOfferCreate,
    TransparencyCheckpointOfferRead,
    TransparencyGossipDocument,
    TransparencyForkAlertReconcileCreate,
    TransparencyForkAlertReconcileRead,
    TransparencyGossipIngestCreate,
    TransparencyGossipObservationRead,
    TransparencyWitnessAttestationRead,
    TransparencyWitnessCreate,
    TransparencyWitnessPolicyRead,
    TransparencyWitnessPolicyUpdate,
    TransparencyWitnessRead,
    TransparencyWitnessStateCreate,
)


router = APIRouter(
    prefix="/api/v1/transparency-witnessing",
    tags=["transparency-witnessing"],
)
DBSession = Annotated[Session, Depends(get_db)]


@router.post(
    "/witnesses",
    response_model=TransparencyWitnessRead,
    status_code=status.HTTP_201_CREATED,
)
def register_transparency_witness_route(
    payload: TransparencyWitnessCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TransparencyWitnessRead:
    try:
        return TransparencyWitnessRead.model_validate(
            register_transparency_witness(
                db,
                payload,
                actor=request_actor(principal, payload.created_by),
            )
        )
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/witnesses", response_model=list[TransparencyWitnessRead])
def list_transparency_witnesses_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[TransparencyWitnessRead]:
    return [
        TransparencyWitnessRead.model_validate(item)
        for item in list_transparency_witnesses(db, limit=limit)
    ]


@router.post(
    "/witnesses/{witness_id}/state",
    response_model=TransparencyWitnessRead,
)
def set_transparency_witness_state_route(
    witness_id: str,
    payload: TransparencyWitnessStateCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TransparencyWitnessRead:
    try:
        return TransparencyWitnessRead.model_validate(
            set_transparency_witness_state(
                db,
                witness_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/policy", response_model=TransparencyWitnessPolicyRead)
def get_witness_policy_route(
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TransparencyWitnessPolicyRead:
    return TransparencyWitnessPolicyRead.model_validate(get_witness_policy(db))


@router.put("/policy", response_model=TransparencyWitnessPolicyRead)
def update_witness_policy_route(
    payload: TransparencyWitnessPolicyUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TransparencyWitnessPolicyRead:
    return TransparencyWitnessPolicyRead.model_validate(
        update_witness_policy(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    )


@router.post(
    "/checkpoint-offers",
    response_model=TransparencyCheckpointOfferRead,
    status_code=status.HTTP_201_CREATED,
)
def create_checkpoint_offer_route(
    payload: TransparencyCheckpointOfferCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TransparencyCheckpointOfferRead:
    try:
        return create_checkpoint_offer(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/checkpoint-offers",
    response_model=list[TransparencyCheckpointOfferRead],
)
def list_checkpoint_offers_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[TransparencyCheckpointOfferRead]:
    return list_checkpoint_offers(db, limit=limit)


@router.post(
    "/checkpoint-offers/{offer_id}/attestations",
    response_model=TransparencyWitnessAttestationRead,
    status_code=status.HTTP_201_CREATED,
)
def ingest_checkpoint_attestation_route(
    offer_id: str,
    payload: TransparencyAttestationIngestCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TransparencyWitnessAttestationRead:
    try:
        return TransparencyWitnessAttestationRead.model_validate(
            ingest_checkpoint_attestation(
                db,
                offer_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/checkpoint-offers/{offer_id}/attestations",
    response_model=list[TransparencyWitnessAttestationRead],
)
def list_checkpoint_attestations_route(
    offer_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[TransparencyWitnessAttestationRead]:
    try:
        return [
            TransparencyWitnessAttestationRead.model_validate(item)
            for item in list_checkpoint_attestations(db, offer_id)
        ]
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/checkpoint-offers/{offer_id}/gossip",
    response_model=TransparencyGossipDocument,
)
def export_checkpoint_gossip_route(
    offer_id: str,
    db: DBSession,
    source_region: Annotated[
        str,
        Query(
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
        ),
    ],
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TransparencyGossipDocument:
    try:
        return export_checkpoint_gossip(
            db,
            offer_id,
            source_region=source_region,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/gossip",
    response_model=TransparencyGossipObservationRead,
    status_code=status.HTTP_201_CREATED,
)
def ingest_transparency_gossip_route(
    payload: TransparencyGossipIngestCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TransparencyGossipObservationRead:
    try:
        return ingest_transparency_gossip(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/gossip/fork-alerts/reconcile",
    response_model=TransparencyForkAlertReconcileRead,
)
def reconcile_transparency_fork_alerts_route(
    payload: TransparencyForkAlertReconcileCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> TransparencyForkAlertReconcileRead:
    return reconcile_transparency_fork_alerts(
        db,
        limit=payload.limit,
        actor=request_actor(principal, payload.actor),
    )


@router.get(
    "/gossip",
    response_model=list[TransparencyGossipObservationRead],
)
def list_transparency_gossip_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[TransparencyGossipObservationRead]:
    return list_transparency_gossip(db, limit=limit)
