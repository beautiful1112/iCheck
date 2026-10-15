from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .database import get_db
from .ecosystem_transport_schemas import (
    EcosystemTransportEndpointCreate,
    EcosystemTransportEndpointRead,
    EcosystemTransportEndpointStateCreate,
    EcosystemTransportGossipDispatchCreate,
    EcosystemTransportTLSUpdate,
    EcosystemTransportHealthRead,
    EcosystemTransportJobAction,
    EcosystemTransportJobRead,
    EcosystemTransportPromotionCreate,
    EcosystemTransportWitnessDispatchCreate,
    EcosystemTransportWorkerRead,
    JobStatus,
)
from .models import EcosystemTransportJobStatus
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext
from .services.ecosystem_transport import (
    cancel_transport_job,
    create_transport_endpoint,
    list_transport_endpoints,
    list_transport_jobs,
    list_transport_workers,
    queue_promotion_delivery,
    queue_gossip_dispatch,
    queue_witness_dispatch,
    retry_transport_job,
    set_transport_endpoint_state,
    update_transport_endpoint_tls,
    transport_endpoint_document,
    transport_health,
    transport_job_document,
)


router = APIRouter(
    prefix="/api/v1/ecosystem-transport",
    tags=["ecosystem-transport"],
)
DBSession = Annotated[Session, Depends(get_db)]


@router.post(
    "/endpoints",
    response_model=EcosystemTransportEndpointRead,
    status_code=status.HTTP_201_CREATED,
)
def create_transport_endpoint_route(
    payload: EcosystemTransportEndpointCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> EcosystemTransportEndpointRead:
    try:
        endpoint = create_transport_endpoint(
            db,
            payload,
            actor=request_actor(principal, payload.created_by),
        )
        return EcosystemTransportEndpointRead.model_validate(
            transport_endpoint_document(endpoint)
        )
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/endpoints",
    response_model=list[EcosystemTransportEndpointRead],
)
def list_transport_endpoints_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[EcosystemTransportEndpointRead]:
    return [
        EcosystemTransportEndpointRead.model_validate(item)
        for item in list_transport_endpoints(db, limit=limit)
    ]


@router.post(
    "/endpoints/{endpoint_id}/state",
    response_model=EcosystemTransportEndpointRead,
)
def set_transport_endpoint_state_route(
    endpoint_id: str,
    payload: EcosystemTransportEndpointStateCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> EcosystemTransportEndpointRead:
    try:
        endpoint = set_transport_endpoint_state(
            db,
            endpoint_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return EcosystemTransportEndpointRead.model_validate(
            transport_endpoint_document(endpoint)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.put(
    "/endpoints/{endpoint_id}/tls",
    response_model=EcosystemTransportEndpointRead,
)
def update_transport_endpoint_tls_route(
    endpoint_id: str,
    payload: EcosystemTransportTLSUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> EcosystemTransportEndpointRead:
    try:
        endpoint = update_transport_endpoint_tls(
            db,
            endpoint_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return EcosystemTransportEndpointRead.model_validate(
            transport_endpoint_document(endpoint)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "revision conflict" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post(
    "/witness-offers/{offer_id}/dispatch",
    response_model=list[EcosystemTransportJobRead],
    status_code=status.HTTP_202_ACCEPTED,
)
def dispatch_witness_offer_route(
    offer_id: str,
    payload: EcosystemTransportWitnessDispatchCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> list[EcosystemTransportJobRead]:
    try:
        jobs = queue_witness_dispatch(
            db,
            offer_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return [
            EcosystemTransportJobRead.model_validate(
                transport_job_document(item)
            )
            for item in jobs
        ]
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/gossip-offers/{offer_id}/dispatch",
    response_model=list[EcosystemTransportJobRead],
    status_code=status.HTTP_202_ACCEPTED,
)
def dispatch_gossip_offer_route(
    offer_id: str,
    payload: EcosystemTransportGossipDispatchCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> list[EcosystemTransportJobRead]:
    try:
        jobs = queue_gossip_dispatch(
            db,
            offer_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return [
            EcosystemTransportJobRead.model_validate(
                transport_job_document(item)
            )
            for item in jobs
        ]
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/promotion-deliveries",
    response_model=EcosystemTransportJobRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_promotion_delivery_route(
    payload: EcosystemTransportPromotionCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> EcosystemTransportJobRead:
    try:
        job = queue_promotion_delivery(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return EcosystemTransportJobRead.model_validate(
            transport_job_document(job)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/jobs", response_model=list[EcosystemTransportJobRead])
def list_transport_jobs_route(
    db: DBSession,
    status_filter: Annotated[
        JobStatus | None,
        Query(alias="status"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[EcosystemTransportJobRead]:
    parsed = (
        EcosystemTransportJobStatus(status_filter)
        if status_filter is not None
        else None
    )
    return [
        EcosystemTransportJobRead.model_validate(item)
        for item in list_transport_jobs(db, limit=limit, status=parsed)
    ]


@router.post(
    "/jobs/{job_id}/retry",
    response_model=EcosystemTransportJobRead,
)
def retry_transport_job_route(
    job_id: str,
    payload: EcosystemTransportJobAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> EcosystemTransportJobRead:
    try:
        job = retry_transport_job(
            db,
            job_id,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
        return EcosystemTransportJobRead.model_validate(
            transport_job_document(job)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=EcosystemTransportJobRead,
)
def cancel_transport_job_route(
    job_id: str,
    payload: EcosystemTransportJobAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> EcosystemTransportJobRead:
    try:
        job = cancel_transport_job(
            db,
            job_id,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
        return EcosystemTransportJobRead.model_validate(
            transport_job_document(job)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/workers",
    response_model=list[EcosystemTransportWorkerRead],
)
def list_transport_workers_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[EcosystemTransportWorkerRead]:
    return [
        EcosystemTransportWorkerRead.model_validate(item)
        for item in list_transport_workers(db, limit=limit)
    ]


@router.get("/health", response_model=EcosystemTransportHealthRead)
def transport_health_route(
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> EcosystemTransportHealthRead:
    return EcosystemTransportHealthRead.model_validate(transport_health(db))
