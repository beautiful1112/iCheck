from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .models import SNMPExporterAttestation
from .services.authorization_scope import request_actor, require_global_scope
from .services.control_plane_auth import PrincipalContext
from .services.snmp_exporter_attestations import (
    accept_snmp_exporter_attestation,
    build_snmp_exporter_attestor_input,
)
from .snmp_attestation_schemas import (
    SNMPExporterAttestationCreate,
    SNMPExporterAttestationRead,
    SNMPExporterAttestorInput,
)


router = APIRouter(
    prefix="/api/v1/snmp-exporter-attestations",
    tags=["capabilities"],
)
DBSession = Annotated[Session, Depends(get_db)]


@router.post(
    "",
    response_model=SNMPExporterAttestationRead,
    status_code=status.HTTP_201_CREATED,
)
def create_snmp_exporter_attestation_route(
    payload: SNMPExporterAttestationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.manage")
    ),
) -> SNMPExporterAttestation:
    require_global_scope(principal)
    actor = request_actor(principal, payload.actor)
    try:
        return accept_snmp_exporter_attestation(db, payload, actor=actor)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "already been used" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("", response_model=list[SNMPExporterAttestationRead])
def list_snmp_exporter_attestations_route(
    db: DBSession,
    proposal_version_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.read")
    ),
) -> list[SNMPExporterAttestation]:
    require_global_scope(principal)
    query = select(SNMPExporterAttestation)
    if proposal_version_id is not None:
        query = query.where(
            SNMPExporterAttestation.proposal_version_id == proposal_version_id
        )
    return list(
        db.scalars(
            query.order_by(SNMPExporterAttestation.verified_at.desc()).limit(limit)
        ).all()
    )


@router.get(
    "/proposal-inputs/{proposal_version_id}",
    response_model=SNMPExporterAttestorInput,
)
def get_snmp_exporter_attestor_input_route(
    proposal_version_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.read")
    ),
) -> SNMPExporterAttestorInput:
    require_global_scope(principal)
    try:
        return build_snmp_exporter_attestor_input(db, proposal_version_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{attestation_id}", response_model=SNMPExporterAttestationRead)
def get_snmp_exporter_attestation_route(
    attestation_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.read")
    ),
) -> SNMPExporterAttestation:
    require_global_scope(principal)
    row = db.get(SNMPExporterAttestation, attestation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SNMP Exporter attestation not found")
    return row
