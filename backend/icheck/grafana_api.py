"""Grafana connection settings and exact human confirmation, not arbitrary HTTP."""
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import current_principal
from .database import get_db
from .grafana_client import GrafanaError, GrafanaConflict, secret_key
from .grafana_schemas import (GrafanaConnectionCreate, GrafanaConnectionRead,
    GrafanaConnectionUpdate, GrafanaMetricQuery, GrafanaPreview, GrafanaChangeRead, GrafanaConfirm)
from .models import GrafanaConnection, GrafanaChange
from .services import grafana as service
from .services.authorization_scope import namespace_clause
from .services.control_plane_auth import PrincipalContext

router = APIRouter(prefix="/api/v1/grafana", tags=["Grafana native plugin"])


def invoke(response, action, *args, **kwargs):
    response.headers["Cache-Control"] = "no-store"
    try:
        return action(*args, **kwargs)
    except PermissionError as error:
        raise HTTPException(403, detail=str(error)) from None
    except LookupError as error:
        raise HTTPException(404, detail=str(error)) from None
    except GrafanaConflict as error:
        raise HTTPException(409, detail=str(error)) from None
    except GrafanaError as error:
        raise HTTPException(400, detail=str(error)) from None
    except ValueError:
        raise HTTPException(400, detail="Invalid or unsafe Grafana input; revise the configuration or proposal") from None


def listing(db, principal):
    service.guard(principal)
    return db.scalars(select(GrafanaConnection).where(namespace_clause(GrafanaConnection, principal))
                      .order_by(GrafanaConnection.name).limit(100)).all()


@router.get("/connections", response_model=list[GrafanaConnectionRead])
def connections(response: Response, actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, listing, db, actor)


@router.get("/setup")
def setup(response: Response, actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    rows = invoke(response, listing, db, actor)
    try:
        secret_key()
        ready = True
    except GrafanaError:
        ready = False
    return {"contract": "icheck.grafana-plugin/v1", "storage_ready": ready,
            "connections": [GrafanaConnectionRead.model_validate(row).model_dump() for row in rows],
            "warning": service.WARNING}


@router.get("/devices/{device_id}/dashboards")
def device_dashboards(device_id: str, response: Response,
    from_time: str = Query(default="now-1h", alias="from", max_length=64),
    to_time: str = Query(default="now", alias="to", max_length=64),
    actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.device_dashboard_links, db, actor, device_id,
                  from_time=from_time, to_time=to_time)


@router.post("/connections", response_model=GrafanaConnectionRead, status_code=201)
def connect(payload: GrafanaConnectionCreate, response: Response,
            actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.create_connection, db, payload, actor)


@router.put("/connections/{identifier}", response_model=GrafanaConnectionRead)
def update(identifier: str, payload: GrafanaConnectionUpdate, response: Response,
           actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.update_connection, db, identifier, payload, actor)


@router.get("/connections/{identifier}/health")
def health(identifier: str, response: Response, actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.tools_for_ai, "grafana.health", db, {"connection_id": identifier}, actor)[0]


@router.get("/connections/{identifier}/metrics")
def metrics(identifier: str, response: Response, filter: str = Query(default="", max_length=128),
            limit: int = Query(default=100, ge=1, le=200),
            actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.tools_for_ai, "grafana.metrics.discover", db,
                  {"connection_id": identifier, "filter": filter, "limit": limit}, actor)[0]


@router.get("/connections/{identifier}/resources")
def resources(identifier: str, response: Response, kind: str = Query(default="dashboard", pattern="^(dashboard|folder)$"),
              query: str = Query(default="", max_length=128),
              actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.tools_for_ai, "grafana." + kind + "s.search", db,
                  {"connection_id": identifier, "query": query}, actor)[0]


@router.post("/connections/{identifier}/metrics/query")
def query_samples(identifier: str, payload: GrafanaMetricQuery, response: Response,
                  actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.tools_for_ai, "grafana.metrics.query", db,
                  {"connection_id": identifier, **payload.model_dump()}, actor)[0]


@router.get("/connections/{identifier}/resources/{kind}/{uid}")
def resource(identifier: str, kind: str, uid: str, response: Response,
             actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    if kind not in {"dashboard", "folder"}:
        raise HTTPException(400, "Unsupported Grafana resource kind")
    return invoke(response, service.read_resource, db, identifier, kind, uid, actor)


@router.post("/connections/{identifier}/preview", response_model=GrafanaChangeRead, status_code=201)
def preview(identifier: str, payload: GrafanaPreview, response: Response,
            actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.preview, db, identifier, payload, actor)


@router.get("/changes", response_model=list[GrafanaChangeRead])
def changes(response: Response, limit: int = Query(default=30, ge=1, le=100),
            actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    def action():
        service.guard(actor)
        rows = db.scalars(select(GrafanaChange).where(namespace_clause(GrafanaChange, actor))
            .order_by(GrafanaChange.created_at.desc(), GrafanaChange.id).limit(limit)).all()
        return [service.change_read(row) for row in rows]
    return invoke(response, action)


@router.get("/changes/{identifier}", response_model=GrafanaChangeRead)
def get_change(identifier: str, response: Response, actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, lambda: service.change_read(service.change(db, identifier, actor)))


@router.post("/changes/{identifier}/confirm", response_model=GrafanaChangeRead)
def confirm(identifier: str, payload: GrafanaConfirm, response: Response,
            actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.confirm, db, identifier, payload, actor)


@router.post("/changes/{identifier}/restore-preview", response_model=GrafanaChangeRead, status_code=201)
def restore(identifier: str, response: Response, actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.restore_preview, db, identifier, actor)
