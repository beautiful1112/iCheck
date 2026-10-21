"""Integration catalog, protected connection configuration and explicit tests."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from .auth import current_principal, require_permissions
from .database import get_db
from .integration_custody import IntegrationCustodyUnavailable
from .integration_schemas import (ConnectionCreate, ConnectionRead, ConnectionUpdate,
                                   ConnectionTest, ConnectionTestResult, GroupDiscovery, SyncStep, SyncRead,
                                   ScheduleRead, ScheduleUpdate, AssetBindingsUpdate, AlertFeedUpdate, ExternalAlertSilence)
from .monitoring_connectors.zabbix import ConnectorError
from .monitoring_connectors.catalog import PROVIDERS
from .monitoring_connectors.contracts import ProviderDescriptor
from .monitoring_connectors.https_transport import EndpointError
from .services import monitoring_integrations as service
from .services import integration_scheduling
from .services import integration_bindings
from .services import integration_alerts
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


@router.get("/providers", response_model=list[ProviderDescriptor])
def list_providers(
    _: PrincipalContext = Depends(require_permissions("metrics.read")),
) -> list[ProviderDescriptor]:
    return list(PROVIDERS)


def invoke(response, action, *args, **kwargs):
    response.headers["Cache-Control"] = "no-store"
    try:
        return action(*args, **kwargs)
    except PermissionError as error:
        status, detail = 403, str(error)
    except LookupError as error:
        status, detail = 404, str(error)
    except service.IntegrationConflict as error:
        status, detail = 409, str(error)
    except IntegrationCustodyUnavailable as error:
        status, detail = 503, str(error)
    except ConnectorError as error:
        status, detail = 502, service.safe_error(error)
    except EndpointError as error:
        status, detail = 422, str(error)
    except ValueError:
        status, detail = 422, "Invalid or unsafe integration configuration"
    raise HTTPException(status, detail, headers={"Cache-Control": "no-store"}) from None


@router.get("/connections", response_model=list[ConnectionRead])
def connections(response: Response, limit: int = Query(default=50, ge=1, le=100),
                offset: int = Query(default=0, ge=0),
                actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.listing, db, actor, limit=limit, offset=offset)


@router.post("/connections", response_model=ConnectionRead, status_code=201)
def create(payload: ConnectionCreate, response: Response,
           actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.create_connection, db, payload, actor)


@router.get("/connections/{identifier}", response_model=ConnectionRead)
def read(identifier: UUID, response: Response,
         actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.connection, db, str(identifier), actor)


@router.put("/connections/{identifier}", response_model=ConnectionRead)
def update(identifier: UUID, payload: ConnectionUpdate, response: Response,
           actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.update_connection, db, str(identifier), payload, actor)


@router.post("/connections/{identifier}/test", response_model=ConnectionTestResult)
def test(identifier: UUID, payload: ConnectionTest, response: Response,
         actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.test_connection, db, str(identifier), payload, actor)


@router.post("/connections/{identifier}/groups")
def groups(identifier: UUID, payload: GroupDiscovery, response: Response,
           actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.discover_groups, db, str(identifier), payload, actor)


@router.post("/connections/{identifier}/preview")
def preview(identifier: UUID, payload: ConnectionTest, response: Response,
            actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.preview, db, str(identifier), payload, actor)


@router.get("/connections/{identifier}/syncs", response_model=list[SyncRead])
def syncs(identifier: UUID, response: Response,
          actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.sync_history, db, str(identifier), actor)


@router.post("/connections/{identifier}/syncs", response_model=SyncRead)
def sync_start(identifier: UUID, payload: ConnectionTest, response: Response,
               actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.start_sync, db, str(identifier), payload, actor)


@router.post("/connections/{identifier}/syncs/{run_id}/step", response_model=SyncRead)
def sync_step(identifier: UUID, run_id: UUID, payload: SyncStep, response: Response,
              actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.sync_step, db, str(identifier), str(run_id), payload, actor)


@router.get("/connections/{identifier}/resources")
def imported(identifier: UUID, response: Response, limit: int = Query(default=50, ge=1, le=100),
             offset: int = Query(default=0, ge=0), search: str = Query(default="", max_length=128),
             actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, service.resources, db, str(identifier), actor, limit=limit, offset=offset, search=search)


@router.get("/connections/{identifier}/schedule", response_model=ScheduleRead)
def schedule_read(identifier: UUID, response: Response,
                  actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_scheduling.read, db, str(identifier), actor)


@router.post("/connections/{identifier}/notify", status_code=202)
def notify(identifier: UUID, payload: ConnectionTest, response: Response,
           actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_alerts.notify, db, str(identifier), payload, actor)


@router.put("/connections/{identifier}/schedule", response_model=ScheduleRead)
def schedule_update(identifier: UUID, payload: ScheduleUpdate, response: Response,
                    actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_scheduling.update, db, str(identifier), payload, actor)


@router.get("/connections/{identifier}/asset-mapping")
def asset_mapping(identifier: UUID, response: Response, limit: int = Query(default=100, ge=1, le=1000),
                  offset: int = Query(default=0, ge=0),
                  actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_bindings.listing, db, str(identifier), actor, limit=limit, offset=offset)


@router.get("/connections/{identifier}/asset-candidates")
def asset_candidates(identifier: UUID, response: Response, search: str = Query(min_length=1, max_length=128),
                     actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_bindings.search_assets, db, str(identifier), actor, search=search)


@router.put("/connections/{identifier}/asset-mapping")
def asset_mapping_update(identifier: UUID, payload: AssetBindingsUpdate, response: Response,
                         actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_bindings.update, db, str(identifier), payload, actor)


@router.get("/connections/{identifier}/alert-feed")
def alert_feed(identifier: UUID, response: Response,
               actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_alerts.read_feed, db, str(identifier), actor)


@router.put("/connections/{identifier}/alert-feed")
def alert_feed_update(identifier: UUID, payload: AlertFeedUpdate, response: Response,
                      actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_alerts.update_feed, db, str(identifier), payload, actor)


@router.get("/connections/{identifier}/external-alerts")
def external_alerts(identifier: UUID, response: Response, limit: int = Query(default=50, ge=1, le=100),
                    offset: int = Query(default=0, ge=0),
                    actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_alerts.listing, db, str(identifier), actor, limit=limit, offset=offset)


@router.post("/connections/{identifier}/external-alerts/{event_id}/silence")
def external_silence(identifier: UUID, event_id: UUID, payload: ExternalAlertSilence, response: Response,
                     actor: PrincipalContext = Depends(current_principal), db: Session = Depends(get_db)):
    return invoke(response, integration_alerts.silence, db, str(identifier), str(event_id), payload, actor)
