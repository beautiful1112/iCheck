"""Metric-rule preview/confirmation and the protected Alertmanager receiver."""
import json
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from .auth import current_principal
from .database import get_db
from .metric_alert_schemas import MetricRulePreview, MetricRuleConfirm, AlertmanagerWebhook
from .metric_rule_runtime import RuleRuntimeError, RuleRuntimeConflict
from .models import AlertRule, MetricRuleChange
from .services import metric_alerts as service
from .services.authorization_scope import namespace_clause
from .services.control_plane_auth import PrincipalContext
from .services.metrics import MetricQueryError, MetricBackendUnavailable

router=APIRouter(prefix="/api/v1/metric-alerts",tags=["Prometheus metric alerts"])


@router.get("/setup")
def setup(response:Response,actor:PrincipalContext=Depends(current_principal),db:Session=Depends(get_db)):
    def action():
        from .config import get_settings
        service.guard(actor); settings=get_settings(); ready=False
        try:
            runtime=service.RUNTIME(); runtime.guard(actor,settings.metric_rule_backend_id); runtime.read(); ready=True
        except RuleRuntimeError: pass
        return {"contract":"icheck.metric-rule/v1","runtime_provisioned":ready,"backend_id":settings.metric_rule_backend_id,
            "receiver":settings.metric_alert_receiver,"receiver_identity_configured":bool(settings.metric_alert_webhook_subject),
            "notification_delivery_verified":False}
    return invoke(response,action)


@router.get("/targets")
def targets(response:Response,actor:PrincipalContext=Depends(current_principal),db:Session=Depends(get_db)):
    return invoke(response,service.targets,db,actor)


def invoke(response,operation,*args,**kwargs):
    response.headers["Cache-Control"]="no-store"
    try: return operation(*args,**kwargs)
    except PermissionError as error: raise HTTPException(403,str(error)) from None
    except LookupError as error: raise HTTPException(404,str(error)) from None
    except RuleRuntimeConflict as error: raise HTTPException(409,str(error)) from None
    except RuleRuntimeError as error: raise HTTPException(400,str(error)) from None
    except (MetricQueryError,MetricBackendUnavailable): raise HTTPException(400,"Metric rule evidence is unavailable; inspect the approved source and Prometheus connection") from None
    except (ValueError,TypeError,KeyError): raise HTTPException(400,"Invalid metric rule or notification; no unreviewed change is admitted") from None


@router.get("/rules")
def listing(response:Response,actor:PrincipalContext=Depends(current_principal),db:Session=Depends(get_db)):
    def action():
        service.guard(actor)
        rows=db.scalars(select(AlertRule).where(AlertRule.event_type==service.EVENT,namespace_clause(AlertRule,actor)).order_by(AlertRule.name).limit(100)).all()
        return [{"id":row.id,"name":row.name,"enabled":row.enabled,"revision":row.conditions.get("revision",0),
            "definition":row.conditions.get("definition"),"applied_change_id":row.conditions.get("applied_change_id")} for row in rows]
    return invoke(response,action)


@router.post("/preview",status_code=201)
def preview(payload:MetricRulePreview,response:Response,actor:PrincipalContext=Depends(current_principal),db:Session=Depends(get_db)):
    return invoke(response,service.preview,db,payload,actor)


@router.get("/changes")
def changes(response:Response,limit:int=Query(default=30,ge=1,le=100),actor:PrincipalContext=Depends(current_principal),db:Session=Depends(get_db)):
    def action():
        service.guard(actor)
        return [service.read_change(row) for row in db.scalars(select(MetricRuleChange).where(namespace_clause(MetricRuleChange,actor))
            .order_by(MetricRuleChange.created_at.desc(),MetricRuleChange.id).limit(limit)).all()]
    return invoke(response,action)


@router.get("/changes/{identifier}")
def get_change(identifier:str,response:Response,actor:PrincipalContext=Depends(current_principal),db:Session=Depends(get_db)):
    def action():
        service.guard(actor); return service.read_change(service.change(db,identifier,actor))
    return invoke(response,action)


@router.post("/changes/{identifier}/confirm")
def confirm(identifier:str,payload:MetricRuleConfirm,response:Response,actor:PrincipalContext=Depends(current_principal),db:Session=Depends(get_db)):
    return invoke(response,service.confirm,db,identifier,payload,actor)


@router.post("/changes/{identifier}/restore-preview",status_code=201)
def restore(identifier:str,response:Response,actor:PrincipalContext=Depends(current_principal),db:Session=Depends(get_db)):
    return invoke(response,service.restore_preview,db,identifier,actor)


@router.post("/webhook")
async def webhook(request:Request,response:Response,actor:PrincipalContext=Depends(current_principal),db:Session=Depends(get_db)):
    content=bytearray()
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content)>256000: raise HTTPException(413,"Notification exceeds its byte bound")
    try: payload=AlertmanagerWebhook.model_validate(json.loads(content))
    except (ValueError,TypeError): raise HTTPException(422,"Invalid Alertmanager notification; raw values are not returned") from None
    return invoke(response,service.ingest,db,payload,actor)
