from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .activation_api import router as activation_router
from .artifact_replay_api import router as artifact_replay_router
from .agent_api import router as agent_router
from .ai_api import router as ai_router
from .openrouter_api import router as openrouter_router, managed_router as managed_ai_router
from .ai_catalog_api import router as ai_catalog_router
from .device_credential_api import router as device_credential_router
from .onboarding_api import router as onboarding_router
from .managed_credential_worker_api import router as managed_credential_worker_router
from .auth_api import router as auth_router
from .api import router
from .inventory_views_api import router as inventory_views_router
from .collector_api import router as collector_router
from .capability_catalog_api import router as capability_catalog_router
from .capability_pack_api import router as capability_pack_router
from .operations_package_api import router as operations_package_router
from .capability_promotion_api import router as capability_promotion_router
from .capability_transparency_api import router as capability_transparency_router
from .capability_pack_revocation_api import (
    router as capability_pack_revocation_router,
)
from .metrics_api import router as metrics_router
from .integration_api import router as integration_router
from .grafana_api import router as grafana_router
from .research_api import router as research_router
from .autonomy_api import router as autonomy_router
from .monitoring_api import router as monitoring_router
from .monitoring_template_api import router as monitoring_template_router
from .logs_api import router as logs_router
from .indicator_polling_api import router as indicator_polling_router
from .indicator_artifact_api import router as indicator_artifact_router
from .mcp_api import router as mcp_router
from .projection_api import router as projection_router
from .remote_catalog_api import router as remote_catalog_router
from .report_api import router as report_router
from .trust_distribution_api import router as trust_distribution_router
from .trust_recovery_api import router as trust_recovery_router
from .promotion_recovery_api import router as promotion_recovery_router
from .rollout_api import fleet_router, router as rollout_router
from .scaling_api import router as scaling_router
from .quality_api import router as quality_router
from .skill_runtime_api import router as skill_runtime_router
from .situation_api import router as situation_router
from .source_qualification_api import router as source_qualification_router
from .source_replacement_api import router as source_replacement_router
from .situation_recovery_api import router as situation_recovery_router
from .situation_closure_api import router as situation_closure_router
from .service_catalog_api import router as service_catalog_router
from .studio_api import router as studio_router
from .snmp_attestation_api import router as snmp_attestation_router
from .topology_api import router as topology_router
from .visualization_api import router as visualization_router
from .tenancy_api import router as tenancy_router
from .transparency_witness_api import router as transparency_witness_router
from .workflow_runtime_api import router as workflow_runtime_router
from .config import get_settings
from .metric_alert_api import router as metric_alert_router
from .alertmanager_api import router as alertmanager_router
from .credentials import build_server_credential_providers
from .database import SessionLocal, init_db, set_session_namespace
from .langgraph_runtime import postgres_checkpointer
from .device_api import router as device_router, worker_router as device_worker_router
from .ecosystem_transport_api import router as ecosystem_transport_router
from .services.alerts import ensure_default_rules
from .builtin_agent_tools import ensure_builtin_agent_tools
from .services.agent_profiles import ensure_default_agent_profiles
from .services.change_risk_policies import ensure_change_risk_policies
from .services.control_plane_auth import ensure_builtin_roles
from .services.tenancy import ensure_default_namespace


settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Validate configured control-plane secret backends before serving traffic.
    # Provider construction does not read or retain any secret value.
    build_server_credential_providers(settings=settings)
    if settings.auto_create_schema:
        init_db()
    if settings.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        # LangGraph's first setup may CREATE INDEX CONCURRENTLY. Do it before
        # opening an API transaction; otherwise the first runtime request can
        # wait on its own still-open transaction's virtual XID.
        with postgres_checkpointer(settings.database_url):
            pass
    with SessionLocal() as db:
        tenant, region = ensure_default_namespace(db)
        set_session_namespace(db, tenant.id, region.id)
        ensure_default_rules(db)
        ensure_builtin_roles(db)
        ensure_change_risk_policies(db)
        ensure_default_agent_profiles(db)
        if settings.environment == "production":
            ensure_builtin_agent_tools(db)
    yield


app = FastAPI(
    title="iCheck API",
    version="0.1.0",
    description=(
        "Artifact, distributed collection, infrastructure inventory, endpoint "
        "identity, wireless client, and alert APIs for the iCheck platform."
    ),
    lifespan=lifespan,
)
@app.exception_handler(RequestValidationError)
async def redact_auth_validation(request: Request, exc: RequestValidationError):
    if not request.url.path.startswith(("/api/v1/auth/", "/api/v1/ai/", "/api/v1/research/", "/api/v1/device-credentials", "/api/v1/grafana/", "/api/v1/metric-alerts/", "/api/v1/assets/", "/api/v1/capability-studio/", "/api/v1/integrations/")):
        return await request_validation_exception_handler(request, exc)
    # FastAPI's default validation response echoes rejected input, including
    # secrets nested in a body or supplied as an unknown field.
    return JSONResponse(status_code=422, headers={"Cache-Control": "no-store"}, content={
        "detail": [{key: error[key] for key in ("loc", "msg", "type")}
                   for error in exc.errors()]
    })


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Icheck-Snapshot-SHA256", "X-Icheck-Content-SHA256",
                    "X-Icheck-Artifact-Version-ID", "X-Icheck-Renderer"],
)
app.include_router(router)
app.include_router(inventory_views_router)
app.include_router(collector_router)
app.include_router(capability_catalog_router)
app.include_router(capability_pack_router)
app.include_router(operations_package_router)
app.include_router(capability_promotion_router)
app.include_router(capability_pack_revocation_router)
app.include_router(capability_transparency_router)
app.include_router(metrics_router)
app.include_router(integration_router)
app.include_router(grafana_router)
app.include_router(research_router)
app.include_router(autonomy_router)
app.include_router(metric_alert_router)
app.include_router(alertmanager_router)
app.include_router(monitoring_router)
app.include_router(monitoring_template_router)
app.include_router(logs_router)
app.include_router(indicator_polling_router)
app.include_router(indicator_artifact_router)
app.include_router(ai_router)
app.include_router(openrouter_router)
app.include_router(managed_ai_router)
app.include_router(ai_catalog_router)
app.include_router(device_credential_router)
app.include_router(onboarding_router)
app.include_router(managed_credential_worker_router)
app.include_router(device_router)
app.include_router(device_worker_router)
app.include_router(activation_router)
app.include_router(agent_router)
app.include_router(auth_router)
app.include_router(tenancy_router)
app.include_router(studio_router)
app.include_router(snmp_attestation_router)
app.include_router(mcp_router)
app.include_router(artifact_replay_router)
app.include_router(rollout_router)
app.include_router(fleet_router)
app.include_router(skill_runtime_router)
app.include_router(situation_router)
app.include_router(source_qualification_router)
app.include_router(source_replacement_router)
app.include_router(situation_recovery_router)
app.include_router(situation_closure_router)
app.include_router(service_catalog_router)
app.include_router(workflow_runtime_router)
app.include_router(projection_router)
app.include_router(remote_catalog_router)
app.include_router(report_router)
app.include_router(trust_distribution_router)
app.include_router(trust_recovery_router)
app.include_router(promotion_recovery_router)
app.include_router(topology_router)
app.include_router(visualization_router)
app.include_router(transparency_witness_router)
app.include_router(ecosystem_transport_router)
app.include_router(scaling_router)
app.include_router(quality_router)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {"name": "iCheck API", "docs": "/docs", "health": "/api/v1/health"}
