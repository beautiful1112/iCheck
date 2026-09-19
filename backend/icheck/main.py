from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .activation_api import router as activation_router
from .agent_api import router as agent_router
from .ai_api import router as ai_router
from .auth_api import router as auth_router
from .api import router
from .collector_api import router as collector_router
from .metrics_api import router as metrics_router
from .config import get_settings
from .database import SessionLocal, init_db
from .device_api import router as device_router, worker_router as device_worker_router
from .services.alerts import ensure_default_rules
from .services.control_plane_auth import ensure_builtin_roles


settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.auto_create_schema:
        init_db()
    with SessionLocal() as db:
        ensure_default_rules(db)
        ensure_builtin_roles(db)
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)
app.include_router(collector_router)
app.include_router(metrics_router)
app.include_router(ai_router)
app.include_router(device_router)
app.include_router(device_worker_router)
app.include_router(activation_router)
app.include_router(agent_router)
app.include_router(auth_router)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {"name": "iCheck API", "docs": "/docs", "health": "/api/v1/health"}
