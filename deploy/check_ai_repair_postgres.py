"""Synthetic concurrency/RLS acceptance on a fixed private migrated r10 database."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from fastapi import HTTPException, Response
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.orm import Session
from icheck.config import get_settings
from icheck.database import DEFAULT_TENANT_ID, DEFAULT_REGION_ID, set_session_namespace
from icheck.models import AIModelConfig, AIModelRoute
from icheck.openrouter_schemas import OpenRouterConnect, OpenRouterConfigure
from icheck.services import openrouter_setup as setup
from icheck.services.control_plane_auth import development_principal
from icheck.services.tenancy import ensure_default_namespace
from icheck.ai_catalog_api import plan, apply, LifecycleApply
from icheck.services.ai_catalog_mutex import catalog_lock

URL = "postgresql+psycopg://zhao@127.0.0.1:55449/icheck_ai_repair_test"


def main():
    engine = create_engine(URL, pool_size=4)
    checks = []
    with engine.begin() as connection:
        assert connection.scalar(text("SELECT current_database()")) == "icheck_ai_repair_test"
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "r5v7x9z1c3e6"
        assert connection.scalar(text("SELECT count(*) FROM ai_managed_connections")) == 0
        connection.exec_driver_sql("CREATE ROLE ai_repair_test_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS")
        connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO ai_repair_test_runtime")
        connection.exec_driver_sql("GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA public TO ai_repair_test_runtime")
    with Session(engine) as db: ensure_default_namespace(db)

    @contextmanager
    def session(tenant=DEFAULT_TENANT_ID, region=DEFAULT_REGION_ID):
        with Session(engine, expire_on_commit=False) as db:
            event.listen(db, "after_begin", lambda s, t, c: c.exec_driver_sql("SET LOCAL ROLE ai_repair_test_runtime"))
            set_session_namespace(db, tenant, region)
            yield db

    class NetworkResponse:
        status = 200
        def __init__(self, document): self.body = json.dumps(document).encode()
        def read(self, limit): return self.body[:limit]
        def __enter__(self): return self
        def __exit__(self, *_): pass
    class Opener:
        def open(self, request, timeout):
            assert request.full_url in {setup.BASE + "/key", setup.BASE + "/models"}
            return NetworkResponse({"data": {"is_management_key": False}} if request.full_url.endswith("/key") else
                {"data": [{"id": name, "supported_parameters": ["response_format", "structured_outputs", "tools"]}
                    for name in ["example/old", "example/new"]]})

    with tempfile.TemporaryDirectory(prefix="icheck-ai-r10-key-") as directory:
        key = Path(directory) / "key"; key.write_bytes(os.urandom(32)); key.chmod(0o400)
        os.environ["ICHECK_AI_MANAGED_SECRET_KEY_FILE"] = str(key); get_settings.cache_clear()
        with patch.object(setup, "build_opener", lambda *_: Opener()):
            with session() as db:
                assert db.scalar(text("SELECT current_user")) == "ai_repair_test_runtime"
                connection = setup.connect(db, OpenRouterConnect(name="concurrent-repair", api_key="synthetic-test-key-not-real", approve_outbound=True), actor="test")
                old = setup.configure(db, connection.provider_id, OpenRouterConfigure(expected_connection_revision=1,
                    model_id="example/old", display_name="Operations reasoner", purposes=["investigation", "capability.authoring"]), actor="test")
                reviewed = setup.configuration_hash(db, connection.provider_id)
            payload = OpenRouterConfigure(expected_connection_revision=1, model_id="example/new", display_name="Operations reasoner",
                purposes=["investigation", "capability.authoring"], replace_existing_routes=True, expected_configuration_hash=reviewed)
            def configure(_):
                with session() as db:
                    try: setup.configure(db, connection.provider_id, payload, actor="test"); return "accepted"
                    except setup.ManagedAIConflict: db.rollback(); return "stale"
            with ThreadPoolExecutor(max_workers=2) as pool:
                assert sorted(pool.map(configure, range(2))) == ["accepted", "stale"]
            checks.append("concurrent_model_switch_one_winner")
            with session() as db:
                models = db.scalars(select(AIModelConfig)).all()
                assert len(models) == 2
                retained = db.get(AIModelConfig, old.model.id)
                assert retained.model_name == "example/old" and "previous" in retained.display_name
                assert all(route.primary_model_id != retained.id for route in db.scalars(select(AIModelRoute)))
                catalog_lock(db); _, reviewed_plan = plan(db, "models", retained.id, False); db.commit()
            checks.append("old_identity_and_routes_preserved")
            approval = LifecycleApply(enabled=False, preview_hash=reviewed_plan["preview_hash"], reason="Synthetic dependency review")
            def retire(_):
                with session() as db:
                    try: apply("models", retained.id, approval, Response(), principal=development_principal(), db=db); return "accepted"
                    except HTTPException as error:
                        assert error.status_code == 409; db.rollback(); return "stale"
            with ThreadPoolExecutor(max_workers=2) as pool:
                assert sorted(pool.map(retire, range(2))) == ["accepted", "stale"]
            checks.append("concurrent_retirement_one_winner")
            with session() as db:
                assert db.get(AIModelConfig, retained.id).enabled is False
                assert len(db.scalars(select(AIModelConfig)).all()) == 2
                _, dependency = plan(db, "providers", connection.provider_id, False)
                assert dependency["blockers"] and len(dependency["dependencies"]) == 1
            checks.append("dependency_blockers_without_cascade")
            with session("other-tenant", "other-region") as db:
                assert db.scalars(select(AIModelConfig)).all() == []
                try: plan(db, "models", retained.id, False)
                except HTTPException as error: assert error.status_code == 404
                else: raise AssertionError("Cross-namespace lifecycle read")
            checks.append("nonowner_rls_and_cross_namespace_denial")
    engine.dispose()
    print(json.dumps({"passed": True, "database": "isolated-migrated-postgresql-only", "checks": checks}))


if __name__ == "__main__": main()
