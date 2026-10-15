"""Opt-in native PostgreSQL large-catalog keyset and RLS acceptance."""

import os
from pathlib import Path
from uuid import uuid4

from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from icheck.activation_api import (
    get_activation_collector, page_activation_collectors,
    page_activation_policies,
)
from icheck.database import set_session_namespace
from icheck.services.control_plane_auth import PrincipalContext
from test_activation_catalog_pagination import _add_entry


URL = os.getenv("ICHECK_ACTIVATION_CATALOG_POSTGRES_TEST_URL")
ACK = os.getenv("ICHECK_ACTIVATION_CATALOG_POSTGRES_ACK")


def _operator() -> PrincipalContext:
    return PrincipalContext(
        principal_id=str(uuid4()), subject="catalog-operator@example.test",
        principal_type="user", permissions=frozenset({"assets.activate", "assets.read"}),
        role_names=("operator",), authorization_scope={"all": True},
        auth_method="bearer",
    )


@pytest.mark.skipif(
    not URL or ACK != "I_ACK_DISPOSABLE_ACTIVATION_CATALOG_DB",
    reason="Dedicated PostgreSQL activation catalog DB not acknowledged",
)
def test_native_large_activation_catalog_keyset_and_rls():
    engine = create_engine(URL, poolclass=NullPool, isolation_level="READ COMMITTED")
    try:
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT current_database()") ).startswith("icheck_quota_acceptance")
            # This checks the current catalog API/ORM, not an old migration's
            # backfill. Require the current schema, including draft revisions.
            root = Path(__file__).resolve().parents[1]
            config = Config(str(root / "alembic.ini"))
            config.set_main_option("script_location", str(root / "backend/migrations"))
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == ScriptDirectory.from_config(config).get_current_head()
            connection.execute(text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'icheck_activation_catalog_runtime') "
                "THEN CREATE ROLE icheck_activation_catalog_runtime NOLOGIN; END IF; END $$"
            ))
            connection.execute(text("GRANT USAGE ON SCHEMA public TO icheck_activation_catalog_runtime"))
            connection.execute(text(
                "GRANT SELECT ON artifacts, artifact_versions, collector_definitions, "
                "device_activation_policies TO icheck_activation_catalog_runtime"
            ))
        tenant_id, region_id = str(uuid4()), str(uuid4())
        foreign_tenant, foreign_region = str(uuid4()), str(uuid4())
        with Session(engine) as db:
            set_session_namespace(db, tenant_id, region_id)
            version_ids = [
                _add_entry(db, index, tenant_id=tenant_id, region_id=region_id)
                for index in range(525)
            ]
            db.commit()
            set_session_namespace(db, foreign_tenant, foreign_region)
            foreign_version_id = _add_entry(
                db, 999, tenant_id=foreign_tenant, region_id=foreign_region,
            )
            db.commit()
        operator = _operator()
        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_activation_catalog_runtime"))
            set_session_namespace(db, tenant_id, region_id)
            collector_ids, cursor = [], None
            while True:
                page = page_activation_collectors(
                    protocol="https_api", name_prefix=None, cursor=cursor,
                    limit=100, _=operator, db=db,
                )
                collector_ids.extend(item.artifact_version_id for item in page.items)
                if page.next_cursor is None:
                    break
                cursor = page.next_cursor
            assert len(collector_ids) == len(set(collector_ids)) == 525
            assert collector_ids[-1] == version_ids[-1]
            assert get_activation_collector(
                version_id=version_ids[-1], _=operator, db=db,
            ).target_schema["properties"]["index"]["const"] == 524
            policy_ids, cursor = [], None
            while True:
                page = page_activation_policies(
                    protocol=None, policy_status=None, name_prefix=None,
                    cursor=cursor, limit=100, _=operator, db=db,
                )
                policy_ids.extend(item.id for item in page.items)
                if page.next_cursor is None:
                    break
                cursor = page.next_cursor
            assert len(policy_ids) == len(set(policy_ids)) == 525
            assert db.scalar(text("SELECT COUNT(*) FROM artifacts")) == 525
            assert db.scalar(text("SELECT COUNT(*) FROM device_activation_policies")) == 525
            with pytest.raises(HTTPException) as denied:
                get_activation_collector(version_id=foreign_version_id, _=operator, db=db)
            assert denied.value.status_code == 404
        with Session(engine) as db:
            db.execute(text("SET ROLE icheck_activation_catalog_runtime"))
            set_session_namespace(db, foreign_tenant, foreign_region)
            assert db.scalar(text("SELECT COUNT(*) FROM artifacts")) == 1
            assert db.scalar(text("SELECT COUNT(*) FROM device_activation_policies")) == 1
    finally:
        engine.dispose()
