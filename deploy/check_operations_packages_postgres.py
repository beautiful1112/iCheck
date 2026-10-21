"""Disposable PostgreSQL acceptance for N1 providers and N2/N3 package imports."""
import importlib
from check_monitoring_integrations_postgres import main


def verify(engine, identifier, principal):
    from sqlalchemy import select, text
    from sqlalchemy.orm import Session
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from icheck.database import set_session_namespace
    from icheck.models import OperationsPackageInstallation, MonitoringIntegrationConnection
    from icheck.builtin_agent_tools import ensure_builtin_agent_tools
    from icheck.builtin_operations import packages
    from icheck.operations_package_schemas import OperationsInstall
    from icheck.services import operations_packages

    with Session(engine, expire_on_commit=False) as db:
        set_session_namespace(db, principal.tenant_id, principal.region_id)
        ensure_builtin_agent_tools(db)
        document = next(p for p in packages() if p.name == "http-api-diagnostics")
        payload = OperationsInstall(package=document, confirm=True)
        first = operations_packages.install(db, payload, principal, builtin=True)
        again = operations_packages.install(db, payload, principal, builtin=True)
        assert first["id"] == again["id"] and not first["activated"]
        assert len(first["components"]) == 2
        assert all(c["status"] == "validated" for c in first["components"])
    with engine.begin() as connection:
        connection.exec_driver_sql("GRANT SELECT,INSERT,UPDATE ON operations_package_installations TO integration_runtime")
        connection.exec_driver_sql("SET LOCAL ROLE integration_runtime")
        assert connection.scalar(text("SELECT row_security_active('operations_package_installations')"))
        assert connection.scalar(text("SELECT count(*) FROM operations_package_installations")) == 0
        connection.execute(text("SELECT set_config('icheck.tenant_id',:tenant,true),set_config('icheck.region_id',:region,true)"),
                           {"tenant": principal.tenant_id, "region": principal.region_id})
        assert connection.scalar(text("SELECT count(*) FROM operations_package_installations")) == 1
        connection.execute(text("SELECT set_config('icheck.region_id','another-region',true)"))
        assert connection.scalar(text("SELECT count(*) FROM operations_package_installations")) == 0
    migration = importlib.import_module("migrations.versions.h1n3q5s7u9w2_operations_packages")
    with engine.begin() as connection, Operations.context(MigrationContext.configure(connection)):
        try:
            migration.downgrade()
        except RuntimeError:
            pass
        else:
            raise AssertionError("Package receipt loss was permitted")
    with engine.begin() as connection:
        # Isolated fixture only; verify the database accepts the expanded enum.
        connection.execute(text("UPDATE monitoring_integration_connections SET provider='solarwinds_orion' WHERE id=:id"),
                           {"id": identifier})
    migration = importlib.import_module("migrations.versions.g0m2p4r6t8v1_monitoring_providers")
    with engine.begin() as connection, Operations.context(MigrationContext.configure(connection)):
        try:
            migration.downgrade()
        except RuntimeError:
            pass
        else:
            raise AssertionError("Configured provider loss was permitted")
    return ["operations_import_validated_only", "operations_import_idempotent",
            "operations_nonowner_rls", "operations_namespace_isolation",
            "package_receipt_downgrade_guard", "provider_constraint_expanded", "provider_downgrade_guard"]


if __name__ == "__main__":
    main(target="h1n3q5s7u9w2", extra_checks=verify)
