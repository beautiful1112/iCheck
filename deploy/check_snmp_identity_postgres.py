"""Private PostgreSQL discovery-search and correction acceptance, never live DB."""
import json
import os
from pathlib import Path
import sys
import tempfile

from check_optional_location_postgres import ROOT, PG, run


def main():
    with tempfile.TemporaryDirectory(prefix="icheck-snmp-r16-pg-") as directory:
        root = Path(directory); data = root / "data"
        run([str(PG / "initdb"), "-D", str(data), "--auth=trust", "--no-locale", "--encoding=UTF8"])
        run([str(PG / "pg_ctl"), "-D", str(data), "-l", str(root / "postgres.log"), "-o", f"-k {root} -c listen_addresses=''", "-w", "start"])
        try:
            run([str(PG / "createdb"), "-h", str(root), "snmp_acceptance"])
            url = "postgresql+psycopg://zhao@/snmp_acceptance?host=" + str(root)
            env = {**os.environ, "ICHECK_DATABASE_URL": url, "ICHECK_AUTO_CREATE_SCHEMA": "false", "PYTHONPATH": str(ROOT / "backend")}
            run([sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"), "upgrade", "head"], env=env)
            from sqlalchemy import create_engine
            from sqlalchemy.orm import Session
            from icheck.database import set_session_namespace
            from icheck.services.tenancy import ensure_default_namespace
            from icheck.services.control_plane_auth import development_principal
            from icheck.services.devices import onboard_device, update_snmp_configuration
            from icheck.device_schemas import DeviceOnboardCreate, DeviceSNMPConfigurationUpdate
            from icheck.device_api import _device_inventory_query
            from icheck.models import utcnow
            engine = create_engine(url)
            with Session(engine, expire_on_commit=False) as db:
                set_session_namespace(db, "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002")
                ensure_default_namespace(db)
                device = onboard_device(db, DeviceOnboardCreate(name="198.18.0.40", management_ip="198.18.0.40", kind="switch",
                    created_by="test", connections=[{"protocol": "snmp"}]))
                connection = device.connections[0]
                connection.verification_status = "verified"; connection.last_verified_at = utcnow()
                connection.last_verification_evidence = {"target_host": device.management_ip, "identity_revision": device.identity_revision,
                    "discovered_name": "synthetic-access"}
                db.commit()
                principal = development_principal()
                query = _device_inventory_query(principal, "synthetic-access", None, None, None)
                assert [row.id for row in db.scalars(query)] == [device.id]
                assert device.discovered_name == "synthetic-access"
                device.identity_revision += 1; db.commit()
                assert device.discovered_name is None and list(db.scalars(query)) == []
                result = update_snmp_configuration(db, device.id, connection.id,
                    DeviceSNMPConfigurationUpdate(expected_revision=1, modules=["if_mib"], actor="test",
                        reason="Correct synthetic SNMP configuration only."), actor="test")
                assert result.revision == 2 and result.connections[0].verification_status == "pending"
                assert result.site is None and result.location == {}
            engine.dispose()
            print(json.dumps({"passed": True, "database": "private-temporary-postgresql16", "checks": [
                "json_discovery_search", "identity_revision_fences_discovery", "revisioned_snmp_correction", "blank_placement_retained"],
                "live_database_changed": False, "lab_network_calls": 0}))
        finally:
            run([str(PG / "pg_ctl"), "-D", str(data), "-m", "fast", "-w", "stop"])


if __name__ == "__main__": main()
