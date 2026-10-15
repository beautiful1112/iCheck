"""Destructive synthetic acceptance only on the fixed private r9 test database."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import tempfile
from sqlalchemy import create_engine, text, select
from sqlalchemy.orm import Session
from icheck.config import get_settings
from icheck.database import set_session_namespace
from icheck.device_credential_schemas import DeviceCredentialCreate, DeviceCredentialUpdate
from icheck.models import CredentialProfile, ManagedDeviceCredential
from icheck.services import device_credentials, device_onboarding
from icheck.services.control_plane_auth import development_principal
from icheck.services.tenancy import ensure_default_namespace
from icheck.onboarding_schemas import OnboardingInput, OnboardingApprove

URL = "postgresql+psycopg://zhao@127.0.0.1:55439/icheck_r9_test"


def main():
    engine = create_engine(URL)
    checks = []
    with tempfile.TemporaryDirectory(prefix="icheck-device-key-test-") as directory:
        key = Path(directory) / "device.key"; key.write_bytes(os.urandom(32)); key.chmod(0o400)
        os.environ["ICHECK_DEVICE_MANAGED_SECRET_KEY_FILE"] = str(key); get_settings.cache_clear()
        def session():
            db = Session(engine, expire_on_commit=False)
            set_session_namespace(db, "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002")
            return db
        with session() as db:
            ensure_default_namespace(db)
            p = device_credentials.create(db, DeviceCredentialCreate(name="postgres-snmp", site="LAB", kind="snmp_v2c",
                community="synthetic-postgres-community"), "test")
        with engine.begin() as c:
            c.execute(text("CREATE ROLE r9_custody_probe NOLOGIN"))
            c.execute(text("GRANT SELECT,INSERT,UPDATE ON managed_device_credentials,device_onboarding_receipts,credential_profiles TO r9_custody_probe"))
        with engine.begin() as c:
            c.execute(text("SET LOCAL ROLE r9_custody_probe"))
            c.execute(text("SET LOCAL icheck.tenant_id='00000000-0000-0000-0000-000000000001'"))
            c.execute(text("SET LOCAL icheck.region_id='00000000-0000-0000-0000-000000000002'"))
            assert c.scalar(text("SELECT count(*) FROM managed_device_credentials")) == 1
            with c.begin_nested() as savepoint:
                try:
                    c.execute(text("UPDATE managed_device_credentials SET site='OTHER',revision=revision+1"))
                except Exception:
                    savepoint.rollback(); checks.append("immutable_site_binding")
                else:
                    raise AssertionError("Credential site mutation was accepted")
            with c.begin_nested() as savepoint:
                try: c.execute(text("DELETE FROM managed_device_credentials"))
                except Exception: savepoint.rollback(); checks.append("no_delete_privilege")
                else: raise AssertionError("Custody deletion accepted")
            c.execute(text("SET LOCAL icheck.region_id='00000000-0000-0000-0000-000000000099'"))
            assert c.scalar(text("SELECT count(*) FROM managed_device_credentials")) == 0
            assert c.scalar(text("SELECT count(*) FROM device_onboarding_receipts")) == 0
            checks.append("nonowner_namespace_rls")
        def rotate(_):
            with session() as db:
                try:
                    device_credentials.update(db, p["id"], DeviceCredentialUpdate(name=p["name"], site="LAB", kind="snmp_v2c",
                        community="synthetic-rotated-community", expected_revision=1, reason="Concurrent acceptance"), "test")
                    return "accepted"
                except ValueError:
                    db.rollback(); return "stale"
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(rotate, range(2))) == ["accepted", "stale"]
        checks.append("concurrent_rotation_one_winner")
        principal = development_principal()
        body = OnboardingInput(site="LAB", credential_profile_ref=p["name"], protocol="snmp",
            devices=[{"name": "postgres-switch", "management_ip": "198.18.0.10", "kind": "switch"}])
        with session() as db:
            plan = device_onboarding.preview(db, body, principal)
        approval = OnboardingApprove(**plan["input"], preview_hash=plan["preview_hash"], reason="Synthetic acceptance")
        def approve(_):
            with session() as db:
                return device_onboarding.approve(db, approval, principal)
        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = list(pool.map(approve, range(2)))
        assert receipts[0]["device_ids"] == receipts[1]["device_ids"]
        assert sorted(r["replayed"] for r in receipts) == [False, True]
        checks.append("concurrent_atomic_onboarding_replay")
        print(json.dumps({"passed": True, "database": "isolated-synthetic-only", "checks": checks}))


if __name__ == "__main__": main()
