import importlib
from datetime import datetime, UTC

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError


def test_preset_migration_preserves_old_cipher_and_refuses_lossy_downgrade():
    old = importlib.import_module("migrations.versions.q4u6w8y0b2d5_managed_ai_connections")
    new = importlib.import_module("migrations.versions.a4g6i8k0m2p5_managed_ai_provider_presets")
    engine = create_engine("sqlite://")
    with engine.begin() as c:
        for table in ("ai_provider_configs", "credential_profiles"):
            c.execute(text(f"CREATE TABLE {table} (id VARCHAR(36) PRIMARY KEY)"))
            c.execute(text(f"INSERT INTO {table} VALUES ('old'), ('new')"))
        with Operations.context(MigrationContext.configure(c)): old.upgrade()
        insert = text("""INSERT INTO ai_managed_connections
            (id,provider_id,credential_profile_id,preset,encrypted_secret,outbound_enabled,revision,created_by,updated_by,created_at,updated_at)
            VALUES (:id,:id,:id,:preset,:cipher,1,3,'admin','admin',:now,:now)""")
        values = {"id": "old", "preset": "openrouter", "cipher": b"retained-encrypted-secret", "now": datetime.now(UTC)}
        c.execute(insert, values)
        before = dict(c.execute(text("SELECT * FROM ai_managed_connections")).mappings().one())
        with Operations.context(MigrationContext.configure(c)): new.upgrade()
        assert dict(c.execute(text("SELECT * FROM ai_managed_connections")).mappings().one()) == before
        with Operations.context(MigrationContext.configure(c)): new.downgrade()
        with Operations.context(MigrationContext.configure(c)): new.upgrade()
        assert dict(c.execute(text("SELECT * FROM ai_managed_connections")).mappings().one()) == before
        with pytest.raises(IntegrityError): c.execute(insert, {**values, "id": "new", "preset": "unreviewed"})
        c.execute(insert, {**values, "id": "new", "preset": "anthropic"})
        with Operations.context(MigrationContext.configure(c)), pytest.raises(RuntimeError, match="custody"):
            new.downgrade()
    engine.dispose()
