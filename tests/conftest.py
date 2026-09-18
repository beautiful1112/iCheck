import os

os.environ["ICHECK_DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["ICHECK_AUTO_CREATE_SCHEMA"] = "true"
os.environ["ICHECK_COLLECTOR_REGISTRATION_TOKEN"] = "test-registration-token"
os.environ["ICHECK_METRICS_ALLOWED_HOSTS"] = (
    "prometheus.example.test,metrics.example.test"
)
os.environ["ICHECK_AI_ALLOWED_HOSTS"] = "models.example.test"
os.environ["ICHECK_TEST_AI_PROVIDER_TOKEN"] = "unit-test-provider-token"

import pytest
from fastapi.testclient import TestClient

from icheck.database import Base, engine
from icheck.main import app


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
