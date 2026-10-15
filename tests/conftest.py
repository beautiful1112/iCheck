import os

os.environ["ICHECK_DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["ICHECK_RESEARCH_ENABLED"] = "false"  # Tests must explicitly inject public research transports.
os.environ["ICHECK_AUTO_CREATE_SCHEMA"] = "true"
os.environ["ICHECK_COLLECTOR_REGISTRATION_TOKEN"] = "test-registration-token"
os.environ["ICHECK_AGENT_REGISTRATION_TOKEN"] = "test-agent-registration-token"
os.environ["ICHECK_MCP_ATTESTOR_REGISTRATION_TOKEN"] = (
    "test-mcp-attestor-registration-token"
)
os.environ["ICHECK_METRICS_ALLOWED_HOSTS"] = (
    "prometheus.example.test,metrics.example.test"
)
os.environ["ICHECK_LOGS_ALLOWED_HOSTS"] = "loki.example.test"
os.environ["ICHECK_AI_ALLOWED_HOSTS"] = "models.example.test"
os.environ["ICHECK_MCP_ALLOWED_HOSTS"] = "mcp.example.test,localhost,127.0.0.1"
os.environ["ICHECK_CAPABILITY_CATALOG_ALLOWED_HOSTS"] = "catalog.example.test"
os.environ["ICHECK_ECOSYSTEM_TRANSPORT_ALLOWED_HOSTS"] = (
    "witness.example.test,production.example.test"
)
os.environ["ICHECK_RECOVERY_SIGNING_ALLOWED_HOSTS"] = "signer.example.test"
os.environ["ICHECK_CONTROL_PLANE_AUTH_MODE"] = "disabled"
os.environ["ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED"] = "true"
os.environ["ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN"] = (
    "test-control-plane-bootstrap-token"
)
os.environ["ICHECK_TEST_AI_PROVIDER_TOKEN"] = "unit-test-provider-token"
os.environ["ICHECK_TEST_MCP_TOKEN"] = "unit-test-mcp-token"
os.environ["ICHECK_TEST_TRANSPORT_TOKEN"] = "unit-test-transport-token"
os.environ["ICHECK_TEST_RECOVERY_SIGNER_TOKEN"] = "unit-test-recovery-token"

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
