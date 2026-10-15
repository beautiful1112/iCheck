from pydantic import Field
from .monitoring_schemas import MonitoringApproval, MonitoringModel


class TemplateTargetTest(MonitoringModel):
    artifact_version_id: str = Field(min_length=36, max_length=36)
    device_id: str = Field(min_length=36, max_length=36)
    connection_id: str = Field(min_length=36, max_length=36)
    expected_device_revision: int = Field(ge=1)
    credential_profile_ref: str | None = Field(default=None, max_length=128)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)


class TemplateEnable(MonitoringApproval):
    artifact_version_id: str = Field(min_length=36, max_length=36)
    device_id: str = Field(min_length=36, max_length=36)
    connection_id: str = Field(min_length=36, max_length=36)
    expected_device_revision: int = Field(ge=1)


class TemplateModuleInstall(MonitoringModel):
    artifact_version_id: str = Field(min_length=36, max_length=36)
    expected_catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    preview_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)
