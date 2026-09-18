from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ICHECK_",
        env_file=".env",
        extra="ignore",
    )

    app_name: str = "iCheck"
    environment: str = "development"
    database_url: str = "sqlite+pysqlite:///./icheck.db"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    auto_create_schema: bool = True
    collector_registration_token: str | None = None
    metrics_allowed_hosts: str = ""
    ai_allowed_hosts: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def metrics_allowed_host_list(self) -> list[str]:
        return [
            host.strip()
            for host in self.metrics_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def ai_allowed_host_list(self) -> list[str]:
        return [
            host.strip()
            for host in self.ai_allowed_hosts.split(",")
            if host.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
