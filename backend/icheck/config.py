import ipaddress
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ICHECK_",
        env_file=".env",
        extra="ignore",
        # Native startup tracebacks must not echo the environment input map,
        # which can contain database passwords and registration credentials.
        hide_input_in_errors=True,
    )

    app_name: str = "iCheck"
    environment: str = "development"
    database_url: str = "sqlite+pysqlite:///./icheck.db"
    checkpoint_setup_mode: Literal["automatic", "verify"] | None = None
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    auto_create_schema: bool = True
    collector_registration_token: str | None = None
    agent_registration_token: str | None = None
    mcp_attestor_registration_token: str | None = None
    worker_mtls_mode: Literal["disabled", "optional", "required"] = "disabled"
    worker_mtls_trusted_proxies: str = "127.0.0.1/32,::1/128"
    metrics_allowed_hosts: str = ""
    # Exact HTTPS origins, including non-default ports. No wildcard egress.
    monitoring_integration_allowed_origins: str = ""
    logs_allowed_hosts: str = ""
    ai_allowed_hosts: str = ""
    # Native installer provisions this key once, outside SQL and application bundles.
    ai_managed_secret_key_file: str | None = None
    grafana_secret_key_file: str | None = None
    grafana_allowed_hosts: str = ""
    device_managed_secret_key_file: str | None = None
    managed_monitoring_gateway_subject: str | None = None
    metric_rule_directory: str | None = None
    metric_rule_backend_id: str | None = None
    metric_rule_tenant_id: str | None = None
    metric_rule_region_id: str | None = None
    metric_rule_prometheus_url: str = "http://127.0.0.1:9090"
    metric_rule_promtool_path: str = "/opt/icheck/bin/promtool"
    metric_alert_webhook_subject: str | None = None
    metric_alert_receiver: str = "icheck-inbox"
    metric_alertmanager_url: str | None = None
    mcp_allowed_hosts: str = ""
    mcp_oauth_allowed_hosts: str = ""
    mcp_oauth_redirect_uri: str | None = None
    mcp_oauth_success_url: str | None = None
    mcp_oauth_client_metadata_url: str | None = None
    mcp_oauth_transaction_secret_file: str | None = None
    mcp_oauth_timeout_seconds: int = 10
    mcp_oauth_transaction_ttl_minutes: int = 10
    mcp_oauth_max_pending_transactions: int = 10_000
    capability_catalog_allowed_hosts: str = ""
    ecosystem_transport_allowed_hosts: str = ""
    recovery_signing_allowed_hosts: str = ""
    report_archive_allowed_hosts: str = ""
    server_secret_vault_address: str | None = None
    server_secret_vault_token_file: str | None = None
    server_secret_vault_namespace: str | None = None
    server_secret_vault_timeout_seconds: int = 5
    artifact_signature_policy: Literal["optional", "required"] = "optional"
    require_governed_change_contracts: bool = False
    enable_reviewed_change_execution: bool = False
    enable_reviewed_rollback_execution: bool = False
    enable_mcp_write_disposition_custody: bool = False
    enable_reviewed_situation_closure: bool = False
    enable_reviewed_source_replacement: bool = False
    enable_replacement_recovery: bool = False
    enable_replacement_situation_closure: bool = False
    control_plane_auth_mode: Literal["disabled", "required"] = "disabled"
    control_plane_bootstrap_token: str | None = None
    control_plane_default_token_ttl_hours: int = 720
    control_plane_browser_session_ttl_hours: int = 12
    control_plane_session_cookie_secure: bool = False
    control_plane_session_cookie_samesite: Literal["lax", "strict"] = "strict"
    # Legacy programmatic token-to-cookie exchange is opt-in; it is not GUI login.
    control_plane_local_browser_login_enabled: bool = False
    control_plane_password_login_enabled: bool = True
    control_plane_password_login_tenant: str = "local"
    control_plane_oidc_enabled: bool = False
    control_plane_oidc_display_name: str = "Enterprise SSO"
    control_plane_oidc_issuer: str | None = None
    control_plane_oidc_client_id: str | None = None
    control_plane_oidc_client_secret_file: str | None = None
    control_plane_oidc_transaction_secret_file: str | None = None
    control_plane_oidc_redirect_uri: str | None = None
    control_plane_oidc_success_url: str | None = None
    control_plane_oidc_allowed_hosts: str = ""
    control_plane_oidc_scopes: str = "openid profile email"
    control_plane_oidc_timeout_seconds: int = 10
    control_plane_oidc_transaction_ttl_minutes: int = 10
    control_plane_oidc_max_pending_transactions: int = 10_000
    control_plane_trusted_proxy_enabled: bool = False
    control_plane_trusted_proxy_display_name: str = "Identity gateway"
    control_plane_trusted_proxy_issuer: str | None = None
    control_plane_trusted_proxy_success_url: str | None = None
    control_plane_trusted_proxy_networks: str = "127.0.0.1/32,::1/128"
    control_plane_trusted_proxy_shared_secret_files: str = ""
    control_plane_workload_oidc_enabled: bool = False
    control_plane_workload_oidc_issuer: str | None = None
    control_plane_workload_oidc_audience: str | None = None
    control_plane_workload_oidc_allowed_hosts: str = ""
    control_plane_workload_oidc_timeout_seconds: int = 10
    control_plane_workload_token_ttl_minutes: int = 15
    sandbox_enabled: bool = False
    sandbox_backend: Literal["process", "bubblewrap"] = "process"
    sandbox_bwrap_path: str = "/usr/bin/bwrap"
    sandbox_python_path: str = "/usr/bin/python3"
    sandbox_timeout_seconds: int = 5
    extension_packages_root: str | None = None
    # Public documentation research. No model/provider secret is reused.
    research_enabled: bool = True
    research_provider: Literal["unconfigured", "bing_rss", "brave", "searxng"] = "unconfigured"
    research_api_key_file: str | None = None
    research_searxng_url: str | None = None
    research_timeout_seconds: int = 12

    @model_validator(mode="after")
    def validate_security_mode(self) -> "Settings":
        if not 2 <= self.research_timeout_seconds <= 30:
            raise ValueError("research_timeout_seconds must be between 2 and 30")
        if self.enable_reviewed_change_execution and not self.require_governed_change_contracts:
            raise ValueError("Reviewed change execution requires governed change contracts")
        if self.enable_reviewed_rollback_execution and not self.enable_reviewed_change_execution:
            raise ValueError("Reviewed rollback execution requires reviewed primary execution")
        if (
            self.environment.strip().lower() == "production"
            and self.checkpoint_setup_mode == "automatic"
        ):
            raise ValueError(
                "Production checkpoint setup must use the owner-provisioned verify mode"
            )
        if not 1 <= self.control_plane_default_token_ttl_hours <= 8760:
            raise ValueError(
                "control_plane_default_token_ttl_hours must be between 1 and 8760"
            )
        if not 1 <= self.control_plane_browser_session_ttl_hours <= 168:
            raise ValueError(
                "control_plane_browser_session_ttl_hours must be between 1 and 168"
            )
        if not 1 <= self.control_plane_oidc_timeout_seconds <= 30:
            raise ValueError(
                "control_plane_oidc_timeout_seconds must be between 1 and 30"
            )
        if not 5 <= self.control_plane_oidc_transaction_ttl_minutes <= 30:
            raise ValueError(
                "control_plane_oidc_transaction_ttl_minutes must be between 5 and 30"
            )
        if not (
            1
            <= self.control_plane_oidc_max_pending_transactions
            <= 1_000_000
        ):
            raise ValueError(
                "control_plane_oidc_max_pending_transactions must be between "
                "1 and 1000000"
            )
        if self.control_plane_oidc_enabled:
            required_oidc = {
                "issuer": self.control_plane_oidc_issuer,
                "client_id": self.control_plane_oidc_client_id,
                "client_secret_file": self.control_plane_oidc_client_secret_file,
                "transaction_secret_file": (
                    self.control_plane_oidc_transaction_secret_file
                ),
                "redirect_uri": self.control_plane_oidc_redirect_uri,
                "success_url": self.control_plane_oidc_success_url,
            }
            missing = [name for name, value in required_oidc.items() if not value]
            if missing:
                raise ValueError(
                    "OIDC federation requires: " + ", ".join(sorted(missing))
                )
            if not self.control_plane_oidc_allowed_host_list:
                raise ValueError(
                    "OIDC federation requires ICHECK_CONTROL_PLANE_OIDC_ALLOWED_HOSTS"
                )
            if any(
                "://" in host
                or "/" in host
                or not host
                for host in self.control_plane_oidc_allowed_host_list
            ):
                raise ValueError("OIDC allowed hosts must contain exact hostnames")
            if "openid" not in self.control_plane_oidc_scope_list:
                raise ValueError("OIDC federation scopes must include openid")
            if "offline_access" in self.control_plane_oidc_scope_list:
                raise ValueError(
                    "OIDC federation does not persist refresh tokens; "
                    "offline_access is forbidden"
                )
            for path in (
                self.control_plane_oidc_client_secret_file,
                self.control_plane_oidc_transaction_secret_file,
            ):
                if path and not path.startswith("/"):
                    raise ValueError("OIDC secret file paths must be absolute")
            issuer = urlsplit(self.control_plane_oidc_issuer or "")
            if (
                issuer.scheme != "https"
                or not issuer.hostname
                or issuer.username
                or issuer.password
                or issuer.query
                or issuer.fragment
                or issuer.hostname.lower()
                not in self.control_plane_oidc_allowed_host_list
            ):
                raise ValueError(
                    "OIDC issuer must be an allowlisted HTTPS URL without a query"
                )
            for value, label, origin_only in (
                (
                    self.control_plane_oidc_redirect_uri or "",
                    "OIDC redirect URI",
                    False,
                ),
                (
                    self.control_plane_oidc_success_url or "",
                    "OIDC success URL",
                    True,
                ),
            ):
                parsed = urlsplit(value)
                secure = parsed.scheme == "https"
                loopback = parsed.scheme == "http" and parsed.hostname in {
                    "127.0.0.1",
                    "::1",
                    "localhost",
                }
                if (
                    not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or parsed.fragment
                    or not (
                        secure
                        or (
                            loopback
                            and self.environment.strip().lower() != "production"
                        )
                    )
                    or (
                        origin_only
                        and (parsed.path not in {"", "/"} or parsed.query)
                    )
                ):
                    raise ValueError(f"{label} is invalid")
        for proxy in self.control_plane_trusted_proxy_network_list:
            try:
                ipaddress.ip_network(proxy, strict=False)
            except ValueError as exc:
                raise ValueError(
                    "trusted-proxy browser networks must contain only IP/CIDR values"
                ) from exc
        if len(self.control_plane_trusted_proxy_shared_secret_file_list) > 2:
            raise ValueError(
                "trusted-proxy browser federation accepts at most two shared-secret files"
            )
        for path in self.control_plane_trusted_proxy_shared_secret_file_list:
            if not path.startswith("/"):
                raise ValueError(
                    "trusted-proxy browser shared-secret file paths must be absolute"
                )
        if self.control_plane_trusted_proxy_enabled:
            issuer = (self.control_plane_trusted_proxy_issuer or "").strip()
            if (
                not issuer
                or len(issuer) > 255
                or issuer != self.control_plane_trusted_proxy_issuer
                or any(ord(character) < 0x20 for character in issuer)
            ):
                raise ValueError(
                    "trusted-proxy browser issuer must contain 1 to 255 printable characters"
                )
            if not self.control_plane_trusted_proxy_network_list:
                raise ValueError(
                    "trusted-proxy browser federation requires trusted proxy networks"
                )
            if not self.control_plane_trusted_proxy_shared_secret_file_list:
                raise ValueError(
                    "trusted-proxy browser federation requires a shared-secret file"
                )
            if not self.control_plane_trusted_proxy_display_name.strip():
                raise ValueError(
                    "trusted-proxy browser display name must not be empty"
                )
            if len(self.control_plane_trusted_proxy_display_name) > 128:
                raise ValueError(
                    "trusted-proxy browser display name must not exceed 128 characters"
                )
            parsed = urlsplit(self.control_plane_trusted_proxy_success_url or "")
            secure = parsed.scheme == "https"
            loopback = parsed.scheme == "http" and parsed.hostname in {
                "127.0.0.1",
                "::1",
                "localhost",
            }
            if (
                not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
                or parsed.query
                or parsed.path not in {"", "/"}
                or not (
                    secure
                    or (
                        loopback
                        and self.environment.strip().lower() != "production"
                    )
                )
            ):
                raise ValueError(
                    "trusted-proxy browser success URL must be a secure origin"
                )
        if not 1 <= self.control_plane_workload_oidc_timeout_seconds <= 30:
            raise ValueError(
                "control_plane_workload_oidc_timeout_seconds must be between 1 and 30"
            )
        if not 1 <= self.control_plane_workload_token_ttl_minutes <= 60:
            raise ValueError(
                "control_plane_workload_token_ttl_minutes must be between 1 and 60"
            )
        if any(
            "://" in host or "/" in host or not host
            for host in self.control_plane_workload_oidc_allowed_host_list
        ):
            raise ValueError(
                "workload OIDC allowed hosts must contain exact hostnames"
            )
        if self.control_plane_workload_oidc_enabled:
            issuer = urlsplit(self.control_plane_workload_oidc_issuer or "")
            if (
                issuer.scheme != "https"
                or not issuer.hostname
                or issuer.username
                or issuer.password
                or issuer.query
                or issuer.fragment
                or issuer.hostname.lower()
                not in self.control_plane_workload_oidc_allowed_host_list
            ):
                raise ValueError(
                    "workload OIDC issuer must be an allowlisted HTTPS URL "
                    "without a query"
                )
            audience = (self.control_plane_workload_oidc_audience or "").strip()
            if (
                not audience
                or audience != self.control_plane_workload_oidc_audience
                or len(audience) > 255
                or any(ord(character) < 0x20 for character in audience)
            ):
                raise ValueError(
                    "workload OIDC audience must contain 1 to 255 "
                    "printable characters"
                )
        if not 1 <= self.sandbox_timeout_seconds <= 30:
            raise ValueError("sandbox_timeout_seconds must be between 1 and 30")
        if not 1 <= self.server_secret_vault_timeout_seconds <= 30:
            raise ValueError(
                "server_secret_vault_timeout_seconds must be between 1 and 30"
            )
        if not 1 <= self.mcp_oauth_timeout_seconds <= 30:
            raise ValueError("mcp_oauth_timeout_seconds must be between 1 and 30")
        if not 5 <= self.mcp_oauth_transaction_ttl_minutes <= 30:
            raise ValueError(
                "mcp_oauth_transaction_ttl_minutes must be between 5 and 30"
            )
        if not 1 <= self.mcp_oauth_max_pending_transactions <= 1_000_000:
            raise ValueError(
                "mcp_oauth_max_pending_transactions must be between 1 and 1000000"
            )
        if (
            self.worker_mtls_mode != "disabled"
            and not self.worker_mtls_trusted_proxy_list
        ):
            raise ValueError(
                "worker mTLS requires ICHECK_WORKER_MTLS_TRUSTED_PROXIES"
            )
        for proxy in self.worker_mtls_trusted_proxy_list:
            try:
                ipaddress.ip_network(proxy, strict=False)
            except ValueError as exc:
                raise ValueError(
                    "worker mTLS trusted proxies must contain only IP/CIDR values"
                ) from exc
        if bool(self.server_secret_vault_address) != bool(
            self.server_secret_vault_token_file
        ):
            raise ValueError(
                "server-side Vault requires both "
                "ICHECK_SERVER_SECRET_VAULT_ADDRESS and "
                "ICHECK_SERVER_SECRET_VAULT_TOKEN_FILE"
            )
        if (
            self.server_secret_vault_token_file
            and not self.server_secret_vault_token_file.startswith("/")
        ):
            raise ValueError("server_secret_vault_token_file must be absolute")
        oauth_values = (
            self.mcp_oauth_redirect_uri,
            self.mcp_oauth_success_url,
            self.mcp_oauth_transaction_secret_file,
        )
        if any(oauth_values):
            if not all(oauth_values):
                raise ValueError(
                    "MCP OAuth requires redirect URI, success URL, and transaction secret"
                )
            if not self.mcp_oauth_allowed_host_list:
                raise ValueError("MCP OAuth requires an authorization host allowlist")
            if not self.server_secret_vault_address:
                raise ValueError("MCP OAuth requires server-side Vault configuration")
            if not (self.mcp_oauth_transaction_secret_file or "").startswith("/"):
                raise ValueError("MCP OAuth transaction secret file must be absolute")
            for value, label, origin_only in (
                (self.mcp_oauth_redirect_uri or "", "MCP OAuth redirect URI", False),
                (self.mcp_oauth_success_url or "", "MCP OAuth success URL", True),
            ):
                parsed = urlsplit(value)
                secure = parsed.scheme == "https"
                loopback = parsed.scheme == "http" and parsed.hostname in {
                    "127.0.0.1",
                    "::1",
                    "localhost",
                }
                if (
                    not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or parsed.fragment
                    or not (
                        secure
                        or (loopback and self.environment.strip().lower() != "production")
                    )
                    or (origin_only and (parsed.path not in {"", "/"} or parsed.query))
                ):
                    raise ValueError(f"{label} is invalid")
            if self.mcp_oauth_client_metadata_url:
                metadata_url = urlsplit(self.mcp_oauth_client_metadata_url)
                if (
                    metadata_url.scheme != "https"
                    or not metadata_url.hostname
                    or metadata_url.username
                    or metadata_url.password
                    or not metadata_url.path.strip("/")
                    or metadata_url.query
                    or metadata_url.fragment
                ):
                    raise ValueError("MCP OAuth client metadata URL is invalid")
        if not self.sandbox_bwrap_path.startswith("/"):
            raise ValueError("sandbox_bwrap_path must be absolute")
        if not self.sandbox_python_path.startswith("/"):
            raise ValueError("sandbox_python_path must be absolute")
        if (
            self.environment.strip().lower() == "production"
            and self.control_plane_auth_mode != "required"
        ):
            raise ValueError(
                "production requires ICHECK_CONTROL_PLANE_AUTH_MODE=required"
            )
        if (
            self.environment.strip().lower() == "production"
            and not self.control_plane_session_cookie_secure
        ):
            raise ValueError(
                "production requires secure control-plane session cookies"
            )
        if (
            self.environment.strip().lower() == "production"
            and not self.require_governed_change_contracts
        ):
            raise ValueError(
                "production requires ICHECK_REQUIRE_GOVERNED_CHANGE_CONTRACTS=true"
            )
        if self.environment.strip().lower() == "production" and self.auto_create_schema:
            raise ValueError(
                "production requires ICHECK_AUTO_CREATE_SCHEMA=false"
            )
        return self

    @property
    def effective_checkpoint_setup_mode(self) -> Literal["automatic", "verify"]:
        if self.checkpoint_setup_mode is not None:
            return self.checkpoint_setup_mode
        return (
            "verify"
            if self.environment.strip().lower() == "production"
            else "automatic"
        )

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
    def logs_allowed_host_list(self) -> list[str]:
        return [
            host.strip()
            for host in self.logs_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def ai_allowed_host_list(self) -> list[str]:
        return [
            host.strip()
            for host in self.ai_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def mcp_allowed_host_list(self) -> list[str]:
        return [
            host.strip()
            for host in self.mcp_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def mcp_oauth_allowed_host_list(self) -> list[str]:
        return [
            host.strip().lower()
            for host in self.mcp_oauth_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def mcp_oauth_configured(self) -> bool:
        return all(
            (
                self.mcp_oauth_redirect_uri,
                self.mcp_oauth_success_url,
                self.mcp_oauth_transaction_secret_file,
                self.mcp_oauth_allowed_host_list,
                self.server_secret_vault_address,
                self.server_secret_vault_token_file,
            )
        )

    @property
    def capability_catalog_allowed_host_list(self) -> list[str]:
        return [
            host.strip()
            for host in self.capability_catalog_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def ecosystem_transport_allowed_host_list(self) -> list[str]:
        return [
            host.strip()
            for host in self.ecosystem_transport_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def recovery_signing_allowed_host_list(self) -> list[str]:
        return [
            host.strip()
            for host in self.recovery_signing_allowed_hosts.split(",")
            if host.strip()
        ]

    @property
    def report_archive_allowed_host_list(self) -> list[str]:
        return [host.strip().lower() for host in self.report_archive_allowed_hosts.split(",") if host.strip()]

    @property
    def worker_mtls_trusted_proxy_list(self) -> list[str]:
        return [
            value.strip()
            for value in self.worker_mtls_trusted_proxies.split(",")
            if value.strip()
        ]

    @property
    def control_plane_oidc_allowed_host_list(self) -> list[str]:
        return [
            value.strip().lower()
            for value in self.control_plane_oidc_allowed_hosts.split(",")
            if value.strip()
        ]

    @property
    def control_plane_oidc_scope_list(self) -> list[str]:
        return list(
            dict.fromkeys(
                value.strip()
                for value in self.control_plane_oidc_scopes.split()
                if value.strip()
            )
        )

    @property
    def control_plane_trusted_proxy_network_list(self) -> list[str]:
        return [
            value.strip()
            for value in self.control_plane_trusted_proxy_networks.split(",")
            if value.strip()
        ]

    @property
    def control_plane_trusted_proxy_shared_secret_file_list(self) -> list[str]:
        return list(
            dict.fromkeys(
                value.strip()
                for value in self.control_plane_trusted_proxy_shared_secret_files.split(
                    ","
                )
                if value.strip()
            )
        )

    @property
    def control_plane_workload_oidc_allowed_host_list(self) -> list[str]:
        return [
            value.strip().lower()
            for value in self.control_plane_workload_oidc_allowed_hosts.split(",")
            if value.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
