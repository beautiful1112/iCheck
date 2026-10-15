import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
import pytest


def module(name):
    path = Path(__file__).resolve().parents[1] / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


access = module("preview_native_access")
ingress = module("preview_native_ingress")
monitoring = module("preview_native_monitoring")


@pytest.mark.parametrize("timeout", [0, -1, 16, 600, True, "120"])
def test_native_setup_deadlines_refuse_unbounded_or_noncanonical_values(timeout):
    with pytest.raises(ValueError, match="15, 60 or 120"):
        access.bootstrap_admin("operator", timeout_seconds=timeout)
    with pytest.raises(ValueError, match="15, 60 or 120"):
        monitoring.API(timeout_seconds=timeout)


def test_environment_roundtrip_retains_protected_reference():
    values = {"ICHECK_DATABASE_URL": "postgresql+psycopg://runtime:opaque%21@127.0.0.1/icheck", "ICHECK_CONTROL_PLANE_AUTH_MODE": "required"}
    assert access.parse_environment(access.render_environment(values).decode()) == values


def test_native_python_isolation_flags_are_preserved():
    values = {"PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    assert access.parse_environment(access.render_environment(values).decode()) == values


@pytest.mark.parametrize("text", ["ICHECK_A=1\nICHECK_A=2", "UNREVIEWED=1", "ICHECK_A=\"quoted\"", "ICHECK_A=bad\x00value", "invalid", "PYTHONNOUSERSITE=0", "PYTHONPATH=/untrusted"])
def test_unsupported_environment_fails_closed(text):
    with pytest.raises(ValueError):
        access.parse_environment(text)


@pytest.mark.parametrize("defect", [None, "placeholder", "short", "shared", "write_enabled", "governance_disabled"])
def test_api_setup_checks_authority_and_read_only_defaults_before_persisting(tmp_path, monkeypatch, defect):
    values = {"ICHECK_ENVIRONMENT": "production", "ICHECK_CONTROL_PLANE_AUTH_MODE": "required",
        "ICHECK_CONTROL_PLANE_SESSION_COOKIE_SECURE": "true", "ICHECK_WORKER_MTLS_MODE": "required",
        "ICHECK_AUTO_CREATE_SCHEMA": "false", "ICHECK_CHECKPOINT_SETUP_MODE": "verify",
        "ICHECK_REQUIRE_GOVERNED_CHANGE_CONTRACTS": "true"}
    if defect == "placeholder": values["ICHECK_COLLECTOR_REGISTRATION_TOKEN"] = "replace-with-a-long-random-bootstrap-token"
    if defect == "short": values["ICHECK_AGENT_REGISTRATION_TOKEN"] = "short"
    if defect == "shared":
        for key in ("ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN", "ICHECK_COLLECTOR_REGISTRATION_TOKEN", "ICHECK_AGENT_REGISTRATION_TOKEN"):
            values[key] = "f" * 64
    if defect == "write_enabled": values["ICHECK_ENABLE_REVIEWED_CHANGE_EXECUTION"] = "true"
    if defect == "governance_disabled": values["ICHECK_REQUIRE_GOVERNED_CHANGE_CONTRACTS"] = "false"
    env = tmp_path / "control-plane.env"
    original = access.render_environment(values)
    env.write_bytes(original)
    env.chmod(0o600)
    monkeypatch.setattr(access, "ENV", env)
    monkeypatch.setattr(access, "ACCESS", tmp_path / "unclaimed")
    monkeypatch.setattr(access, "trusted", lambda path: None)
    if defect:
        with pytest.raises(ValueError): access.prepare_api(["10.23.45.67"])
        assert env.read_bytes() == original
    else:
        metadata = access.prepare_api(["10.23.45.67"])
        prepared = access.parse_environment(env.read_text())
        assert prepared["ICHECK_CONTROL_PLANE_PASSWORD_LOGIN_ENABLED"] == "true"
        assert prepared["ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED"] == "false"
        tokens = {prepared[key] for key in ("ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN", "ICHECK_COLLECTOR_REGISTRATION_TOKEN", "ICHECK_AGENT_REGISTRATION_TOKEN")}
        assert len(tokens) == 3 and all(len(token) >= 32 for token in tokens)
        assert prepared["ICHECK_CORS_ORIGINS"] == access.public_origins(["10.23.45.67"])
        assert all(token not in json.dumps(metadata) for token in tokens)


def test_client_identity_maps_are_issuer_derived_sha256_not_sha1():
    key, ca = ingress.issue("fixture evaluation CA")
    _, client = ingress.issue("fixture collector", issuer_cert=ca, issuer_key=key)
    assert client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    config = ingress.configuration([client]).decode()
    # A root-run nginx -t must keep disk buffers writable by the native service.
    assert config.startswith("user www-data www-data;\n")
    assert client.fingerprint(hashes.SHA256()).hex() in config
    assert str(client.serial_number) in config
    assert client.not_valid_after_utc.isoformat() in config
    assert "$ssl_client_fingerprint" not in config
    assert "ssl_verify_client on;" in config
    assert 'default "";' in config
    assert 'if ($icheck_cert_sha256 = "") { return 403; }' in config
    public, worker = config.split("listen 127.0.0.1:8444 ssl;")
    for header in ("Verified", "SHA256", "Subject", "Serial", "Not-After"):
        assert f'proxy_set_header X-iCheck-Client-Cert-{header} "";' in public
        assert f"proxy_set_header X-iCheck-Client-Cert-{header} $" in worker
    for header in ("Verified", "Subject", "Secret"):
        assert f'proxy_set_header X-Icheck-Trusted-Proxy-{header} "";' in public
        assert f'proxy_set_header X-Icheck-Trusted-Proxy-{header} "";' in worker
    assert "location = /api/v1/auth/bootstrap { return 404; }" in config
    assert "access_log off;" in config
    for adapter in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        assert f"{adapter}_temp_path /var/lib/icheck-preview-ingress/" in config


def test_server_certificate_is_bounded_and_matches_only_preview_hosts():
    key, ca = ingress.issue("fixture evaluation CA")
    _, server = ingress.issue("fixture HTTPS", issuer_cert=ca, issuer_key=key, server=True)
    names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(str(item) for item in names.get_values_for_type(x509.IPAddress)) == set(ingress.HOSTS)
    assert names.get_values_for_type(x509.DNSName) == ["localhost"]
    assert (server.not_valid_after_utc - server.not_valid_before_utc).days == 90
    assert server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])


def test_custom_server_address_matches_certificate_listener_host_policy_and_cors():
    hosts = ingress.listen_hosts(["10.23.45.67", "10.23.45.67"])
    key, ca = ingress.issue("fixture evaluation CA")
    _, server = ingress.issue("fixture HTTPS", issuer_cert=ca, issuer_key=key, server=True, hosts=hosts)
    names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(str(item) for item in names.get_values_for_type(x509.IPAddress)) == {"127.0.0.1", "10.23.45.67"}
    config = ingress.configuration([], hosts=hosts).decode()
    assert "listen 10.23.45.67:8443 ssl;" in config and "10.23.45.67 1;" in config
    assert "198.18.0.100" not in config and "198.18.1.101" not in config
    assert access.public_origins(["10.23.45.67", "10.23.45.67"]).split(",") == [
        "https://127.0.0.1:8443", "https://localhost:8443", "https://10.23.45.67:8443"]


def test_portable_default_never_exposes_developer_lan_addresses():
    config = ingress.configuration([]).decode()
    public, worker = config.split("listen 127.0.0.1:8444 ssl;")
    assert public.count(":8443 ssl;") == 1
    assert "listen 127.0.0.1:8443 ssl;" in public
    assert "192.168." not in config
    assert "192.168." not in access.public_origins([])


@pytest.mark.parametrize("address", ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "example.test", "10.0.0.1/24", "10.0.0.1; include /tmp/x;"])
def test_unsafe_https_addresses_are_rejected_before_rendering(address):
    with pytest.raises(ValueError):
        ingress.listen_hosts([address])
    with pytest.raises(ValueError):
        access.public_origins([address])


def test_configuration_refresh_preserves_existing_certificate_scope(tmp_path, monkeypatch):
    hosts = ingress.listen_hosts(["10.23.45.67"])
    key, ca = ingress.issue("fixture evaluation CA")
    _, server = ingress.issue("fixture HTTPS", issuer_cert=ca, issuer_key=key, server=True, hosts=hosts)
    from cryptography.hazmat.primitives.serialization import Encoding
    certificate = tmp_path / "server.pem"
    certificate.write_bytes(server.public_bytes(Encoding.PEM))
    monkeypatch.setattr(ingress, "trusted", lambda path: None)
    assert ingress.existing_server_hosts(certificate, None) == hosts
    assert ingress.existing_server_hosts(certificate, []) == ("127.0.0.1",)
    with pytest.raises(ValueError, match="outside the existing server certificate"):
        ingress.existing_server_hosts(certificate, ["10.23.45.68"])


@pytest.mark.parametrize("timeout", [15, 60, 120])
def test_bootstrap_copies_public_ca_and_removes_secret_only_after_private_token_custody(tmp_path, monkeypatch, timeout):
    expected_timeout = timeout
    env = tmp_path / "control-plane.env"
    env.write_text("ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN=fixture-onetime\n")
    env.chmod(0o600)
    ca = tmp_path / "preview-ca.pem"
    ca.write_bytes(b"fixture public certificate\n")
    destination = tmp_path / "access"
    monkeypatch.setattr(access, "ENV", env)
    monkeypatch.setattr(access, "PUBLIC_CA", ca)
    monkeypatch.setattr(access, "ACCESS", destination)
    monkeypatch.setattr(access, "trusted", lambda path: None)
    monkeypatch.setattr(access.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=max(1, os.getuid()), pw_gid=os.getgid()))
    monkeypatch.setattr(access.os, "chown", lambda *args: None)
    result = {"token": {"access_token": "icp_" + "f" * 32, "token": {"expires_at": "2026-11-09T00:00:00Z"}}}
    class Response:
        status = 201
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, maximum): return json.dumps(result).encode()
    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "http://127.0.0.1:8000/api/v1/auth/bootstrap"
            assert timeout == expected_timeout
            return Response()
    monkeypatch.setattr(access, "build_opener", lambda *args: Opener())
    metadata = access.bootstrap_admin("operator", timeout_seconds=timeout)
    assert (destination / "preview-ca.pem").read_bytes() == ca.read_bytes()
    assert (destination / "preview-ca.pem").stat().st_mode & 0o777 == 0o644
    token_file = destination / "admin-access-token"
    assert token_file.read_text().strip() == result["token"]["access_token"]
    assert token_file.stat().st_mode & 0o777 == 0o600
    assert "ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN" not in env.read_text()
    assert metadata["public_ca_file"] == str(destination / "preview-ca.pem")
    assert result["token"]["access_token"] not in json.dumps(metadata)


def test_native_ingress_remains_unprivileged_and_database_free():
    unit = (Path(__file__).resolve().parents[1] / "preview/nginx.service").read_text()
    assert "User=www-data" in unit and "CapabilityBoundingSet=\n" in unit
    assert "EnvironmentFile" not in unit and "DATABASE" not in unit
    assert "-t -c /etc/icheck-preview-ingress/nginx.conf" in unit


def test_ingress_is_a_native_external_service_not_an_unknown_backend_worker():
    directory = Path(__file__).resolve().parents[1] / "preview"
    assert sorted(path.name for path in directory.glob("*.service")) == ["nginx.service"]
    assert not (directory.parent / "systemd/nginx.service").exists()


def test_workers_are_fixed_namespace_mtls_and_database_free():
    environments = access.worker_environments(["198.18.0.0/24"])
    for values in environments.values():
        assert "ICHECK_DATABASE_URL" not in values
        assert values["ICHECK_CONTROL_PLANE_URL"] == "https://127.0.0.1:8444"
        assert values["ICHECK_WORKER_TLS_KEY_FILE"].endswith("/client.key")
        assert values["ICHECK_CREDENTIAL_ALLOW_ENVIRONMENT"] == "false"
        assert access.parse_environment(access.render_environment(values).decode()) == values
    assert environments["collector"]["ICHECK_COLLECTOR_SITE"] == "LAB"
    assert environments["collector"]["ICHECK_COLLECTOR_SNMP_ALLOWED_TARGETS"] == "198.18.0.0/24"


@pytest.mark.parametrize("cidrs", [[], ["0.0.0.0/0"], ["8.8.8.0/24"], ["198.18.0.3/24"], ["::/0"]])
def test_worker_network_authority_is_finite_and_fails_closed(cidrs):
    with pytest.raises(ValueError):
        access.worker_environments(cidrs)


def test_monitoring_profile_is_namespace_pinned_loopback_and_tls_default():
    config = monitoring.gateway_configuration(["198.18.0.0/24"])
    assert config["tenant_id"] == monitoring.TENANT and config["region_id"] == monitoring.REGION
    assert config["api_base_url"] == "https://127.0.0.1:8443"
    assert config["api_token_file"] != config["prometheus_token_file"]
    assert config["listen_address"] == "127.0.0.1"
    assert "database_url" not in config
    for profile in config["profiles"].values():
        assert profile["sites"] == ["LAB"]
        assert profile["allowed_targets"] == ["198.18.0.0/24"]
        assert profile["credential_profile_ids"] == [None]
    assert config["profiles"]["preview-windows"]["windows_scheme"] == "https"
    assert not config["profiles"]["preview-windows"].get("allow_insecure_windows_http")


def test_discovery_and_scrapes_share_only_the_protected_caller_token():
    job = monitoring.discovery_job()
    assert job["honor_labels"] is False
    assert job["http_sd_configs"][0]["url"] == "http://127.0.0.1:9120/discovery"
    assert job["authorization"] == job["http_sd_configs"][0]["authorization"]
    assert job["authorization"]["credentials_file"].endswith("/prometheus/gateway-token")
    assert "credentials" not in job["authorization"]
