import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from icheck import agent_worker, collector_worker
from icheck.config import Settings
from icheck.collectors.http_json import collect_http_json
from icheck.credentials import (
    CredentialContext,
    CredentialGrant,
    CredentialUnavailable,
    ProviderCredentialLease,
    ResolvedCredential,
    VaultDynamicCredentialProvider,
    VaultKV2CredentialProvider,
    WorkerCredentialBroker,
    build_server_credential_providers,
    resolved_server_secret,
    resolve_server_secret,
)


class FakeVaultResponse:
    def __init__(self, document):
        self.body = json.dumps(document).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, limit):
        return self.body[:limit]


class FakeVaultOpener:
    def __init__(self, document):
        self.document = document
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeVaultResponse(self.document)


class SequencedVaultOpener:
    def __init__(self, documents):
        self.documents = list(documents)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeVaultResponse(self.documents.pop(0))


class FakeJSONResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, _limit):
        return b'{"items":[{"id":"edge-01"}]}'


class RecordingHTTPOpener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeJSONResponse()


def test_vault_kv2_provider_uses_worker_local_token_file(tmp_path):
    token_file = tmp_path / "vault-token"
    token_file.write_text("worker-local-vault-token", encoding="utf-8")
    opener = FakeVaultOpener(
        {"data": {"data": {"username": "readonly", "password": "s3cr3t"}}}
    )
    provider = VaultKV2CredentialProvider(
        address="https://vault.example.test",
        token_file=str(token_file),
        namespace="operations",
        opener=opener,
    )

    values = provider.resolve("vault-kv2://kv/windows/readonly")

    assert values == {"username": "readonly", "password": "s3cr3t"}
    request, timeout = opener.requests[0]
    assert request.full_url == (
        "https://vault.example.test/v1/kv/data/windows/readonly"
    )
    assert request.get_header("X-vault-token") == "worker-local-vault-token"
    assert request.get_header("X-vault-namespace") == "operations"
    assert timeout == 5


def test_vault_dynamic_lease_renews_with_rotated_token_and_revokes(tmp_path):
    token_file = tmp_path / "vault-token"
    token_file.write_text("vault-token-v1", encoding="utf-8")
    opener = SequencedVaultOpener(
        [
            {
                "data": {"username": "dynamic-user", "password": "ephemeral"},
                "lease_id": "database/creds/readonly/lease-1",
                "lease_duration": 30,
                "renewable": True,
            },
            {"lease_duration": 600, "renewable": True},
            {},
        ]
    )
    provider = VaultDynamicCredentialProvider(
        address="https://vault.example.test",
        token_file=str(token_file),
        namespace="operations",
        opener=opener,
    )
    grant_expiry = datetime.now(UTC) + timedelta(seconds=120)
    broker = WorkerCredentialBroker({"vault_dynamic": provider})
    resolved = broker.resolve(
        CredentialGrant(
            profile_id="profile-dynamic",
            profile_name="database-readonly",
            provider="vault_dynamic",
            secret_ref="vault-dynamic://database/creds/readonly",
            adapter_type="postgresql_query",
            deployment_id="deployment-1",
            expires_at=grant_expiry,
            profile_revision=4,
        ),
        CredentialContext(
            worker_id="worker-1",
            deployment_id="deployment-1",
            adapter_type="postgresql_query",
        ),
    )
    assert resolved.renewable is True
    assert resolved.values == {
        "username": "dynamic-user",
        "password": "ephemeral",
    }
    assert resolved.expires_at < grant_expiry
    initial_request, _ = opener.requests[0]
    assert initial_request.full_url == (
        "https://vault.example.test/v1/database/creds/readonly"
    )
    assert initial_request.get_header("X-vault-token") == "vault-token-v1"

    token_file.write_text("vault-token-v2", encoding="utf-8")
    renewed_expiry = resolved.renew(300)
    assert renewed_expiry <= grant_expiry
    renew_request, _ = opener.requests[1]
    renew_payload = json.loads(renew_request.data)
    assert renew_request.full_url.endswith("/v1/sys/leases/renew")
    assert renew_request.get_method() == "PUT"
    assert renew_request.get_header("X-vault-token") == "vault-token-v2"
    assert renew_payload["lease_id"] == "database/creds/readonly/lease-1"
    assert 1 <= renew_payload["increment"] <= 120

    resolved.close()
    revoke_request, _ = opener.requests[2]
    assert revoke_request.full_url.endswith("/v1/sys/leases/revoke")
    assert json.loads(revoke_request.data) == {
        "lease_id": "database/creds/readonly/lease-1"
    }
    assert resolved.values == {}
    assert resolved.renewable is False


def test_server_secret_provider_resolves_one_vault_field(tmp_path):
    token_file = tmp_path / "vault-token"
    token_file.write_text("control-plane-vault-token", encoding="utf-8")
    opener = FakeVaultOpener(
        {"data": {"data": {"api_key": "provider-secret", "owner": "netops"}}}
    )
    settings = SimpleNamespace(
        server_secret_vault_address="https://vault.example.test",
        server_secret_vault_token_file=str(token_file),
        server_secret_vault_namespace="operations",
        server_secret_vault_timeout_seconds=7,
    )
    providers = build_server_credential_providers(
        settings=settings,
        vault_opener=opener,
    )
    assert "vault_dynamic" in providers
    profile = SimpleNamespace(
        enabled=True,
        allowed_adapters=["ai_provider"],
        worker_selector={},
        provider="vault_kv2",
        secret_ref="vault-kv2://kv/ai/primary#api_key",
    )

    secret = resolve_server_secret(
        profile,
        adapter_type="ai_provider",
        providers=providers,
    )

    assert secret == "provider-secret"
    request, timeout = opener.requests[0]
    assert request.full_url == "https://vault.example.test/v1/kv/data/ai/primary"
    assert request.get_header("X-vault-token") == "control-plane-vault-token"
    assert timeout == 7


def test_dynamic_server_secret_is_lease_scoped_and_always_revoked():
    revoked = []

    class DynamicProvider:
        def resolve(self, secret_ref):
            assert secret_ref == "vault-dynamic://ai/creds/runtime"
            return ProviderCredentialLease(
                values={"token": "ephemeral-ai-token"},
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                revoke_callback=lambda: revoked.append("lease-revoked"),
            )

    profile = SimpleNamespace(
        enabled=True,
        allowed_adapters=["ai_provider"],
        worker_selector={},
        provider="vault_dynamic",
        secret_ref="vault-dynamic://ai/creds/runtime",
    )
    with resolved_server_secret(
        profile,
        adapter_type="ai_provider",
        providers={"vault_dynamic": DynamicProvider()},
    ) as secret:
        assert secret == "ephemeral-ai-token"
        assert revoked == []
    assert revoked == ["lease-revoked"]

    with pytest.raises(CredentialUnavailable, match="lease-scoped"):
        resolve_server_secret(
            profile,
            adapter_type="ai_provider",
            providers={"vault_dynamic": DynamicProvider()},
        )
    assert revoked == ["lease-revoked", "lease-revoked"]


def test_server_secret_provider_fails_closed_for_scope_and_shape(tmp_path):
    token_file = tmp_path / "vault-token"
    token_file.write_text("control-plane-vault-token", encoding="utf-8")
    providers = build_server_credential_providers(
        settings=SimpleNamespace(
            server_secret_vault_address="https://vault.example.test",
            server_secret_vault_token_file=str(token_file),
            server_secret_vault_namespace=None,
            server_secret_vault_timeout_seconds=5,
        ),
        vault_opener=FakeVaultOpener(
            {"data": {"data": {"token": "secret", "other": "not-selected"}}}
        ),
    )
    profile = SimpleNamespace(
        enabled=True,
        allowed_adapters=["ai_provider"],
        worker_selector={},
        provider="vault",
        secret_ref="vault-kv2://kv/ai/primary",
    )
    with pytest.raises(CredentialUnavailable, match="exactly one value"):
        resolve_server_secret(
            profile,
            adapter_type="ai_provider",
            providers=providers,
        )

    profile.worker_selector = {"site": "HKG"}
    with pytest.raises(CredentialUnavailable, match="Worker-scoped"):
        resolve_server_secret(
            profile,
            adapter_type="ai_provider",
            providers=providers,
        )


def test_vault_provider_rejects_unsafe_control_plane_configuration(tmp_path):
    token_file = tmp_path / "vault-token"
    token_file.write_text("token", encoding="utf-8")
    with pytest.raises(ValueError, match="query or fragment"):
        VaultKV2CredentialProvider(
            address="https://vault.example.test?redirect=elsewhere",
            token_file=str(token_file),
        )
    with pytest.raises(ValueError, match="absolute"):
        VaultKV2CredentialProvider(
            address="https://vault.example.test",
            token_file="relative/vault-token",
        )


def test_server_vault_settings_require_complete_absolute_configuration():
    with pytest.raises(ValidationError, match="requires both"):
        Settings(
            _env_file=None,
            server_secret_vault_address="https://vault.example.test",
            server_secret_vault_token_file=None,
        )
    with pytest.raises(ValidationError, match="must be absolute"):
        Settings(
            _env_file=None,
            server_secret_vault_address="https://vault.example.test",
            server_secret_vault_token_file="relative/token",
        )
    with pytest.raises(ValidationError, match="between 1 and 30"):
        Settings(
            _env_file=None,
            server_secret_vault_address="https://vault.example.test",
            server_secret_vault_token_file="/etc/icheck/vault-token",
            server_secret_vault_timeout_seconds=31,
        )


def test_http_json_uses_runtime_bearer_credential(monkeypatch):
    opener = RecordingHTTPOpener()
    monkeypatch.setattr(
        "icheck.collectors.http_json.build_opener",
        lambda *_handlers: opener,
    )
    envelopes = collect_http_json(
        {
            "artifact_name": "credentialed-inventory",
            "output_kinds": ["observation"],
            "credential_profile_ref": "inventory-readonly",
            "target": {"url": "https://inventory.example.test/assets"},
            "defaults": {"records_path": "items"},
            "configuration": {},
            "_runtime": {
                "http_allowed_hosts": ["inventory.example.test"],
                "lease_seconds": 60,
                "credential": {"token": "short-lived-token"},
            },
        }
    )

    assert len(envelopes) == 1
    request, timeout = opener.requests[0]
    assert request.get_header("Authorization") == "Bearer short-lived-token"
    assert timeout == 10


def test_remote_control_plane_requires_https():
    with pytest.raises(ValueError, match="require HTTPS"):
        collector_worker.ControlPlaneClient("http://control.example.test:8000")
    assert collector_worker.ControlPlaneClient(
        "http://127.0.0.1:8000"
    ).base_url == "http://127.0.0.1:8000/"
    assert collector_worker.ControlPlaneClient(
        "http://control.example.test:8000",
        allow_insecure=True,
    ).base_url == "http://control.example.test:8000/"


def test_agent_registration_token_file_requires_private_absolute_file(tmp_path):
    token_file = tmp_path / "agent-registration-token"
    token_file.write_text("one-time-agent-bootstrap", encoding="utf-8")
    token_file.chmod(0o644)
    with pytest.raises(SystemExit, match="accessible by group or others"):
        agent_worker.load_agent_registration_token(str(token_file))
    token_file.chmod(0o600)
    assert agent_worker.load_agent_registration_token(str(token_file)) == (
        "one-time-agent-bootstrap"
    )
    with pytest.raises(SystemExit, match="absolute"):
        agent_worker.load_agent_registration_token("relative/token")


def test_control_plane_client_loads_mtls_files_with_strict_key_permissions(
    tmp_path,
    monkeypatch,
):
    ca_file = tmp_path / "ca.pem"
    cert_file = tmp_path / "worker.pem"
    key_file = tmp_path / "worker.key"
    password_file = tmp_path / "worker.password"
    for path, value in (
        (ca_file, "ca"),
        (cert_file, "cert"),
        (key_file, "key"),
        (password_file, "secret"),
    ):
        path.write_text(value, encoding="utf-8")
    key_file.chmod(0o600)
    password_file.chmod(0o600)

    class FakeContext:
        minimum_version = None

        def __init__(self):
            self.loaded = None

        def load_cert_chain(self, **kwargs):
            self.loaded = kwargs

    context = FakeContext()
    opener = object()
    monkeypatch.setattr(
        collector_worker.ssl,
        "create_default_context",
        lambda *, cafile: context if cafile == str(ca_file) else None,
    )
    monkeypatch.setattr(collector_worker, "build_opener", lambda *_: opener)

    client = collector_worker.ControlPlaneClient(
        "https://control.example.test",
        tls_ca_file=str(ca_file),
        tls_cert_file=str(cert_file),
        tls_key_file=str(key_file),
        tls_key_password_file=str(password_file),
    )

    assert client.opener is opener
    assert context.minimum_version == collector_worker.ssl.TLSVersion.TLSv1_2
    assert context.loaded == {
        "certfile": str(cert_file),
        "keyfile": str(key_file),
        "password": "secret",
    }


def test_control_plane_client_rejects_partial_or_exposed_mtls_key(tmp_path):
    with pytest.raises(ValueError, match="both a certificate and private key"):
        collector_worker.ControlPlaneClient(
            "https://control.example.test",
            tls_cert_file="worker.pem",
        )

    cert_file = tmp_path / "worker.pem"
    key_file = tmp_path / "worker.key"
    cert_file.write_text("not parsed before key permissions", encoding="utf-8")
    key_file.write_text("private", encoding="utf-8")
    key_file.chmod(0o640)
    with pytest.raises(ValueError, match="must not be accessible"):
        collector_worker.ControlPlaneClient(
            "https://control.example.test",
            tls_cert_file=str(cert_file),
            tls_key_file=str(key_file),
        )


class RecordingBroker:
    def __init__(self, secret):
        self.secret = secret
        self.resolved = None

    def resolve(self, grant, context):
        assert grant.adapter_type == context.adapter_type
        self.resolved = ResolvedCredential(
            values={"token": self.secret},
            expires_at=grant.expires_at,
        )
        return self.resolved


class RecordingControlPlane:
    def __init__(self, grant):
        self.grant = grant
        self.calls = []

    def request(self, method, path, payload=None, **_kwargs):
        self.calls.append((method, path, payload))
        if path.endswith("/credential-grant"):
            return self.grant
        return {"ok": True}


def _assignment():
    return {
        "run_id": "run-1",
        "lease_token": "l" * 32,
        "assignment_sha256": "a" * 64,
        "deployment_id": "deployment-1",
        "adapter_type": "test_credential_adapter",
        "credential_profile_ref": "profile-1",
    }


def _grant():
    return {
        "profile_id": "profile-1",
        "profile_name": "readonly",
        "provider": "test",
        "secret_ref": "test://readonly",
        "adapter_type": "test_credential_adapter",
        "deployment_id": "deployment-1",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
    }


def _run(client, assignment, broker):
    return collector_worker.run_assignment(
        client,
        "worker-1",
        assignment,
        http_allowed_hosts=[],
        exporter_allowed_hosts=[],
        snmp_allowed_targets=[],
        windows_exporter_allowed_hosts=[],
        windows_allowed_targets=[],
        credential_broker=broker,
    )


def test_worker_redacts_credentials_from_envelopes_and_clears_memory(monkeypatch):
    secret = "credential-value-that-must-not-leak"
    broker = RecordingBroker(secret)
    client = RecordingControlPlane(_grant())
    monkeypatch.setitem(
        collector_worker.ADAPTERS,
        "test_credential_adapter",
        lambda assignment: [
            {
                "kind": "observation",
                "type": "test.record",
                "source": "test",
                "observed_at": datetime.now(UTC).isoformat(),
                "payload": {
                    "echo": assignment["_runtime"]["credential"]["token"]
                },
            }
        ],
    )

    assert _run(client, _assignment(), broker) is True
    assert [call[1].rsplit("/", 1)[-1] for call in client.calls[:2]] == [
        "admit", "credential-grant",
    ]
    assert len([call for call in client.calls if call[1].endswith("/admit")]) == 2

    envelope_call = next(
        call for call in client.calls if call[1].endswith("/envelopes")
    )
    assert envelope_call[2]["envelopes"][0]["payload"]["echo"] == "[REDACTED]"
    assert secret not in json.dumps(client.calls)
    assert broker.resolved.values == {}


def test_worker_rechecks_admission_after_credential_resolution(monkeypatch):
    class RevokedControlPlane(RecordingControlPlane):
        def request(self, method, path, payload=None, **kwargs):
            if path.endswith("/admit") and any(
                call[1].endswith("/admit") for call in self.calls
            ):
                self.calls.append((method, path, payload))
                raise collector_worker.ControlPlaneHTTPError(409, "target ownership changed")
            return super().request(method, path, payload, **kwargs)

    invoked = []
    monkeypatch.setitem(
        collector_worker.ADAPTERS,
        "test_credential_adapter",
        lambda _assignment: invoked.append(True) or [],
    )
    broker = RecordingBroker("short-lived-secret")
    client = RevokedControlPlane(_grant())
    assert _run(client, _assignment(), broker) is False
    assert invoked == []
    assert len([call for call in client.calls if call[1].endswith("/admit")]) == 2
    assert broker.resolved.values == {}


def test_worker_proactively_renews_short_dynamic_credential_lease(monkeypatch):
    renewals = []
    revocations = []

    class RenewableBroker:
        def __init__(self):
            provider_lease = ProviderCredentialLease(
                values={"token": "ephemeral-token"},
                expires_at=datetime.now(UTC) + timedelta(seconds=1),
                renewable=True,
                renew_callback=lambda increment: (
                    renewals.append(increment)
                    or datetime.now(UTC) + timedelta(seconds=60)
                ),
                revoke_callback=lambda: revocations.append(True),
            )
            self.resolved = ResolvedCredential(
                values={"token": "ephemeral-token"},
                expires_at=provider_lease.expires_at,
                grant_expires_at=datetime.now(UTC) + timedelta(seconds=60),
                _provider_lease=provider_lease,
            )

        def resolve(self, _grant, _context):
            return self.resolved

    broker = RenewableBroker()
    client = RecordingControlPlane(_grant())
    monkeypatch.setitem(
        collector_worker.ADAPTERS,
        "test_credential_adapter",
        lambda _assignment: [],
    )

    assert _run(client, _assignment(), broker) is True
    assert renewals and 15 <= renewals[0] <= 300
    assert revocations == [True]
    assert broker.resolved.values == {}


def test_worker_redacts_credentials_from_failure_and_stderr(monkeypatch, capsys):
    secret = "credential-value-that-must-not-leak"
    broker = RecordingBroker(secret)
    client = RecordingControlPlane(_grant())

    def fail(_assignment):
        raise RuntimeError(f"remote echoed Bearer {secret}")

    monkeypatch.setitem(
        collector_worker.ADAPTERS,
        "test_credential_adapter",
        fail,
    )
    assert _run(client, _assignment(), broker) is False

    completion = next(
        call for call in client.calls if call[1].endswith("/complete")
    )
    assert completion[2]["error"] == "remote echoed [REDACTED]"
    assert secret not in capsys.readouterr().err
    assert secret not in json.dumps(client.calls)
    assert broker.resolved.values == {}


def test_worker_broker_rejects_expired_or_mismatched_grants():
    class StaticProvider:
        def resolve(self, _secret_ref):
            return {"token": "secret"}

    broker = WorkerCredentialBroker({"test": StaticProvider()})
    grant = CredentialGrant.from_mapping(_grant())
    context = CredentialContext(
        worker_id="worker-1",
        deployment_id="deployment-1",
        adapter_type="test_credential_adapter",
    )
    with broker.resolve(grant, context) as credential:
        assert credential.values == {"token": "secret"}
    assert credential.values == {}

    mismatched = CredentialContext(
        worker_id="worker-1",
        deployment_id="another-deployment",
        adapter_type="test_credential_adapter",
    )
    with pytest.raises(CredentialUnavailable, match="deployment mismatch"):
        broker.resolve(grant, mismatched)

    expired_payload = _grant()
    expired_payload["expires_at"] = (
        datetime.now(UTC) - timedelta(seconds=1)
    ).isoformat()
    with pytest.raises(CredentialUnavailable, match="expired"):
        broker.resolve(CredentialGrant.from_mapping(expired_payload), context)
