from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select

from icheck.config import Settings, get_settings
from icheck.database import SessionLocal
from icheck.main import app
from icheck.models import AuditEvent


COLLECTOR_REGISTRATION = {
    "X-iCheck-Registration-Token": "test-registration-token"
}
AGENT_REGISTRATION = {
    "X-iCheck-Registration-Token": "test-agent-registration-token"
}


def _certificate(common_name: str, *, ca: bool = False):
    key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    certificate = builder.sign(key, algorithm=None)
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return certificate, pem


def _identity_headers(certificate: x509.Certificate) -> dict[str, str]:
    return {
        "X-iCheck-Client-Cert-Verified": "SUCCESS",
        "X-iCheck-Client-Cert-SHA256": certificate.fingerprint(
            hashes.SHA256()
        ).hex(),
        "X-iCheck-Client-Cert-Subject": certificate.subject.rfc4514_string(),
        "X-iCheck-Client-Cert-Serial": str(certificate.serial_number),
        "X-iCheck-Client-Cert-Not-After": (
            certificate.not_valid_after_utc.isoformat()
        ),
    }


@pytest.fixture
def required_mtls(monkeypatch):
    monkeypatch.setenv("ICHECK_WORKER_MTLS_MODE", "required")
    monkeypatch.setenv("ICHECK_WORKER_MTLS_TRUSTED_PROXIES", "127.0.0.1/32")
    get_settings.cache_clear()
    yield
    monkeypatch.setenv("ICHECK_WORKER_MTLS_MODE", "disabled")
    get_settings.cache_clear()


@pytest.fixture
def optional_mtls(monkeypatch):
    monkeypatch.setenv("ICHECK_WORKER_MTLS_MODE", "optional")
    monkeypatch.setenv("ICHECK_WORKER_MTLS_TRUSTED_PROXIES", "127.0.0.1/32")
    get_settings.cache_clear()
    yield
    monkeypatch.setenv("ICHECK_WORKER_MTLS_MODE", "disabled")
    get_settings.cache_clear()


def _collector_payload(name="mtls-collector"):
    return {
        "name": name,
        "site": "lab",
        "capabilities": ["snmp_exporter"],
        "labels": {"region": "lab"},
    }


def test_required_worker_mtls_binds_rotates_and_rejects_old_identity(
    required_mtls,
):
    first, _first_pem = _certificate("collector-01")
    second, second_pem = _certificate("collector-01-next")
    with TestClient(app, client=("127.0.0.1", 45000)) as client:
        registered = client.post(
            "/api/v1/collector-workers/register",
            headers={**COLLECTOR_REGISTRATION, **_identity_headers(first)},
            json=_collector_payload(),
        )
        assert registered.status_code == 200, registered.text
        registration = registered.json()
        worker = registration["worker"]
        token = registration["access_token"]
        first_fingerprint = first.fingerprint(hashes.SHA256()).hex()
        second_fingerprint = second.fingerprint(hashes.SHA256()).hex()
        assert worker["mtls_fingerprint_sha256"] == first_fingerprint
        assert worker["mtls_revision"] == 1

        missing_certificate = client.post(
            f"/api/v1/collector-workers/{worker['id']}/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json={"state": "online"},
        )
        assert missing_certificate.status_code == 401
        assert "client certificate is required" in missing_certificate.text

        wrong, _wrong_pem = _certificate("wrong-worker")
        wrong_certificate = client.post(
            f"/api/v1/collector-workers/{worker['id']}/heartbeat",
            headers={
                "Authorization": f"Bearer {token}",
                **_identity_headers(wrong),
            },
            json={"state": "online"},
        )
        assert wrong_certificate.status_code == 401
        assert "does not match" in wrong_certificate.text

        heartbeat = client.post(
            f"/api/v1/collector-workers/{worker['id']}/heartbeat",
            headers={
                "Authorization": f"Bearer {token}",
                **_identity_headers(first),
            },
            json={"state": "online"},
        )
        assert heartbeat.status_code == 200, heartbeat.text

        staged = client.post(
            f"/api/v1/collector-workers/{worker['id']}/mtls-rotation",
            json={
                "certificate_pem": second_pem,
                "expected_revision": 1,
                "reason": "Rotate the lab Worker certificate.",
            },
        )
        assert staged.status_code == 200, staged.text
        assert staged.json()["next_fingerprint_sha256"] == second_fingerprint
        assert staged.json()["revision"] == 2

        cutover = client.post(
            f"/api/v1/collector-workers/{worker['id']}/heartbeat",
            headers={
                "Authorization": f"Bearer {token}",
                **_identity_headers(second),
            },
            json={"state": "online"},
        )
        assert cutover.status_code == 200, cutover.text
        assert cutover.json()["mtls_fingerprint_sha256"] == second_fingerprint
        assert cutover.json()["mtls_next_fingerprint_sha256"] is None
        assert cutover.json()["mtls_revision"] == 3

        old_certificate = client.post(
            f"/api/v1/collector-workers/{worker['id']}/heartbeat",
            headers={
                "Authorization": f"Bearer {token}",
                **_identity_headers(first),
            },
            json={"state": "online"},
        )
        assert old_certificate.status_code == 401

        reused_across_pools = client.post(
            "/api/v1/agent/workers/register",
            headers={**AGENT_REGISTRATION, **_identity_headers(second)},
            json={"name": "mtls-agent", "capabilities": ["openai_compatible"]},
        )
        assert reused_across_pools.status_code == 422
        assert "already bound" in reused_across_pools.text

    db = SessionLocal()
    try:
        event_types = set(
            db.scalars(
                select(AuditEvent.event_type).where(
                    AuditEvent.entity_id == worker["id"]
                )
            ).all()
        )
        assert {
            "collector.worker.mtls_bound",
            "collector.worker.mtls_rotation_staged",
            "collector.worker.mtls_promoted",
        }.issubset(event_types)
    finally:
        db.close()


def test_optional_mode_allows_migration_then_prevents_bearer_downgrade(
    optional_mtls,
):
    certificate, _pem = _certificate("optional-collector")
    with TestClient(app, client=("127.0.0.1", 45001)) as client:
        unbound = client.post(
            "/api/v1/collector-workers/register",
            headers=COLLECTOR_REGISTRATION,
            json=_collector_payload("optional-collector"),
        )
        assert unbound.status_code == 200, unbound.text
        first = unbound.json()
        assert first["worker"]["mtls_fingerprint_sha256"] is None
        bearer_only = client.post(
            f"/api/v1/collector-workers/{first['worker']['id']}/heartbeat",
            headers={"Authorization": f"Bearer {first['access_token']}"},
            json={"state": "online"},
        )
        assert bearer_only.status_code == 200, bearer_only.text

        bound = client.post(
            "/api/v1/collector-workers/register",
            headers={**COLLECTOR_REGISTRATION, **_identity_headers(certificate)},
            json=_collector_payload("optional-collector"),
        )
        assert bound.status_code == 200, bound.text
        second = bound.json()
        assert second["worker"]["mtls_fingerprint_sha256"] is not None
        assert second["access_token"] != first["access_token"]

        downgraded = client.post(
            f"/api/v1/collector-workers/{second['worker']['id']}/heartbeat",
            headers={"Authorization": f"Bearer {second['access_token']}"},
            json={"state": "online"},
        )
        assert downgraded.status_code == 401
        assert "requires a verified client certificate" in downgraded.text
        protected = client.post(
            f"/api/v1/collector-workers/{second['worker']['id']}/heartbeat",
            headers={
                "Authorization": f"Bearer {second['access_token']}",
                **_identity_headers(certificate),
            },
            json={"state": "online"},
        )
        assert protected.status_code == 200, protected.text


def test_forwarded_certificate_headers_fail_closed_from_untrusted_proxy(
    client,
    required_mtls,
):
    certificate, _pem = _certificate("spoofed-worker")
    response = client.post(
        "/api/v1/collector-workers/register",
        headers={**COLLECTOR_REGISTRATION, **_identity_headers(certificate)},
        json=_collector_payload("spoofed-worker"),
    )
    assert response.status_code == 401
    assert "untrusted proxy" in response.text


def test_rotation_rejects_ca_certificate(required_mtls):
    active, _active_pem = _certificate("collector-active")
    _ca, ca_pem = _certificate("not-a-worker", ca=True)
    with TestClient(app, client=("127.0.0.1", 45002)) as client:
        registered = client.post(
            "/api/v1/collector-workers/register",
            headers={**COLLECTOR_REGISTRATION, **_identity_headers(active)},
            json=_collector_payload("ca-rejection"),
        ).json()
        response = client.post(
            f"/api/v1/collector-workers/{registered['worker']['id']}/mtls-rotation",
            json={
                "certificate_pem": ca_pem,
                "expected_revision": 1,
                "reason": "This must be rejected.",
            },
        )
        assert response.status_code == 409
        assert "must not be a CA" in response.text


def test_rotation_can_be_cancelled_and_identity_revocation_invalidates_token(
    required_mtls,
):
    active, _active_pem = _certificate("collector-lifecycle")
    _staged_cert, staged_pem = _certificate("collector-lifecycle-next")
    with TestClient(app, client=("127.0.0.1", 45003)) as client:
        registration = client.post(
            "/api/v1/collector-workers/register",
            headers={**COLLECTOR_REGISTRATION, **_identity_headers(active)},
            json=_collector_payload("mtls-lifecycle"),
        ).json()
        worker_id = registration["worker"]["id"]
        token = registration["access_token"]

        staged = client.post(
            f"/api/v1/collector-workers/{worker_id}/mtls-rotation",
            json={
                "certificate_pem": staged_pem,
                "expected_revision": 1,
                "reason": "Prepare a replacement certificate.",
            },
        )
        assert staged.status_code == 200, staged.text

        stale_cancel = client.post(
            f"/api/v1/collector-workers/{worker_id}/mtls-rotation/cancel",
            json={"expected_revision": 1, "reason": "Stale operator view."},
        )
        assert stale_cancel.status_code == 409
        assert "revision conflict" in stale_cancel.text

        cancelled = client.post(
            f"/api/v1/collector-workers/{worker_id}/mtls-rotation/cancel",
            json={"expected_revision": 2, "reason": "Replacement was withdrawn."},
        )
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["current_fingerprint_sha256"] is not None
        assert cancelled.json()["next_fingerprint_sha256"] is None
        assert cancelled.json()["revision"] == 3

        restaged = client.post(
            f"/api/v1/collector-workers/{worker_id}/mtls-rotation",
            json={
                "certificate_pem": staged_pem,
                "expected_revision": 3,
                "reason": "Replacement is approved again.",
            },
        )
        assert restaged.status_code == 200, restaged.text
        assert restaged.json()["revision"] == 4

        revoked = client.post(
            f"/api/v1/collector-workers/{worker_id}/mtls-revoke",
            json={"expected_revision": 4, "reason": "Private key compromise."},
        )
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["current_fingerprint_sha256"] is None
        assert revoked.json()["next_fingerprint_sha256"] is None
        assert revoked.json()["revision"] == 5

        rejected = client.post(
            f"/api/v1/collector-workers/{worker_id}/heartbeat",
            headers={
                "Authorization": f"Bearer {token}",
                **_identity_headers(active),
            },
            json={"state": "online"},
        )
        assert rejected.status_code == 401

    db = SessionLocal()
    try:
        event_types = set(
            db.scalars(
                select(AuditEvent.event_type).where(AuditEvent.entity_id == worker_id)
            ).all()
        )
        assert {
            "collector.worker.mtls_rotation_cancelled",
            "collector.worker.mtls_revoked",
        }.issubset(event_types)
    finally:
        db.close()


def test_required_agent_worker_mtls_binding_and_heartbeat(required_mtls):
    certificate, _pem = _certificate("agent-remote-01")
    headers = _identity_headers(certificate)
    with TestClient(app, client=("127.0.0.1", 45004)) as client:
        registered = client.post(
            "/api/v1/agent/workers/register",
            headers={**AGENT_REGISTRATION, **headers},
            json={
                "name": "agent-remote-01",
                "capabilities": ["openai_compatible", "mcp"],
            },
        )
        assert registered.status_code == 200, registered.text
        registration = registered.json()
        heartbeat = client.post(
            f"/api/v1/agent/workers/{registration['worker']['id']}/heartbeat",
            headers={
                "Authorization": f"Bearer {registration['access_token']}",
                **headers,
            },
            json={"state": "online"},
        )
        assert heartbeat.status_code == 200, heartbeat.text
        assert heartbeat.json()["mtls_revision"] == 1


def test_agent_certificate_promotion_survives_registry_refresh_and_is_atomic(required_mtls):
    active, _ = _certificate("agent-rotation-current")
    replacement, replacement_pem = _certificate("agent-rotation-next")
    with TestClient(app, client=("127.0.0.1", 45005)) as client:
        response = client.post("/api/v1/agent/workers/register",
            headers={**AGENT_REGISTRATION, **_identity_headers(active)},
            json={"name": "agent-rotation", "capabilities": ["openai_compatible"]})
        assert response.status_code == 200, response.text
        registration = response.json()
        worker_id = registration["worker"]["id"]
        path = f"/api/v1/agent/workers/{worker_id}"
        token = {"Authorization": "Bearer " + registration["access_token"]}
        response = client.post(path + "/mtls-rotation", json={
            "certificate_pem": replacement_pem, "expected_revision": 1,
            "reason": "Rotate the fixture Agent certificate."})
        assert response.status_code == 200, response.text

        # Authentication flushes the promotion; invalid business input must
        # nevertheless roll identity and its audit back with the request.
        rejected = client.post(path + "/heartbeat",
            headers={**token, **_identity_headers(replacement)},
            json={"state": "online", "capabilities": [" "]})
        assert rejected.status_code == 422, rejected.text
        with SessionLocal() as db:
            from icheck.models import AgentWorker
            worker = db.get(AgentWorker, worker_id)
            assert worker.mtls_fingerprint_sha256 == active.fingerprint(hashes.SHA256()).hex()
            assert worker.mtls_revision == 2
            assert list(db.scalars(select(AuditEvent).where(
                AuditEvent.entity_id == worker_id,
                AuditEvent.event_type == "agent.worker.mtls_promoted"))) == []

        accepted = client.post(path + "/heartbeat",
            headers={**token, **_identity_headers(replacement)}, json={"state": "online"})
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["mtls_fingerprint_sha256"] == replacement.fingerprint(hashes.SHA256()).hex()
        assert accepted.json()["mtls_next_fingerprint_sha256"] is None
        assert accepted.json()["mtls_revision"] == 3
        assert client.post(path + "/heartbeat", headers={**token, **_identity_headers(active)},
            json={"state": "online"}).status_code == 401
        with SessionLocal() as db:
            assert len(list(db.scalars(select(AuditEvent).where(
                AuditEvent.entity_id == worker_id,
                AuditEvent.event_type == "agent.worker.mtls_promoted")))) == 1


def test_worker_mtls_rejects_invalid_trusted_proxy_network():
    with pytest.raises(ValueError, match="only IP/CIDR"):
        Settings(
            worker_mtls_mode="required",
            worker_mtls_trusted_proxies="proxy.example.test",
        )
