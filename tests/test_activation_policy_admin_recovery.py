"""Global-administrator recovery of orphaned AI activation requests."""

from datetime import timedelta
from uuid import uuid4

from icheck.config import get_settings
from icheck.database import SessionLocal
from icheck.models import ActivationPolicyProposal, utcnow

from test_activation_policy_proposals import _published_http_artifact


def _insert_request(
    version_id: str, *, actor: str, age_hours: int,
    tenant_id: str | None = None, region_id: str | None = None,
) -> str:
    with SessionLocal() as db:
        row = ActivationPolicyProposal(
            artifact_version_id=version_id,
            protocol="https_api",
            actor=actor,
            request_key=str(uuid4()),
            request_sha256="a" * 64,
            brief="Draft read-only wireless controller inventory.",
            status="generating",
            result_snapshot={},
            tokens_used=0,
            created_at=utcnow() - timedelta(hours=age_hours),
            **({"tenant_id": tenant_id, "region_id": region_id} if tenant_id else {}),
        )
        db.add(row)
        db.commit()
        return row.id


def test_admin_recovery_requires_global_authority_and_audits_orphan_closure(
    client, monkeypatch,
):
    version_id = _published_http_artifact(client)
    stale_id = _insert_request(version_id, actor="former.operator@example.test", age_hours=3)
    fresh_id = _insert_request(version_id, actor="current.operator@example.test", age_hours=0)
    foreign_id = _insert_request(
        version_id, actor="foreign.operator@example.test", age_hours=3,
        tenant_id="other-tenant", region_id="other-region",
    )
    base = "/api/v1/assets/activation-policy-proposals"
    monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "required")
    get_settings.cache_clear()
    try:
        boot = client.post(
            "/api/v1/auth/bootstrap",
            headers={"X-Icheck-Bootstrap-Token": "test-control-plane-bootstrap-token"},
            json={"subject": "admin@example.test", "display_name": "Admin"},
        )
        assert boot.status_code == 201, boot.text
        admin = {"Authorization": f"Bearer {boot.json()['token']['access_token']}"}
        operator_role = next(
            role for role in client.get("/api/v1/auth/roles", headers=admin).json()
            if role["name"] == "operator"
        )
        principal = client.post(
            "/api/v1/auth/principals", headers=admin,
            json={"subject": "operator@example.test", "display_name": "Operator"},
        )
        assert principal.status_code == 201, principal.text
        principal_id = principal.json()["id"]
        binding = client.post(
            f"/api/v1/auth/principals/{principal_id}/bindings", headers=admin,
            json={"role_id": operator_role["id"], "scope": {"sites": ["LAB"]}},
        )
        assert binding.status_code == 201, binding.text
        token = client.post(
            f"/api/v1/auth/principals/{principal_id}/tokens", headers=admin,
            json={"name": "recovery-scope-test", "expires_in_hours": 24},
        )
        assert token.status_code == 201, token.text
        operator = {"Authorization": f"Bearer {token.json()['access_token']}"}

        denied = client.get(f"{base}/admin/recovery", headers=operator)
        assert denied.status_code == 403
        action = {
            "expected_request_sha256": "a" * 64,
            "reason": "Original operator access was revoked after incident review.",
        }
        assert client.post(
            f"{base}/{stale_id}/admin-interrupt", headers=operator, json=action,
        ).status_code == 403
        assert client.post(
            f"{base}/{foreign_id}/admin-interrupt", headers=admin, json=action,
        ).status_code == 404
        assert client.post(
            f"{base}/{stale_id}/interrupt", headers=admin,
            json={"reason": action["reason"], "actor": "former.operator@example.test"},
        ).status_code == 404

        listed = client.get(f"{base}/admin/recovery", headers=admin)
        assert listed.status_code == 200, listed.text
        assert {row["id"] for row in listed.json()} == {stale_id, fresh_id}
        assert listed.json()[0]["request_sha256"] == "a" * 64
        filtered = client.get(
            f"{base}/admin/recovery", headers=admin,
            params={"actor": "former.operator@example.test"},
        )
        assert [row["id"] for row in filtered.json()] == [stale_id]
        assert client.post(
            f"{base}/{fresh_id}/admin-interrupt", headers=admin, json=action,
        ).status_code == 409
        assert client.post(
            f"{base}/{stale_id}/admin-interrupt", headers=admin,
            json={**action, "expected_request_sha256": "b" * 64},
        ).status_code == 409
        assert client.post(
            f"{base}/{stale_id}/admin-interrupt", headers=admin,
            json={**action, "reason": "    "},
        ).status_code == 422

        closed = client.post(
            f"{base}/{stale_id}/admin-interrupt", headers=admin, json=action,
        )
        assert closed.status_code == 200, closed.text
        assert closed.json()["status"] == "failed"
        assert closed.json()["failure_code"] == "Interrupted"
        assert closed.json()["result"] is None
        assert closed.json()["request_sha256"] == "a" * 64
        assert client.post(
            f"{base}/{stale_id}/admin-interrupt", headers=admin, json=action,
        ).status_code == 200
        after = client.get(f"{base}/admin/recovery", headers=admin)
        assert [row["id"] for row in after.json()] == [fresh_id]
        audits = client.get(
            "/api/v1/audit-events", headers=admin,
            params={"event_type": "device.activation_policy.proposal_admin_interrupted"},
        )
        assert audits.status_code == 200, audits.text
        assert len(audits.json()) == 1
        event = audits.json()[0]
        assert event["actor_id"] == "admin@example.test"
        assert event["details"]["owner_actor"] == "former.operator@example.test"
        assert event["details"]["administrative"] is True
        assert event["details"]["external_charge_unknown"] is True
        assert event["details"]["reason"] == action["reason"]
    finally:
        monkeypatch.setenv("ICHECK_CONTROL_PLANE_AUTH_MODE", "disabled")
        get_settings.cache_clear()
