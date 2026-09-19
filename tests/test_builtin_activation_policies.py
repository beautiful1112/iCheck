from icheck.builtin_activation_policies import ensure_builtin_activation_policies
from icheck.builtin_artifacts import (
    ensure_psrp_cim_artifact,
    ensure_snmp_exporter_artifact,
    ensure_windows_exporter_artifact,
)
from icheck.database import SessionLocal


def _ensure_defaults():
    with SessionLocal() as db:
        return ensure_builtin_activation_policies(
            db,
            snmp_artifact=ensure_snmp_exporter_artifact(db),
            windows_exporter_artifact=ensure_windows_exporter_artifact(db),
            psrp_cim_artifact=ensure_psrp_cim_artifact(db),
        )


def test_builtin_activation_policies_are_published_and_idempotent(client):
    first = _ensure_defaults()
    second = _ensure_defaults()

    assert [policy.id for policy in second] == [policy.id for policy in first]
    assert {(policy.protocol, policy.execution_mode.value) for policy in first} == {
        ("snmp", "scheduled"),
        ("windows_exporter", "scheduled"),
        ("winrm_https", "on_demand"),
    }
    assert all(policy.status.value == "published" for policy in first)
    assert all(policy.content_hash for policy in first)

    response = client.get(
        "/api/v1/assets/activation-policies?policy_status=published"
    )
    assert response.status_code == 200, response.text
    policies = response.json()
    assert len(policies) == 3
    snmp = next(policy for policy in policies if policy["protocol"] == "snmp")
    assert snmp["target_template"] == {
        "exporter_url": "http://127.0.0.1:9116",
        "target": "${management_ip}",
    }
    assert snmp["worker_selector"] == {"site": "${site}"}
