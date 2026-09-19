# Device collection activation

## Purpose

Device activation is the governed bridge between a verified onboarding intent
and a runnable collector deployment. Verification proves only the level stated
by its evidence. Activation determines which published collector artifact will
run, the rendered target and configuration, the worker scope, and the schedule.

The control plane never activates an arbitrary browser payload. It renders a
versioned policy, validates the resulting deployment against the published
collector contract, returns an immutable plan hash, and requires an operator to
approve that exact hash with a reason.

## Lifecycle

```text
activation policy draft
        ↓ validate collector schema and placeholders
validated
        ↓ publish; prior published version is deprecated
published
        ↓ render for a verified device connection
preview plan + warnings + SHA-256 plan hash
        ↓ operator approves exact hash and reason
active DeviceConnectionActivation + enabled CollectorDeployment
        ↓ operator deactivates with reason
deactivated activation + disabled deployment, history retained
```

Approval is idempotent. Repeating an approval for the same current plan does
not create another deployment. Re-activating an unchanged deactivated plan
re-enables its existing deployment. If the plan changed, a new preview and
approval are mandatory.

## API

Policy administration:

```text
POST /api/v1/assets/activation-policies
GET  /api/v1/assets/activation-policies
GET  /api/v1/assets/activation-policies/{policy_id}
POST /api/v1/assets/activation-policies/{policy_id}/validate
POST /api/v1/assets/activation-policies/{policy_id}/publish
```

Connection activation:

```text
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/preview
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/approve
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/deactivate
```

The Assets page exposes only published policies compatible with the
connection's protocol and adapter. It displays the rendered target, schedule,
worker selector, artifact version, warnings, and plan hash before approval.

## Template contract

Policies may use only these placeholders in target, configuration-default, and
worker-selector templates:

```text
${device_id}
${device_name}
${management_ip}
${port}
${protocol}
${site}
```

Unknown, malformed, or unavailable placeholders fail validation or preview.
Rendered targets and configuration are checked against the selected collector
artifact's JSON Schemas. A policy cannot cross protocol/adapter boundaries, use
an unpublished collector artifact, contain inline secret-shaped values, or
contradict a connection's worker scope.

The plan hash includes policy content, connection identity, latest verification
time, artifact version, rendered inputs, execution mode, schedule, credential
reference, and worker selector. A new verification result therefore invalidates
an older approval preview.

## Built-in policies

The seed command idempotently publishes three defaults:

| Policy | Protocol | Execution | Target |
|---|---|---|---|
| `builtin-snmp-site-local` | SNMP | scheduled, 300 s | site-local SNMP Exporter and device management IP |
| `builtin-windows-exporter` | windows_exporter | scheduled, 300 s | device `http://IP:port/metrics` endpoint |
| `builtin-psrp-cim-diagnostics` | WinRM HTTPS | on demand | TLS-only PSRP/CIM host and port |

HTTPS API and SSH connections intentionally have no universal built-in policy.
A validated collector artifact and an environment-specific published policy are
required because authentication, paths, command sets, and output contracts vary.
ICMP is currently a preflight capability, not a continuous collector artifact.

## State and safety boundary

When every enabled connection is verified and has an active deployment, the
device state is `monitoring_configured`. This means the intended collector
configuration exists; it does not prove that collection is healthy.

Runtime reconciliation is implemented in worker polling and run completion. A
fresh successful scheduled run promotes the connection to `healthy` and the
fully configured device to `active`. A later failure becomes `degraded`; three
missed schedule intervals (with a minimum five-minute freshness budget) become
`stale`. Missing, disabled, or fingerprint-mismatched deployment content becomes
`drifted`. Re-approving the unchanged preview restores the exact approved
deployment fields and requires fresh run health before returning to `active`.

Deactivation prevents new scheduled assignments by disabling the deployment
and clearing its next-run time. It does not terminate a run whose lease is
already in flight; the audit event records that condition. Complete run,
deployment, policy, approval, and deactivation history remains available.

## Verification

Automated coverage includes:

- policy protocol/adapter compatibility and secret rejection;
- placeholder and collector-schema validation;
- published-version replacement;
- verified-connection requirement and credential/worker scope reuse;
- deterministic preview and stale-hash rejection;
- atomic deployment creation, approval idempotency, deactivation, and reuse;
- device state aggregation and audit events;
- idempotent built-in policy seeding;
- clean Alembic migration through `e84b7a2d19c3` and 38 full backend tests.

Live firewall, switch, router, Linux, Windows, wireless-controller, remote-write,
and scale acceptance remains deferred until the user's test lab is ready.
