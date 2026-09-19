# Device onboarding control-plane contract

## Purpose

The Assets page lets an operator add lab or production devices without editing
configuration files or asking a developer to modify iCheck. It records what the
operator wants monitored; it does not claim that an unverified target is live.

Open the page at:

```text
http://localhost:5173/assets/devices
```

The frontend uses `NEXT_PUBLIC_ICHECK_API_URL` and calls these APIs:

```text
POST /api/v1/assets/devices
GET  /api/v1/assets/devices
GET  /api/v1/assets/devices/{device_id}
GET  /api/v1/assets/devices/{device_id}/connections/{connection_id}/preflights
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/verification/retry
GET  /api/v1/assets/activation-policies?policy_status=published
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/preview
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/approve
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/deactivate
POST /api/v1/credential-profiles
GET  /api/v1/credential-profiles
```

## Operator flow

1. Create or select a credential profile. The browser stores only an external
   secret reference and never asks for an SNMP community, password, or token.
2. Enter device identity, management IP, type, site, vendor/model, and labels.
3. Select one or more monitoring methods and optionally bind a compatible,
   site-scoped credential profile to each method.
4. Submit the device. Device identity and all connection intents are committed
   together and an audit event is written.
5. iCheck reports the device as `pending_verification` and each connection as
   `pending` until a site worker performs protocol preflight.
6. For a verified connection, select a compatible published activation policy
   and preview the exact target, configuration, worker scope, schedule, and
   warnings.
7. Approve the unchanged preview hash with a reason. iCheck atomically creates
   or re-enables the collector deployment and records its policy and audit link.
8. Deactivation disables future assignment without deleting run or approval
   history. Re-activation requires a fresh preview and approval.

Supported intent mappings are:

| Operator choice | Adapter contract | Default port |
|---|---|---:|
| SNMP | `snmp_exporter` | 161 |
| HTTPS API | `http_json` | 443 |
| SSH | `ssh` | 22 |
| Windows exporter | `windows_exporter` | 9182 |
| WinRM HTTPS | `psrp_cim` | 5986 |
| ICMP | `icmp` | none |

The mapping is a platform default, not hard-coded device behavior. Future
collector artifacts may extend or replace adapters behind the same onboarding
contract.

## Validation and security

- Device names and management IPs are unique.
- Management addresses must be valid IPv4 or IPv6 values.
- A device cannot declare the same protocol twice.
- Ports are limited to 1–65535.
- Connection worker selectors default to the device site and cannot contradict
  it.
- Credential profiles must be enabled, allow the selected adapter, and match
  the connection worker scope.
- Configuration payloads are checked for inline secret-shaped keys and rejected
  if found.
- Audit metadata records the device and protocol choices, not secret references
  or resolved credentials.
- Worker claims require the registered worker bearer token, match site and
  adapter capabilities, and receive a separate expiring lease token.
- Preflight evidence is capped at 32 KiB, checked for secret-shaped fields, and
  never includes the worker or lease token.
- Device responses contain only the latest verification summary. Immutable
  history is queried separately with a maximum of 100 records per request.

The current `vault` and similar provider values are opaque references at this
control-plane layer. Actual secret retrieval remains fail-closed until the
external credential-provider adapter is connected. Activation validates and
stores only the credential reference; a worker must resolve it through that
future broker boundary.

## Worker preflight execution

The standalone `icheck-collector` process polls for both collector runs and
device preflights. It fails closed unless the target IP is explicitly listed by
`ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS` as an exact address or CIDR.

| Adapter | Preflight evidence | Meaning |
|---|---|---|
| `icmp` | One bounded ICMP echo | Network reachability only |
| `http_json` | TCP connect to configured port | Transport only; authentication not tested |
| `ssh` | TCP connect to configured port | Transport only; authentication not tested |
| `windows_exporter` | TCP connect to configured port | Transport only; metrics not yet scraped |
| `psrp_cim` | TCP connect to configured WinRM TLS port | Transport only; credentials not resolved |
| `snmp_exporter` | Bounded site-local exporter query | Protocol query using a configured exporter auth module |

Worker settings:

```text
ICHECK_COLLECTOR_MAX_PREFLIGHTS=4
ICHECK_COLLECTOR_PREFLIGHT_TIMEOUT_SECONDS=5
ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS=10.0.0.0/8,192.168.0.0/16
ICHECK_COLLECTOR_PREFLIGHT_SNMP_EXPORTER_URL=http://127.0.0.1:9116
```

SNMP targets must also pass `ICHECK_COLLECTOR_SNMP_ALLOWED_TARGETS`, and the
exporter host must pass `ICHECK_COLLECTOR_EXPORTER_ALLOWED_HOSTS`. An absent
SNMP Exporter URL fails the preflight; UDP route selection alone is never
treated as proof that SNMP works.

## State model

```text
operator submits device
        ↓
device: pending_verification
connections: pending
        ↓
site worker claims a bounded preflight job
        ↓
connection: verified | failed
        ↓
policy creates or updates collector deployment
        ↓
device: monitoring_configured
        ↓
fresh collector-run evidence and reconciliation
        ↓
device: active | degraded
```

Onboarding, worker preflight, evidence history, explicit retry, and readiness
aggregation through device `verified`, `partially_verified`, or
`verification_failed` are implemented. Policy-controlled deployment creation,
preview, approval, deactivation, and reactivation are also implemented. A
configured deployment yields `monitoring_configured`, not `active`; continuous
run-health reconciliation promotes it only after a fresh successful scheduled
run. Later failures, freshness expiry, or approved-deployment drift degrade the
device and retain an explainable connection-level reason. All protocol paths
still require acceptance against the firewall, switch, router, Linux, and
Windows lab when that environment is available. See
`docs/device-activation.md`.

## Example

```json
{
  "name": "lab-core-01",
  "kind": "switch",
  "management_ip": "192.0.2.10",
  "site": "LAB",
  "labels": {
    "environment": "lab",
    "role": "core"
  },
  "connections": [
    {
      "protocol": "snmp",
      "credential_profile_ref": "lab-network-readonly",
      "worker_selector": {
        "site": "LAB"
      },
      "configuration": {}
    },
    {
      "protocol": "icmp",
      "worker_selector": {
        "site": "LAB"
      },
      "configuration": {}
    }
  ],
  "created_by": "assets.operator"
}
```
