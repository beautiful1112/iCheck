# Collector contracts

## ARP or MAC-table observations

Create the collector device first through `POST /api/v1/devices`, then submit a
batch:

```json
{
  "observations": [
    {
      "mac_address": "00-1B-44-11-3A-B7",
      "ip_address": "10.20.17.21",
      "source": "arp",
      "collector_device_id": "DEVICE_UUID",
      "interface_name": "Vlan120",
      "vlan_id": 120,
      "hostname": "ops-laptop-17",
      "username": "alex.chen",
      "vendor": "Lenovo",
      "observed_at": "2026-09-15T14:00:00Z",
      "raw_data": {
        "age_seconds": 42
      }
    }
  ]
}
```

Supported sources are `arp`, `mac_table`, `dhcp`, `wifi_controller`, and
`manual`. MAC values are normalized to lower-case colon notation; IPv4 and IPv6
addresses are normalized by the API.

## Wi-Fi controller terminal snapshot

Create a device with `kind: "wireless_controller"`, then submit:

```json
{
  "controller_id": "CONTROLLER_UUID",
  "observed_at": "2026-09-15T14:00:00Z",
  "complete_snapshot": true,
  "clients": [
    {
      "mac_address": "A4:83:E7:10:2F:91",
      "ip_address": "10.20.31.54",
      "hostname": "mira-iphone",
      "username": "mira.patel",
      "vendor": "Apple",
      "access_point": "AP-HK-17F-03",
      "ssid": "CORP",
      "bssid": "10:20:30:40:50:60",
      "radio": "slot-1",
      "band": "5 GHz",
      "channel": 44,
      "vlan_id": 131,
      "rssi": -82,
      "snr": 13,
      "connected_at": "2026-09-15T13:42:00Z",
      "observed_at": "2026-09-15T14:00:00Z",
      "raw_data": {
        "controller_policy": "corp-default"
      }
    }
  ]
}
```

Use `complete_snapshot: false` for event streams or partial polling. Only a
complete snapshot closes sessions for clients that disappeared.

## External alert event

```json
{
  "event_type": "device.unreachable",
  "entity_type": "device",
  "entity_id": "DEVICE_UUID",
  "title": "Router is unreachable",
  "description": "Three consecutive probes failed.",
  "severity": "critical",
  "details": {
    "failed_probes": 3
  },
  "dedup_key": "icmp:DEVICE_UUID"
}
```

Reusing the deduplication key increments the existing active alert rather than
creating alert storms.

## Versioned collector artifact

Collectors are not hard-coded protocol modules. Each collector is an Artifact
with immutable versions. A version carries its semantic definition,
implementation reference, tests, runtime adapter, supported output kinds,
schemas, defaults, and optional credential-profile reference.

Create a draft:

```json
{
  "name": "internal-inventory-api",
  "kind": "collector",
  "description": "Collect assets from the internal inventory API.",
  "owner": "platform-team",
  "labels": {
    "domain": "inventory"
  },
  "initial_version": {
    "definition": {
      "purpose": "Collect inventory assets"
    },
    "implementation": {
      "runtime": "builtin",
      "adapter": "http_json"
    },
    "tests": [],
    "created_by": "capability.author",
    "collector_definition": {
      "adapter_type": "http_json",
      "mode": "poll",
      "output_kinds": ["observation"],
      "credential_profile_ref": null,
      "target_schema": {
        "type": "object",
        "required": ["url"]
      },
      "config_schema": {
        "type": "object"
      },
      "defaults": {
        "records_path": "items",
        "envelope_kind": "observation",
        "record_type": "inventory.asset",
        "subject_field": "id",
        "idempotency_field": "id"
      }
    }
  }
}
```

```text
POST /api/v1/artifacts
POST /api/v1/artifact-versions/{version_id}/validate
POST /api/v1/artifact-versions/{version_id}/publish
```

A version must be validated before publication. Validation computes a canonical
content hash, checks the target and configuration JSON Schemas, and rejects
inline secret values. Only local JSON Schema references are accepted; remote
references, excessive nesting, and oversized schemas fail closed. Publishing a
new version deprecates the previously published version; it does not mutate it.

## Credential profiles

The control plane stores only an opaque external secret reference:

```json
{
  "name": "inventory-readonly",
  "provider": "vault",
  "secret_ref": "kv/network/inventory-readonly",
  "allowed_adapters": ["http_json"],
  "worker_selector": {
    "site": "HKG"
  },
  "enabled": true,
  "created_by": "security.operator"
}
```

```text
POST /api/v1/credential-profiles
GET  /api/v1/credential-profiles
```

The profile never contains a password, token, SNMP community, or private key.
Deployments must use an allowed adapter and a worker selector at least as
restrictive as the credential profile. Assignments contain the profile
reference, not its external `secret_ref` or resolved secret. The worker-side
broker is fail-closed until an approved provider adapter is configured.

Credential profiles can be defaults on an Artifact version or, preferably for
reusable built-in packs, bound per deployment. A deployment reference overrides
the Artifact default and is checked against adapter and worker scope before the
deployment is accepted.

## Collector deployment

Only a published collector version can be deployed:

```json
{
  "name": "inventory-hkg",
  "artifact_version_id": "ARTIFACT_VERSION_UUID",
  "target": {
    "url": "https://inventory.example.internal/assets"
  },
  "configuration": {},
  "worker_selector": {
    "site": "HKG"
  },
  "execution_mode": "scheduled",
  "credential_profile_ref": null,
  "schedule_seconds": 300,
  "enabled": true,
  "created_by": "platform.operator"
}
```

```text
POST /api/v1/collector-deployments
GET  /api/v1/collector-deployments
```

`worker_selector` is matched against worker labels and the worker's site. Target
and configuration objects are checked against the published version's JSON
Schemas. They may contain secret references but must not contain passwords,
tokens, communities, private keys, or Authorization values.

`execution_mode: scheduled` retains interval scheduling. An `on_demand`
deployment has no `next_run_at` until explicitly triggered:

```text
POST /api/v1/collector-deployments/{deployment_id}/trigger
```

The trigger requires an actor and reason, both recorded in audit. A completed
on-demand run returns to `next_run_at: null`; it never silently becomes a
periodic diagnostic.

## Worker registration and lease protocol

```text
POST /api/v1/collector-workers/register
POST /api/v1/collector-workers/{worker_id}/heartbeat
POST /api/v1/collector-workers/{worker_id}/leases/claim
POST /api/v1/collector-runs/{run_id}/lease
POST /api/v1/collector-runs/{run_id}/envelopes
POST /api/v1/collector-runs/{run_id}/complete
GET  /api/v1/collector-runs
GET  /api/v1/collectors/health
```

Registration requires `X-iCheck-Registration-Token`. The successful response
contains worker metadata and a newly issued `access_token`. Re-registering the
same worker rotates that token and immediately invalidates the previous token.
Configure the bootstrap secret through
`ICHECK_COLLECTOR_REGISTRATION_TOKEN` on the control plane; workers should read
it from `ICHECK_COLLECTOR_REGISTRATION_TOKEN_FILE`.

Heartbeats, claims, lease renewal, envelope ingestion, and completion require
`Authorization: Bearer WORKER_ACCESS_TOKEN`. A claim atomically assigns an
eligible due deployment and returns a separate random run lease token. Only
SHA-256 hashes of worker and lease tokens are stored. Run operations require
both the owning worker identity and its current lease token. When an expired
deployment is reassigned, the previous running attempt is cancelled.

mTLS/certificate identity remains a production gate in addition to these
application-layer credentials.

Lifecycle history is queryable with `GET /api/v1/audit-events`, optionally
filtered by event type, entity type, or entity ID. Tokens and secret references
are not written to event details.

## Normalized collection envelope

Every collector produces one of four platform-level kinds:

```text
entity
relationship
observation
event
```

Example batch:

```json
{
  "lease_token": "ONE_TIME_LEASE_TOKEN",
  "envelopes": [
    {
      "kind": "observation",
      "type": "inventory.asset",
      "source": "internal-inventory-api",
      "subject": "server-1042",
      "observed_at": "2026-09-15T15:00:00Z",
      "idempotency_key": "server-1042:revision-7",
      "payload": {
        "hostname": "server-1042",
        "site": "HKG"
      }
    }
  ]
}
```

The source and idempotency key pair prevents duplicate processing. Envelope
storage is the normalized staging boundary; source adapters still do not write
to domain tables.

## Reference HTTP JSON worker

The first standalone worker supports the built-in `http_json` adapter:

```bash
icheck-collector \
  --control-plane http://127.0.0.1:8000 \
  --name collector-hkg-01 \
  --site HKG \
  --registration-token-file /etc/icheck/secrets/collector-registration-token \
  --http-allowed-host inventory.example.internal
```

It performs GET-only JSON collection and supports dotted record, subject,
idempotency, and observed-time paths. It has bounded response size, record
count, and timeout. HTTP redirects and URL-embedded credentials are rejected.
The worker fails closed unless the target hostname is explicitly allowlisted.

The systemd reference unit and environment template are under
`deploy/systemd/`.

## Prometheus-compatible metric backends

Metric storage remains outside PostgreSQL. Register a Prometheus-compatible
query endpoint and its remote-write destination metadata:

```json
{
  "name": "regional-prometheus",
  "provider": "prometheus",
  "query_base_url": "http://127.0.0.1:9090",
  "remote_write_url": "https://metrics.example.internal/api/v1/write",
  "credential_profile_ref": null,
  "external_labels": {
    "icheck_region": "hkg"
  },
  "enabled": true,
  "created_by": "metrics.operator"
}
```

```text
POST /api/v1/metrics/backends
GET  /api/v1/metrics/backends
POST /api/v1/metrics/backends/{id}/query
POST /api/v1/metrics/backends/{id}/query-range
POST /api/v1/metrics/backends/{id}/health?actor=metrics.operator
```

The API uses Prometheus-compatible `/api/v1/query` and
`/api/v1/query_range` endpoints. Queries have bounded length, timeout, series
limit, range, step count, and response size. Backend hosts must be explicitly
listed in `ICHECK_METRICS_ALLOWED_HOSTS`; redirects and URL-embedded
credentials are rejected. Audit stores a query SHA-256 and result metadata, not
the raw PromQL expression.

`remote_write_url` describes the configured storage path; iCheck is not a
remote-write receiver. Prometheus or vmagent performs remote write to the
selected compatible store.

## Built-in SNMP Exporter pack

`python -m icheck.seed` installs and publishes
`builtin-snmp-exporter` as a normal versioned collector artifact. A deployment
uses a site-local exporter:

```json
{
  "target": {
    "exporter_url": "http://127.0.0.1:9116",
    "target": "10.20.30.40"
  },
  "configuration": {
    "modules": ["if_mib"],
    "auth_module": "network_v3",
    "include_metric_prefixes": ["ifHC", "sysUpTime"],
    "timeout_seconds": 15,
    "max_metrics": 2000
  }
}
```

The worker must advertise the `snmp_exporter` capability. Exporter HTTP hosts
are controlled by `ICHECK_COLLECTOR_EXPORTER_ALLOWED_HOSTS`; device hosts,
wildcards, and CIDRs are controlled by
`ICHECK_COLLECTOR_SNMP_ALLOWED_TARGETS`. The exporter auth-module name is not a
credential. SNMP community or SNMPv3 material stays in the exporter-side secret
configuration and is never included in the artifact or assignment.

The worker adapter converts a bounded selection of Prometheus text samples into
`metric.sample` observation envelopes for preview, validation, and workflows.
Continuous production time series use Prometheus scrape and remote write,
not PostgreSQL envelope storage. Reference systemd units and configuration are
under `deploy/systemd/` and `deploy/prometheus/`.

## Built-in windows_exporter pack

`python -m icheck.seed` also installs and publishes
`builtin-windows-exporter`. The worker adapter performs a bounded scrape for
preview, validation, or investigation evidence:

```json
{
  "target": {
    "url": "http://10.20.7.42:9182/metrics"
  },
  "configuration": {
    "collectors": ["cpu", "logical_disk", "memory", "net", "os", "system"],
    "include_metric_prefixes": ["windows_"],
    "timeout_seconds": 15,
    "max_metrics": 2000
  }
}
```

The worker must advertise `windows_exporter`, and target hosts must match
`ICHECK_COLLECTOR_WINDOWS_EXPORTER_ALLOWED_HOSTS`. Continuous metrics are
scraped directly by Prometheus and do not pass through PostgreSQL envelopes.
Reference Windows and Prometheus configuration is under `deploy/windows/` and
`deploy/prometheus/`.

## Governed PSRP/CIM diagnostics

`builtin-psrp-cim-diagnostics` exposes four fixed read-only operations:

```text
operating_system
computer_system
logical_disks
network_adapters
```

It does not accept a PowerShell script, CIM class, filter, or command from the
deployment or future model. A deployment must use `execution_mode: on_demand`,
bind a credential profile that permits `psrp_cim`, use WinRM TLS, and target a
host in `ICHECK_COLLECTOR_WINDOWS_ALLOWED_TARGETS`.

The adapter emits `windows.cim.<operation>` observation envelopes with bounded
record and response sizes. It fails closed until the worker has an external
credential-provider-backed PSRP executor. The executor receives the published
internal template and an opaque profile reference; credential material is never
placed in the Artifact, assignment, envelope, or AI context.
