# Collector contracts

## Managed device credential custody (r9)

Device secrets entered through `/settings/credentials` are AES-256-GCM ciphertext
in `managed_device_credentials`, not plaintext profile fields. A separate native
root:API `0440` key file is provisioned through `ICHECK_DEVICE_MANAGED_SECRET_KEY_FILE`.
Back up the ciphertext database and matching key separately. API and Agent responses,
artifacts, assignments and audit metadata never expose the raw credential. Agent
tools can discover only eligible profile names/IDs. Namespace RLS and immutable
credential/profile/kind/site bindings protect custody; rotation increments both
custody and profile revisions. Dedicated human APIs require `credentials.manage`,
site authorization and browser CSRF. Validation errors remove rejected secret input.

The Collector resolves `managed_device` credentials only through authenticated
run/preflight lease endpoints, checking worker identity/mTLS, active lease token,
adapter, namespace and current site scope. The plaintext response is `no-store`,
is not available through a browser/Agent credential-read API, and lives only in the
bounded worker attempt. Existing external credential brokers are unchanged.

For managed SNMP, the worker starts a bounded attempt-local native SNMP Exporter
with a private `0700` temporary directory and `0600` JSON/YAML configuration. The
community is never placed in argv, a URL, logs or the shared exporter config. Only
root-provisioned modules and binary paths may be used. The process and private file
are removed on success/failure. The protected monitoring gateway resolves the
credential only for a currently approved SNMP enrollment and uses the same runtime;
its original CIDR/port/module scope and pre/post scrape admission checks still apply.
This preview uses per-attempt exporter processes; fleet-capacity qualification and
a pooled isolated exporter custodian remain production follow-up work.

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

This endpoint supports `arp`, `mac_table`, `dhcp` and `manual`.
`wifi_controller` is reserved for the coherent snapshot endpoint below.
MAC values are normalized to lower-case colon notation; IPv4 and IPv6
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

### Collection-clock and absence contract

The snapshot observation time is one coherent controller collection clock.
Omitted client observation times inherit it; explicit client times must equal
it. Vendor "last traffic", "last associated" or connection times are not fresh
RSSI observation times; store such metadata separately. Connection time cannot
exceed collection time. Every normalized MAC occurs at most once, and the
complete/partial flag is a strict JSON boolean. Producers must retain the same
explicit collection time when retrying, not create a new clock per attempt.

A namespace/controller-local durable watermark orders both complete and partial
snapshots, including an empty first snapshot. Older batches write no inventory
or alerts. Normalized same-time identical bodies are idempotent, independent of
client order or MAC/timezone spelling. Differing same-time bodies record
conflict, preserve the previously applied inventory and mark known controller
signal conditions unknown/conflicting; only a strictly newer coherent snapshot
can resume updates. Responses and projection summaries expose
`snapshot_disposition`: accepted, stale, duplicate, conflict or legacy_unknown.
Nonaccepted results report zero inventory writes, not fabricated client records.
Snapshot clocks more than five minutes ahead are refused even for empty batches.
Normalized bodies are bounded to eight MiB, with at most 10,000 clients.

A complete snapshot removes missing controller sessions and their current
controller-owned Wi-Fi IPs, retaining history and other collectors/controllers.
Missing clients advance retained RSSI conditions to unknown, including inactive
sessions and disabled/deleted Rules. They do not recover an open/acknowledged
signal alarm. A partial snapshot leaves omitted clients and signal conditions
untouched. Neither disappearance nor an administrative resolution is independent
quiet-state or incident-closure proof. These are asserted collection semantics,
not attestation that an arbitrary vendor API really returned a complete scan.

Generic network-observation input cannot declare source wifi_controller;
controller terminal data must use this snapshot contract. Generated projections
share the same admission path and reject boolean RSSI before integer coercion;
invalid envelopes retain their redacted dead-letter failure, not telemetry writes.
Shared endpoint creation is atomic across controllers and its metadata clock does
not regress; general ARP/DHCP/IP/attachment ordering and independently qualified
collector condition qualification remains separate work. The origin-bound typed
contract below now implements logical measurements and provenance, not that
independent qualification.

Migration `x2z4b6d8f0h3` follows `w1y3a5c7e9g2`. Stop all old ingress/
producer processes, drain Collector/Projection/Agent leases and runs, migrate
with all-namespace visibility, then restart matching API/Worker code. Backfill
retains sessions and labels the latest known clock legacy_unknown with no
invented body/completeness. Equal/older legacy samples do not update inventory.
RLS, namespace reference, immutable identity, revision/time and deletion guards
protect the watermark; recorded or hidden history refuses lossy downgrade.
The database drain check does not accept a hot mixed-version rollout.

## External alert event

Reserved keys beginning with `collector.condition:` cannot be supplied by
external Alert events or generic recovery/unknown helpers. Use an admitted
Collector envelope for that source family. Administrative acknowledgement or
resolution remains an unverified lifecycle action, not a quiet observation.

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

Collector implementation runtime and adapter must match the collector
definition. Trusted built-ins accept exactly `runtime` and `adapter`.
`python_sandbox_v1` accepts only the trusted-fetch `http_json_sandbox` adapter,
fixed `transform` entrypoint, bounded source, and exact-output fixtures. Every
fixture runs under the kernel sandbox before validation succeeds, and the
result is persisted on the immutable Artifact version. See
[`generated-code-sandbox.md`](./generated-code-sandbox.md).

## Credential profiles

The control plane stores only an opaque external secret reference:

```json
{
  "name": "inventory-readonly",
  "provider": "vault",
  "secret_ref": "vault-kv2://kv/network/inventory-readonly#token",
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
POST /api/v1/credential-profiles/{profile_id}/rotate
```

The profile never contains a password, token, SNMP community, or private key.
Deployments must use an allowed adapter and a worker selector at least as
restrictive as the credential profile. Assignments contain the profile
reference, not its external `secret_ref` or resolved secret.

For a credentialed run, the assigned Worker presents both its Worker bearer and
the active run lease token to:

```text
POST /api/v1/collector-runs/{run_id}/credential-grant
```

The control plane revalidates run ownership, lease expiry, adapter permission,
and Worker labels. It returns a resolution grant containing the provider,
external reference, adapter, deployment, and the lease-bound expiry; it never
returns credential material. The Worker then resolves the reference locally.
HashiCorp Vault KV v2 is supported through `vault`/`vault_kv2` profiles and a
Worker-local token file. `environment` is available only through an explicit
development opt-in. Unknown or unconfigured providers fail closed.

Profile references rotate with an optimistic integer revision. Rotation
requires the expected revision, a different validated external reference, an
actor, and a reason. A stale writer fails without changing the profile. Audit
stores old/new reference hashes and a reason hash, not the reference paths or
reason. Every grant carries the current profile revision. An active run may
request another grant after rotation; the control plane rechecks the same
Worker/run lease and returns the new reference/revision without returning its
value.

Vault references use `vault-kv2://MOUNT/PATH` and may select one field with
`#FIELD`. Returned scalar fields are held only for the current assignment.
Worker-only dynamic credentials use provider `vault_dynamic` with references
such as `vault-dynamic://database/creds/network-readonly`. Vault must return a
bounded lease ID, duration, renewable flag, and data object. A short renewable
provider lease is renewed before adapter execution, but its effective expiry
can never exceed the control-plane run grant. Completion attempts Vault lease
revocation and clears the values from memory. The lease ID, Vault token, and
credential values never return through iCheck APIs or audit. The Worker rereads
its Vault token file for resolve, renew, and revoke, so an atomic protected-file
replacement rotates that token without persisting it in iCheck.

Before envelopes, run failures, or logs leave the Worker, exact raw and derived
Bearer/Basic values are redacted; the in-memory mapping is cleared after the
adapter returns. Remote Worker connections require HTTPS except loopback, with
an explicit isolated-lab override.

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

Studio-generated Collector deployments, including shadow canaries, require a
reviewed target classification. A monitored Device uses
`"target_classification": "registered_device"` plus
`scope_device_id`, `scope_device_identity_revision`, and `scope_site` from the
current inventory record. An API outside Device inventory uses
`"target_classification": "external_source"` and a 10–1000-character
`external_source_reason`, with no Device ID. The latter is an operator
assertion, not an automatic proof of ownership. Known URL/host/target fields
are compared to registered management IPs and names at creation and each
Worker claim; if an external target later becomes a known Device, the
deployment is disabled before assignment. DNS aliases and custom target
fields are not resolved by this check. A Studio-generated
`registered_device` deployment is rejected unless its recognized target
URL/host matches the selected Device's management IP or inventory name;
Worker claims repeat this check. A Device name match is still an inventory
assertion, not independent DNS/TLS proof. Use `external_source` for a separate
API host; binding an alias or proxy to a registered Device requires a future
attestation contract rather than silently treating the selection as proof.
The rollout page exposes a bounded Device search and repeats the selected
Device revision check before submission. A scoped Worker must have the Device
site. Fleet plans hash and preserve the classification and reason.

Upgrading to the classification migration requires a Worker-drain and review
window. Existing unscoped Studio-generated deployments are paused and marked
`legacy_unreviewed`; generated scoped rows whose endpoint does not match the
Device IP/name are paused too. Active leases on either category make the
migration refuse to start. Create new reviewed deployments instead of
re-enabling these rows. Positive-epoch scoped rows with a direct endpoint keep
their Device binding. Existing
manually authored deployments without a classification remain compatible.
For a production upgrade, drain Collector Workers, pause new deployment writes,
verify active leases are gone, then run Alembic and review every
`legacy_unreviewed` row before resuming. PostgreSQL locks affected generated
rows during the scan, not the entire deployment table; the migration is not a
substitute for the maintenance window.

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
POST /api/v1/collector-workers/{worker_id}/device-preflights/claim
POST /api/v1/collector-workers/{worker_id}/device-preflights/{preflight_id}/complete
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

Every newly created Collector run also pins the exact
`artifact_version_id` used by its deployment. Credential grants and governed
failed-runtime revisions resolve that pinned version rather than a later
deployment version. Runs created before this provenance field was introduced
remain readable, but cannot open a Studio revision because the exact executed
code cannot be proven; that path fails closed.

Distributed Worker mTLS is implemented in addition to these application-layer
credentials. A trusted private TLS proxy verifies the certificate and forwards
a SHA-256 identity contract; the control plane binds it during registration
and requires both the bound certificate and bearer token on every Worker
route. Optional migration, required enforcement, staged certificate cutover,
rotation cancellation, and emergency revocation are documented in
[`worker-mtls.md`](./worker-mtls.md). Deploying the environment-specific CA and
proxy and completing lab acceptance remain production gates.

Device preflights use the same worker identity plus a separate expiring lease.
Claims match worker site labels and advertised adapter capabilities. Successful
and failed attempts retain bounded, secret-checked evidence; a failed attempt is
not automatically retried. The operator uses the Assets retry API with an
audited reason. Device list/detail responses expose only the latest summary;
history is fetched with a bounded limit.

The reference worker requires
`ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS`. It performs ICMP echo for `icmp`,
TCP transport checks for HTTP/SSH/Windows adapters, and a bounded site-local
SNMP Exporter query for `snmp_exporter`. TCP success explicitly states that
authentication was not tested. SNMP additionally enforces exporter and target
allowlists and fails if no exporter URL is configured.

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
to domain tables. Before staging, the control plane rechecks that each kind is
declared by the immutable CollectorDefinition and rejects inline-secret shapes.
Every newly accepted production envelope atomically receives exactly one
pending KnowledgeProjection row.

The governed projection contracts are
`icheck.knowledge.entity/v1`,
`icheck.knowledge.relationship/v1`,
`icheck.inventory.network-observation/v1`,
`icheck.inventory.wireless-snapshot/v1`, and
`icheck.alert.event/v1`. Independent PostgreSQL projection Workers claim
leased rows with `SKIP LOCKED`, enforce the originating deployment's
device/site scope, validate strict payload schemas, and commit domain writes
plus completion in one transaction. A stale Worker cannot commit after lease
reassignment. Unknown types are explicitly ignored rather than heuristically
mapped; transient failures retry with a bound and permanent failures retain
hash-only dead-letter evidence. See
`docs/knowledge-projection.md`.

Generic entity payload example:

```json
{
  "entity_type": "network.interface",
  "external_key": "Ethernet1/1",
  "display_name": "Ethernet 1/1",
  "status": "up",
  "active": true,
  "attributes": {"speed_bps": 10000000000, "mtu": 1500}
}
```

Generic relationship payload example:

```json
{
  "relationship_type": "network.link",
  "source": {"entity_type": "network.device", "external_key": "switch-a"},
  "target": {"entity_type": "network.device", "external_key": "switch-b"},
  "directed": false,
  "active": true,
  "attributes": {"protocol": "lldp"}
}
```

These contracts are intentionally narrower than arbitrary database writes.
The platform derives namespace and scope from the published Artifact and its
deployment, bounds attributes, and applies deterministic identity and
out-of-order rules.

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

## Fixed SSH JSON command worker

`ssh_command_sandbox` is a trusted acquisition adapter plus the same generated
transform sandbox used by HTTP JSON collectors. It does not accept arbitrary
shell or CLI text. A published Artifact pins one of these platform-owned
read-only profiles through a JSON Schema `const`:

```text
linux.ip_address_json
linux.route_json
cisco_nxos.show_version_json
cisco_nxos.show_interface_status_json
```

At runtime the Worker resolves the deployment's credential reference locally,
checks the target against `ICHECK_COLLECTOR_SSH_ALLOWED_TARGETS`, verifies the
server key with `ICHECK_COLLECTOR_SSH_KNOWN_HOSTS_FILE`, and executes the exact
registered command with AsyncSSH. Password or private-key authentication must
be explicit. SSH agent, default-key, keyboard-interactive, and host-key bypass
paths are disabled.

Command output must be UTF-8 JSON object/array data. Duplicate keys,
non-finite values, scalar roots, oversized responses, record overflow, timeouts,
and lease-budget violations fail the run. Trusted code converts the JSON to
normalized envelopes; only then does generated mapping code execute in the
network-denied `python_sandbox_v1` runtime. Deployment creation fails unless a
credential profile allows `ssh_command_sandbox` and matches the Worker scope.

The reference systemd environment advertises this capability only together
with an explicit allowlist, known-hosts file, credential broker, and enabled
sandbox. Device SSH preflight remains a TCP transport check and does not claim
authentication or command compatibility; successful scheduled collection is
the runtime proof.

## Governed MIB-to-exporter proposals

Capability Studio can ingest one bounded SMI MIB and propose a module for the
trusted `snmp_exporter` adapter. This is intentionally not a general MIB parser
or a direct deployment path. The subset parser resolves numeric roots and local
`OBJECT-TYPE`, `OBJECT IDENTIFIER`, `MODULE-IDENTITY`, and `OBJECT-IDENTITY`
assignments. Only a document hash and minimized symbol catalog are retained;
raw text, descriptions, notifications, and unresolved symbols are discarded
before model invocation.

The structured model selects known symbol names. Platform code—not the model—
resolves their numeric OIDs and emits the generator module. The immutable
`icheck.snmp-exporter-proposal/v1` contract pins the exporter module name,
numeric walk list, retry/timeout bounds, provenance hash, and an unsatisfied
`external_snmp_exporter_generator_v1` gate. Its validation report is marked
`publication_blocked`; every Artifact publication path rejects it.

The signed attestation acceptance and canary-only promotion protocol is
implemented. A dedicated Ed25519 purpose binds the exact proposal, MIB and
generator-module hashes to generator/exporter binary hashes, identical
generated/installed configuration hashes, zero-timeout bounded live-scrape
counts, expiry, and a replay nonce. Acceptance creates a separate validated
`icheck.snmp-exporter-attested/v1` version. Direct publication is denied; only a
passed platform Collector canary may promote it, and key revocation or evidence
expiry is rechecked at that moment. See
`docs/snmp-exporter-attestation.md`.

The repository now includes a bounded external generator/attestor CLI, exact
proposal-input API, and hardened non-container systemd job template. Installing
the pinned generator, provisioning its dedicated key/OS identity, separately
installing the reviewed module, and producing real-device laboratory evidence
remain deployment gates. Until those gates pass, the proposal cannot become a
live candidate.

## Canary target ownership record

New Collector canaries store the reviewed target classification independently
from their shadow deployment. A canonical SHA-256 digest binds the candidate
version, target, configuration, Worker selector, credential reference, schedule,
ownership fields and creator. Promotion compares the stored digest with the
rollout and current deployment and rechecks current target identity. Historical
canaries have no trustworthy snapshot and cannot be promoted without
a fresh canary. This prevents a mutable deployment from silently changing the
reviewed target; it does not authenticate a DNS name or TLS peer.

External-source classification checks recognized `url`, `host`, and `target`
hosts against Device inventory. On PostgreSQL, the Collector holds a
tenant/region/host transaction key while creating a deployment or rechecking
ownership at Worker assignment and canary promotion. A Device trigger takes
the same key for insert, delete, or identity changes, including direct SQL
writes. This excludes a newly committed inventory match from the interval
between review and commit without a table-wide runtime lock. Other hosts can
continue independently. Custom target fields and alias/DNS/TLS proof are not
covered by this key; those need a separate attestation contract.
After a Worker wins the deployment-row update, it reloads the target and Worker
selector before assignment; a concurrent edit observed after the wait is not
replaced by an older in-memory candidate.
This is a claim-time decision. It does not revoke an assignment already issued
before a later Device change or authenticate the remote peer at network I/O.

## Collector execution admission

New Collector leases persist an assignment SHA-256 over the claim-time version,
target, configuration, Worker selector, credential reference and ownership
fields. The Worker receives that digest and presents it with its lease token to
`POST /api/v1/collector-runs/{run_id}/admit`. External-source and Device-bound
runs require successful admission before credential grant, lease renewal,
envelope ingestion or completion. The Worker checks once before requesting a
credential and again after resolving it, immediately before invoking an
adapter. The same review is repeated at subsequent active-run API contacts:
the claim digest, deployment enabled state, current Device identity revision
and site, target ownership, and Worker selector/site must still match. Workers
without the `execution_admission_v1` registration marker cannot claim
external-source deployments; Device-bound admission uses the universal
`io_supervisor_v1` gate. A drifted target run is cancelled, its lease cleared,
its deployment disabled, and an audit event retained; later evidence is
denied. A Worker that loses the required external-source admission marker or
deployment selector/site scope is also cancelled, while the valid deployment
remains available for another Worker.
The Device-bound admission acceptance record (private development evidence; not distributed)
captures isolated Worker socket-stop, non-owner PostgreSQL/RLS and full-suite
results; it does not accept the live fleet or lab.

The admission migration does not invent claim-time evidence for old runs. It
refuses active external leases on upgrade and refuses downgrade once new claim
evidence exists. The later supervised-I/O fence requires a drain of **all**
Collector leases and running runs. Deploy with a Worker drain and restart. The two-phase check
narrows the handoff window; by itself it cannot interrupt an adapter already
performing network I/O when inventory changes afterward. Cancellation at the
next API contact prevents subsequent ingestion. Remote peer attestation remains
a separate gate. A Worker that never contacts the
control plane again relies on the separate lease-expiry reconciliation below
to mark its abandoned run terminal.

The updated Linux Collector Worker binary executes every built-in adapter in a spawned,
disposable process after pre-I/O admission. The parent re-admits during I/O at
two-second intervals, caps each control-plane check at five seconds, and
terminates the adapter process group on revocation, lost control-plane access,
or the shorter of the lease, credential and adapter wall deadlines. The child
establishes a new process group before network I/O and binds its own lifetime
to the parent Worker with Linux parent-death `SIGKILL`. An independent watchdog
enforces the adapter wall deadline even if an admission HTTP call itself stalls.
No envelopes are sent
after a denied check. Controlled tests cover a blocked loopback HTTP read,
a stalled admission check, and generated HTTP transformation in the nested
sandbox. The real PostgreSQL Worker `SIGKILL`/reclaim probe observes the first
adapter socket close. It cannot undo a remote action already sent, promise
instantaneous detection between polls, or guarantee that external subprocesses
escaping the group are killed. Non-Linux Workers, mixed old/new Worker fleets,
live SNMP/SSH/WinRM targets, and production-scale polling require separate
acceptance. Updated Linux Workers register `io_supervisor_v1: true`; the control
plane refuses **all new Collector deployment claims** from a Worker without
that marker (including non-Linux Workers) and rejects run mutations if the
marker is later removed. This is
a compatibility gate, not a cryptographic attestation of Worker code. Existing
legacy leases may already be doing I/O before the new control plane starts and
are not stopped by this marker check. For a production cutover, stop old
Collector services, wait for or reconcile their active leases, verify no old
adapter processes remain, stop old API instances, run migration
`q5s7u9w1y3a6`, then start the updated control plane and site Workers.
The migration requires visibility of all namespaces, takes a bounded
PostgreSQL table lock, and refuses any lease with a Worker/token or any
`RUNNING` Collector run. It installs a database trigger that rejects a
lease for an unmarked Worker even if an older API binary attempts direct SQL.
A second trigger prevents removal of the marker while that Worker holds a
lease; the lease trigger locks the Worker row to serialize both commit orders.
The SQLite migration checks the drain but relies on the API code gate for
claim admission. The marker is Worker-reported compatibility metadata, not
binary attestation. Do not put old and new Worker binaries on
the same active registration identity. If a lease is still active, defer the
upgrade rather than treating a denied completion as proof that remote I/O
stopped.
The native database acceptance record (private development evidence; not distributed)
includes the migration lock race, old SQL claim denial, non-owner RLS, strict
JSON boolean marker and full PostgreSQL regression. It is not a live service
cutover acceptance.
Worker startup fails closed if its advertised Collector capabilities or the
built-in adapter registry contain a type without supervised-I/O support.
The supervised-I/O acceptance record (private development evidence; not distributed)
documents the controlled process-loss and deadline evidence.

The namespace-pinned `icheck-collector-lease-reconciler` closes that gap for
expired leases even when a Worker never calls back. It takes a PostgreSQL
deployment row lock with `SKIP LOCKED`, cancels still-running runs, updates
device runtime health and canary gates, records an audit event, and releases the
lease atomically. A new claim uses the same finalization path before handing out
a replacement token. Repeated sweeps do not double-count a cancelled run.
Scheduled deployments wait their configured interval before retrying;
on-demand deployments do not retry automatically. Run one reconciler per
tenant/region under supervision; lease duration plus poll interval is the
nominal terminalization delay while that controller is healthy, with any
backlog adding processing time. This does not stop network I/O already in
progress in a lost Worker process by itself; the supervised Worker path above
provides the process-level stop for updated Linux Workers.

A second bounded sweep repairs historical `running` rows whose deployment
lease was already cleared or now belongs to another run. It locks deployment
then run, refreshes both before deciding, and cancels only the orphan with a
distinct `lease_owner_lost` reason and audit event. A newer valid lease and its
run remain untouched. Repair does not invent a former lease deadline: the
absence of a current owner is sufficient to make the old run terminal.
Canary and runtime-health reconciliation apply to these repairs too. Expired
lease and orphan batches commit separately so one bad category cannot undo an
already completed repair; both remain bounded and idempotent.
The orphan-reconciliation acceptance record (private development evidence; not distributed)
covers non-owner PostgreSQL isolation, row contention, and newer-lease safety.

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

## Built-in LLDP/CDP adjacency pack

`python -m icheck.seed` also publishes
`builtin-snmp-device-adjacency`. Its trusted `snmp_topology` adapter converts a
bounded, normalized SNMP Exporter info metric into one
`icheck.network.device-adjacency-snapshot/v1` relationship envelope. A device-
scoped deployment binds the resulting graph to that device for Topology and
Situation impact context:

```json
{
  "target": {
    "exporter_url": "http://127.0.0.1:9116",
    "target": "10.20.30.40",
    "local_device_key": "core-01",
    "local_display_name": "Core 01"
  },
  "configuration": {
    "protocol": "lldp",
    "modules": ["icheck_lldp"],
    "auth_module": "network_v3",
    "neighbor_metric": "icheck_lldp_neighbor_info",
    "scrape_health_metric": "snmp_scrape_walk_duration_seconds",
    "remote_device_key_labels": [
      "remote_chassis_id",
      "remote_system_name"
    ],
    "complete_snapshot": true,
    "max_neighbors": 1000
  }
}
```

The Worker must advertise `snmp_topology` and uses the same exporter/target
allowlists as `snmp_exporter`. The configured exporter module must expose one
normalized gauge/info row per physical link with local port, stable remote
device identity, and remote port labels. Optional system name and management
IP labels enrich the remote entity. Vendor community or SNMPv3 secrets remain
inside the exporter and are never copied into the envelope.

A complete snapshot is accepted only when the configured exporter scrape-
health metric is present. This prevents an empty response or misspelled
neighbor metric from closing every known link. The projection aggregates up to
128 parallel links per remote device, closes relationships missing from a
newer complete snapshot, and prevents a delayed older snapshot from
reactivating them. An empty but healthy complete snapshot is valid.

The built-in pack defines the safe normalized contract and lifecycle; it does
not claim that one SNMP module covers every vendor. The lab gate must still
validate each vendor's MIB/generator mapping, stable chassis identity, label
cardinality, and empty-table behavior before production deployment. Until
then, the seeded web activation policy makes the reviewed adjacency capability
available beside the ordinary SNMP metric capability, but does not claim that
an unvalidated vendor module is safe.

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
record and response sizes. The Worker credential broker supplies a lease-bounded
username/password mapping directly to the production PSRP transport together
with the published internal template. The transport rechecks the exact template,
target, and port; forces WinRM HTTPS; verifies the server certificate against
the system trust store or an explicit PEM CA bundle; ignores ambient HTTP proxy
settings; permits explicit `ntlm` or `basic` authentication only; and strictly
parses bounded JSON. It runs each call in a short-lived spawned process and
terminates that process at the operation deadline, so a hung WinRM request
cannot silently outlive the Collector lease.

Install a Windows-capable Worker with `pip install 'icheck[windows]'` (or the
equivalent project/wheel extra) and configure:

```text
ICHECK_COLLECTOR_CAPABILITIES=...,psrp_cim
ICHECK_COLLECTOR_WINDOWS_ALLOWED_TARGETS=10.20.0.0/16,*.windows.example.internal
ICHECK_COLLECTOR_PSRP_ALLOWED_PORTS=5986
ICHECK_COLLECTOR_PSRP_AUTH=ntlm
ICHECK_COLLECTOR_PSRP_CONFIGURATION_NAME=iCheck.ReadOnly
ICHECK_COLLECTOR_PSRP_CA_FILE=/etc/icheck/pki/windows-winrm-ca.pem
```

The CA file is optional only when the WinRM certificate already chains to the
Worker's system trust store. There is deliberately no insecure certificate
mode. `Microsoft.PowerShell` is the default endpoint; production deployments
should prefer a constrained JEA endpoint. Credential material is never placed
in the Artifact, envelope, control-plane audit, or AI context, and the Worker
clears the lease-local mapping after the call. Live Windows-host, CA, Vault
rotation, and least-privilege/JEA acceptance remain lab gates.

The read-only Agent Tool `windows.get_latest_diagnostics` can consume the latest
fresh successful run only when its deployment is bound to an authorized Device.
It does not trigger collection. It rechecks the published `psrp_cim` adapter and
projects only operation-specific CIM fields; target, credential, arbitrary
payload, failure, and Worker metadata are omitted.

Active collection uses the separate non-read-only
`windows.request_diagnostics` Tool. It accepts only a Device ID, exact fixed
operation set, optional deployment ID for ambiguity, and reason. The platform
resolves an already published, enabled, Device-bound on-demand deployment; the
model cannot provide a script, target, credential, or Collector configuration.
The request passes through the normal exact-plan human approval and resumable
action path, is audited as an Agent trigger, and does not add a duplicate trigger
while the same deployment is queued or running.

## Versioned collector conditions

A published Collector can declare up to 64 `condition_contracts` in its Artifact
definition. They are part of the immutable version's content, not a threshold
or verdict supplied by a Worker:

```json
{
  "condition_contracts": [{
    "key": "cpu.high",
    "event_type": "device.cpu.high",
    "entity_type": "device",
    "title": "High CPU",
    "operator": "gt",
    "expected": 90,
    "unit": "percent",
    "max_age_seconds": 300
  }]
}
```

The CollectorDefinition must declare observation output. After execution
admission, the authenticated Worker sends an observation envelope of type
`icheck.collector.condition/v1` through the normal leased run envelope endpoint.
Its payload is deliberately small:

```json
{"condition_key": "cpu.high", "entity_id": "DEVICE_UUID", "value": 99, "quality": "valid"}
```

Entity ID can be omitted for a Device-bound device condition; an envelope
subject must agree with an explicit ID. Supported entity types are device,
endpoint, knowledge_entity and reviewed external-source identity. Current
namespace, deployment scope and entity ownership are rechecked. These are
logical identity pins, not hardware/firmware attestation.

The evaluator supports lt/lte/gt/gte/eq/ne. Ordered predicates require a numeric
expected value. Numeric inputs are never coerced from booleans or strings.
Missing, explicitly unknown, type-incompatible or too-old measurements are
unknown, never quiet. Strings and integers are bounded; nonfinite floats and
caller-supplied verdict/authority fields are rejected. Observations cannot
precede execution admission or their issued credential grant, exceed its
lifetime, or be more than five minutes ahead.

Acceptance seals the normalized measurement with current published definition,
assignment/target/configuration, entity identity, Worker token-issuance/mTLS
identity and credential-profile revision plus its actual grant audit reference.
No credential values are stored. Caller source labels are descriptive only.
Condition envelope idempotency is namespaced to the exact run; changed payload
reuse is an error and a duplicate still needs fresh Worker authentication.
A rejected batch rolls back all its accepted items.

Projection rechecks the sealed measurement and current origin after locks.
Drift retains redacted projection failure history and does not apply a quiet
observation. Source generations are deployment/version/assignment/profile-
revision/condition/entity local. A new credential or definition generation
cannot recover the previous generation's Alert. Worker replacements can share
a logical generation; their individual origin pins remain in admissions.
Receipt commit and Alert mutation share a transaction. Exact receipt recovery
does not repeat a mutation; concurrent retries create one receipt/occurrence.
Older observations are stale, equal normalized measurements are duplicates,
and unequal same-time measurements conflict even when their predicates agree.
Only a newer measurement clears conflict.

Capability Studio's structured specification exposes condition definitions
and bounded literal or field-path mappings. For an API returning only CPU and
device fields, map the literal `cpu.high` into `condition_key`; no vendor-specific
condition-name field or IDE change is required. Generated fixtures are checked
against the declared typed contract before the normal hardened no-network
sandbox and reviewed publication. Empty condition lists preserve legacy Studio
serialization. Candidate canary evidence is still separate from production
condition admission.

Migration `y3a5c7e9g1i4` follows `x2z4b6d8f0h3` and adds namespace-protected,
append-only admissions, source generations and interpretation receipts with
reference/authority guards. Stop all old ingress/producers, drain Collector,
Projection and Agent work, migrate with all-namespace visibility, then restart
matching code. Legacy reserved generic keys require reconciliation without
deleting history; no authenticated provenance is invented by backfill.
Recorded or hidden provenance refuses downgrade.

Every receipt explicitly sets `independently_verified: false` and
`authorizes_incident_closure: false`. An ordinary versioned quiet measurement
may recover its source Alert; it is not independent causal proof, vendor
freshness/completeness attestation, automatic remediation authority, or AI
incident-closure permission. Production transport/physical qualification,
retention/load, independent closure authority/recovery and proof UI remain
separate gates. The logical network-ordering prerequisite is described below.

## Network observation ordering and explicit address sets

ARP, MAC-table, DHCP and manual observations now use durable clocks scoped to
namespace, Endpoint, source, Collector Device (or explicit unbound identity),
and dimension: metadata, IPv4, IPv6 or attachment. The direct API and normalized
`icheck.inventory.network-observation/v1` projection share admission. They are
logical observations, not authenticated physical identity or independent causal
truth; both independent-verification and incident-closure flags remain false.

Use an explicit address set when the source observes every address for that
Endpoint/source/Collector association:

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_addresses": ["10.20.0.42", "10.20.0.43", "2001:db8::42"],
  "source": "arp",
  "collector_device_id": "DEVICE_UUID",
  "interface_name": "Ethernet1/3",
  "vlan_id": 20,
  "observed_at": "2026-10-05T10:00:00Z"
}
```

`ip_addresses` replaces both address families for only that source/Collector;
an empty array explicitly deactivates both. A legacy singular `ip_address`
replaces only its own family, leaving the other family unchanged. Omitting IP
fields observes neither family and does not clear addresses. Do not combine
both forms. Addresses are normalized, unique and bounded to 256; a set carries
one VLAN, not per-address VLAN metadata. Other sources and retained history
are never deleted by a source's replacement.

Omitting `interface_name` preserves an existing attachment and its cursor.
Send strict boolean `attachment_present: false` for explicit detach; it advances
the attachment clock and deactivates only that source/Collector association,
including an empty-first boundary that rejects later delayed resurrection.
`true` requires an interface or Collector identity, and `false` cannot accompany
an interface. A first legacy Collector-bound sparse observation can retain an
unknown-port observer association; that is not proof of a physical attachment.
Multiple simultaneous ports/VLAN attachments for one source/Collector/MAC are
not represented by this single-attachment contract.

Older frames make no writes. Equal normalized values are duplicates; unequal
same-clock values mark the dimension conflicted without replacing previously
applied inventory. Only a strictly newer accepted dimension clears conflict.
Equal-clock contradictory items in one batch are rejected before mutation.
`network_dispositions` reports per-input/per-dimension decisions, including
`not_observed` for an omitted known attachment. Endpoint API rows and the
Endpoints subpage label retained source conflicts and legacy/unqualified rows;
retention must not be presented as fresh independent evidence.

Clocks normalize to UTC and cannot exceed five minutes ahead. Canonical bodies
are compared directly, with finite JSON, depth/node, 64-KiB dimension and
eight-MiB batch bounds; no standalone SHA256 job is introduced. Relevant pending
edits are refused before flush. Device locks and endpoint insertion serialize
supported writers; authorization, enabled state and generated deployment scope
are rechecked after waits. Source-local current/history indexes and bounded
history queries reduce avoidable scans, not prove fleet throughput.

Migration `z4b6d8f0h2j5` follows `y3a5c7e9g1i4`. Stop old ingress and processes,
drain Collector/Projection/Agent runs and leases, migrate with all-namespace
visibility, then restart matching code. Legacy active and inactive history is
backfilled as `legacy_unknown` with an empty, uninvented body. Reference,
identity, revision, clock, RLS and deletion/downgrade guards preserve history.
This is not a mixed-version hot-rollout gate or a production migration.

## Studio normalization of vendor arrays

Studio can author bounded per-item and nested-array mappings without a new
adapter or IDE patch. `item_field` extracts one relative path; `item_mappings`
builds each object. The trusted `value` wrapper makes primitive records/items
consistent between authoring and HTTP/SSH collection. Order, multiplicity,
nulls and observed empty lists are preserved; malformed/missing arrays fail the
whole transform rather than imply disappearance. Singleton wrapping is explicit.
Registered normalized payload/domain checks still apply, so preserved values
are not automatically qualified inventory. Filtering, coercion and executable
expressions are not supported.

The plan is bounded to 128 total operations and eight array levels; strict
per-array limits cannot exceed 10,000. Fixed response-wide 100,000 item-visit /
1,000,000 step budgets and existing sandbox byte/AST/time limits cannot be
increased through deployment configuration. See the
[mapping grammar and examples](./capability-studio.md#bounded-vendor-array-mappings--5-october-2026).
Controlled Linux-shaped address and controller-client publication/projection
tests pass on non-owner PostgreSQL RLS. They are not vendor/clock/physical
qualification, real Linux command or controller API acceptance, a multi-port/
VLAN contract, sustained fleet throughput or incident-closure authority.

Isolated acceptance covers service ordering on PostgreSQL and SQLite plus
populated backfill/guards. The Studio follow-up adds a populated native backfill
case and registered normalized-record/structured-mapping authoring; see
[Capability Studio](./capability-studio.md#registered-normalized-collector-outputs--5-october-2026).
Physical/vendor freshness, broader list transformations, multi-port cardinality,
sustained capacity and rendered UI/live GUI acceptance remain distinct work.
The earlier inventory-only boundary is recorded in the
bounded verification record (private development evidence; not distributed).

## Explicit IP/VLAN and port/VLAN binding sets (v2)

The later `icheck.inventory.network-observation/v2` contract implements the
non-wireless multi-binding prerequisite. Direct producers use
`POST /api/v1/inventory/network-observations/v2`; generated Collectors select
that exact registered record type in Studio. The catalog now contains nine
contracts. Wi-Fi controller clients still use the separate wireless snapshot
contract and its complete/partial controller-local clock rules, not generic
network observations.

```json
{
  "observations": [{
    "mac_address": "00:1b:44:11:3a:b7",
    "collector_device_id": "<authorized-enabled-device-id>",
    "source": "arp",
    "observed_at": "2026-10-05T10:00:00Z",
    "ip_family_scope": "dual_stack",
    "ip_bindings": [
      {"ip_address": "192.0.2.10", "vlan_id": 10},
      {"ip_address": "192.0.2.10", "vlan_id": 20},
      {"ip_address": "2001:db8::10", "vlan_id": 10}
    ],
    "attachments": [
      {"interface_name": "eth1", "vlan_id": 10},
      {"interface_name": "eth1", "vlan_id": 20},
      {"interface_name": "eth2", "vlan_id": 20}
    ]
  }]
}
```

The example clock must be replaced with an actual observation clock. Its Device
reference must resolve in the current authorized namespace; it is not a target
ownership or freshness assertion. Generated payloads do not supply
`observed_at`: the trusted envelope clock and admitted Device binding are
injected by projection, as with v1.

Each address/VLAN pair and interface/VLAN pair has its own history row. VLAN
is a strict integer from 1–4094, or null when unspecified; booleans/floats/
numeric strings are rejected. Duplicate normalized pairs are refused rather
than filtered. Set order and equivalent MAC/IPv6 spelling do not manufacture
different observations. Bounds are 256 IP bindings and 64 attachments per
observation, 2,000 observations per batch, with the existing eight-MiB batch,
64-KiB channel, finite-JSON and future-clock checks also applying.

For IP replacement, `ip_family_scope` is mandatory when `ip_bindings` is
supplied: `ipv4`, `ipv6` or `dual_stack`. Every binding must belong to the
declared family scope. An IPv4-only frame does not clear IPv6. Omitted/null
sets mean **not observed**, preserving bindings and that dimension's source
clock. Explicit `ip_bindings: []` with a declared scope clears only those
source-owned families; `attachments: []` clears only this source's attachments.
An empty first observation retains its cursor, so an older frame cannot create
or resurrect bindings. Source/Collector isolation, stale rejection, same-clock
conflict retention and atomic invalid-batch handling remain unchanged.

Reappearance after an accepted clear creates a new history episode, retaining
the earlier disconnected interval. This is logical declared source-set
completeness, not independently measured physical completeness. No accepted
frame, clear, catalog entry, graph edge or history result grants incident-closure
authority.

V1 keeps its original singular/shared-VLAN behavior. Its endpoint refuses v2
fields instead of silently ignoring them; v2 refuses ambiguous v1 fields.
Equivalent lost-response retries across versions compare only exact known
shapes. A legacy unknown interface is not equivalent to an explicitly empty
port set. A **newer v1** frame still applies v1 replacement semantics, so do not
run competing v1/v2 producers for the same source-owned cohort. Adopt v2 through
a reviewed, single-owner, coordinated Collector/API/Projection rollout; there
is no automatic conversion or qualification of legacy history.

Studio can map vendor address and port arrays into these object arrays with
`item_mappings`; missing/malformed source arrays still fail the transform, not
become empty clears. Published type/identity/clock defaults remain pinned.
Endpoints disambiguate repeated IPs by VLAN, and topology/runtime preview
retains distinct bounded parallel paths. Studio reports actual preview counts
and its 16-node/32-edge display cap. The existing history Tool output schema
stays compatible; scope-filtered limit-plus-one reads now disclose truncation
and non-independent completeness in the evidence summary.

The v2 verification record (private development evidence; not distributed)
reports 218 affected ordinary and 233 migrated non-owner PostgreSQL checks,
24 frontend unit cases, final typing/strict lint/build and isolated desktop/
390px browser checks. The complete ordinary repeat at this boundary passes
1,287 with 24 skips and eight warnings in 1,480.66 seconds; it does not accept
the full native database or live lab.
Production history capacity, vendor semantics/freshness, deployed framework
concurrency, full accessibility and the six-class live GUI lab remain open.

## External peer acceptance of condition sources

Collector condition receipts remain logical, non-independent observations.
Separate append-only source-validation proposals, peer reviews and revocations
can now qualify one exact generation for a fresh single-Alert quiet check.
Repeated newer quiet polls retain the known Alert episode in their receipts;
only a quiet source before the first Alert has no episode pointer. Source
qualification does not alter v1/v2 inventory clocks, vendor completeness,
physical truth or Situation closure permission. Read the
[source acceptance contract](collector-source-qualification.md) before use.
