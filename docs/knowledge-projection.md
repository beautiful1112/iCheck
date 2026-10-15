# Knowledge Projection Worker

## Product boundary

Collector adapters emit source-neutral Entity, Relationship, Observation, and
Event envelopes. The envelope table is an immutable staging and replay
boundary; it is not itself the operational knowledge model. The Knowledge
Projection Worker closes the first production Observe loop by translating
explicitly versioned envelope contracts into scoped generic knowledge plus the
existing endpoint, IP, wired attachment, Wi-Fi terminal, rule-alert, and
Alert-trigger domains.

The first executable contracts are:

| Envelope kind | Type | Projection |
|---|---|---|
| `entity` | `icheck.knowledge.entity/v1` | Artifact-namespaced, deployment-scoped generic entity state and history |
| `relationship` | `icheck.knowledge.relationship/v1` | Artifact-namespaced, deployment-scoped directed or undirected graph edge |
| `relationship` | `icheck.network.device-adjacency-snapshot/v1` | LLDP/CDP device entities and lifecycle-aware Layer-2 neighbor edges |
| `observation` | `icheck.inventory.network-observation/v1` | Endpoint identity, IP history, and wired attachment |
| `observation` | `icheck.inventory.wireless-snapshot/v1` | Endpoint identity, IP history, controller terminal sessions, RSSI rules |
| `event` | `icheck.alert.event/v1` | Stateful Alert and any separately activated Alert Workflow |

Other types are retained as immutable staging evidence and end in `ignored`
with an explicit contract summary. They do not create partially understood
domain records. `metric.sample` remains bounded preview/evidence; continuous
time series still go directly through Prometheus scrape and remote write.

## Durable pipeline

```text
Collector Worker
  -> validate lease + declared output kind + inline-secret policy
  -> CollectionEnvelope (source + idempotency key unique)
  -> KnowledgeProjection (one row per envelope)
  -> PostgreSQL SKIP LOCKED lease
  -> strict versioned payload + deployment-scope validation
  -> domain writes + projection completion in one transaction
  -> generic graph / inventory / Wi-Fi / Alert / Workflow-trigger knowledge
```

Accepted production envelopes and their pending projection row are committed in
the same transaction. Duplicate `source + idempotency_key` submissions neither
create a second envelope nor a second projection. The migration backfills every
pre-existing staging envelope as pending, in bounded 1,000-row batches.

Multiple `icheck-projection-worker` processes may share the queue. Claims use
row locking with `SKIP LOCKED`, a random lease token stored only as SHA-256, a
deadline, and an attempt counter. Expired processing leases can be reassigned.
Completion uses a conditional update on status, worker, token hash, and
unexpired deadline in the same transaction as domain writes. If ownership
changed while work was running, all old-worker domain changes roll back and the
new lease remains intact.

Transient failures move to `retry` with bounded exponential backoff and become
`dead_letter` after five claims. Strict-schema, inline-secret, and authorization
scope violations are permanent and dead-letter immediately. Error text and raw
payload are never returned by the operations API; only error type and SHA-256
are persisted. An authorized operator may reasonedly requeue an ignored or
dead-letter row, and that action is audited.

## Contract authority and scope

The envelope timestamp, source, subject, and immutable CollectorDefinition are
authoritative. Payloads use strict schemas with unknown fields rejected.

- A network observation may omit `collector_device_id` only when the
  deployment's exact device scope supplies it. A site-scoped observation must
  name a device in that site.
- A wireless snapshot must resolve to a real `wireless_controller` inside the
  deployment's device/site scope.
- A device Alert must target a device inside scope. An endpoint Alert must
  target an endpoint already linked through IP, wired, or wireless evidence to
  an in-scope device. Scoped collectors cannot emit arbitrary global entity
  types.
- Generic Entity and Relationship contracts require an explicit device or site
  deployment scope. Their namespace is derived from the immutable Collector
  Artifact, never supplied by an untrusted payload. Identity is
  `namespace + scope + type + external_key`, so identical interface names on
  different devices do not merge. A relationship can connect only entities in
  its own namespace and scope; an undirected edge is canonicalized so reversed
  source/target order remains one edge.
- Generic attributes are normalized contract data, not raw payload storage.
  They are secret-checked and limited to 64 top-level keys, six levels, finite
  JSON values, and 32 KiB serialized size. Newer `observed_at` state wins;
  older arrivals may extend first/last-seen history but cannot regress current
  state. Entity and relationship `active=false` provides explicit lifecycle
  closure.
- A device-adjacency snapshot uses the same Artifact-derived namespace and
  deployment scope. It accepts only LLDP or CDP, at most 2,000 links and 128
  parallel links per remote device, consistent normalized remote metadata, and
  no self-links or duplicate links. Links to the same remote device are
  aggregated into one undirected `network.l2_neighbor.lldp` or
  `network.l2_neighbor.cdp` relationship. Only a newer complete snapshot may
  close absent relationships and deactivate an orphaned remote entity; delayed
  snapshots may update first-seen history but cannot reactivate closed state.
- The CollectorDefinition's declared `output_kinds` is rechecked before
  staging. A compromised Worker cannot submit an Event through an
  observation-only Artifact.

Projection uses the envelope's `observed_at`; a payload cannot replace it.
Domain services are transaction-composable so Alert rules and Alert Workflow
outbox rows commit atomically with the underlying inventory change.

## Operations API

```text
GET  /api/v1/knowledge-projections/health
GET  /api/v1/knowledge-projections?status=dead_letter
POST /api/v1/knowledge-projections/{projection_id}/retry
GET  /api/v1/knowledge-projection-workers
GET  /api/v1/knowledge/entities?entity_type=network.interface&active=true
GET  /api/v1/knowledge/relationships?relationship_type=network.link
```

Projection list and health queries inherit Collector deployment device/site
scope. Worker identities are global operations metadata. Responses expose
contract identity, state, attempts, lease metadata, bounded result counts, and
hash-only errors; they exclude envelope payloads.

Generic knowledge list APIs require `assets.read`, enforce the same device/site
scope as their source deployment, accept bounded type/namespace/active filters,
and return only normalized contract fields. Topology Studio can select the
catalogued generic entity and relationship types. Its stored preview omits
arbitrary generic attributes.

The AI L1 Collection Gaps rail shows projection Worker availability, active
queue size, oldest ready age, hourly completion count, and dead letters. This
is confidence context for the operator, not a traditional monitoring
dashboard.

## Bare-metal deployment

The production Worker requires PostgreSQL; it refuses SQLite because safe
multi-process ownership depends on database row locks.

```bash
ICHECK_DATABASE_URL='postgresql+psycopg://icheck_projection@127.0.0.1:5432/icheck?sslmode=require' \
ICHECK_TENANT_ID=00000000-0000-4000-8000-000000000001 \
ICHECK_REGION_ID=00000000-0000-4000-8000-000000000001 \
ICHECK_PROJECTION_WORKER_NAME=projection-worker-hkg-01 \
.venv/bin/icheck-projection-worker
```

Reference files:

- `deploy/systemd/icheck-projection-worker.service`
- `deploy/systemd/projection-worker.env.example`

Processes are horizontally scalable and do not require Docker.

Provision a protected dedicated password/connection and the reviewed
`projection-worker` profile through the [native controller procedure](native-release.md).
Never use API/migration-owner credentials or give generated capabilities this
trusted-core role. The current native environment example supplies the mandatory
production authentication/governance flags as well as namespace binding.

R30 adds a 43-relation profile and real native empty polling/restart/clean-stop
acceptance under `icheck-projection`. Supported inventory/Wi-Fi/Alert/topology/
condition/derived-indicator paths pass on disposable PostgreSQL under the exact
profile, including populated source subprocess SIGKILL, natural 15-second lease
reclaim and idempotent restart. Named timestamp grants on reference rows are
actual timestamp UPDATE permissions needed for row locks, not configuration or
credential-reference authority. See the r30 record (private development evidence; not distributed).

## Verified and remaining

Automated acceptance covers API-to-staging queue creation, source idempotency,
network/IP/attachment projection, WLC terminal and RSSI Alert projection,
direct Alert projection, strict output-kind and secret rejection, device-scope
dead letter, bounded generic attributes, scoped generic Entity/Relationship
upsert, reversed undirected-edge idempotency, LLDP/CDP snapshot aggregation and
closure, out-of-order adjacency non-reactivation,
generic topology preview, bounded hash-only errors, audited retry, lease
expiry/reassignment, scoped health/list output, migration from an empty
database, and legacy-envelope backfill.

This slice does not claim the M1 scale exit gate. The guarded
`icheck-scale-test` harness now drives the real scheduling and projection paths
with at least two Collector Workers, two Projection Workers, deterministic
lease loss, queue/latency, CPU, memory, timeout, retry, and simulated
time-series cardinality reporting. Its automated SQLite run is deliberately
non-representative; a private 1,000-target PostgreSQL functional run has also
passed. A separate real-process recovery probe (private development evidence; not distributed)
passed with a SIGKILL, natural lease expiry, a second Projection Worker, and
one final endpoint/IP observation. A separate controlled
Collector process-loss probe (private development evidence; not distributed)
also passes through this projection path. Production sizing, infrastructure
restarts, and live SNMP/WLC/Windows sources remain open. See
[`scale-testing.md`](./scale-testing.md).
