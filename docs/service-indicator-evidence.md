# Governed service-indicator evidence

## Purpose

Service indicators connect externally measured operational or business facts to
the governed service catalog. They let the AI operator answer questions such as
“is checkout latency above its reviewed threshold?” without treating an SLO
target, topology adjacency, or model prose as measured truth.

An indicator definition is reviewed catalog configuration. An observation is
time-bound evidence. Threshold and freshness status are calculated by iCheck,
not supplied by the model or source system.

## Definition contract

Each indicator belongs to one service and has a stable lower-case key, display
name, kind, unit, source type/reference, freshness duration, lifecycle state,
and monotonic revision. Supported kinds are availability, latency, error rate,
throughput, saturation, business, and custom. Source types are Prometheus, API,
Collector, business system, or manual.

Threshold behavior is explicit:

- `above` becomes warning/critical when the value reaches the corresponding
  upper threshold;
- `below` becomes warning/critical when the value reaches the corresponding
  lower threshold;
- `none` is informational and cannot carry thresholds.

When both thresholds are configured, their ordering is validated. Values and
thresholds must be finite. Definition creation checks the parent service
revision; definition updates check the definition revision. Both operations
increment the service catalog revision and write audit events.

`source_ref` identifies a query or upstream metric contract. It is not a place
for a token, password, or connection string. Source credentials remain in the
existing secret-reference and Worker boundary.

## Scheduled Prometheus publication

A Prometheus-source indicator can own one revisioned polling binding. The
binding selects an enabled, allowlisted Metric Backend and stores PromQL,
polling interval, timeout, explicit reduction, and an optional label allowlist.
It never stores a URL or token. `single` requires exactly one scalar/vector
sample and may retain only selected labels. `sum`, `avg`, `min`, and `max`
reduce a vector to one finite value and intentionally discard series labels.
Matrix, string, empty, malformed, non-finite, and over-100-series results fail
closed.

The standalone PostgreSQL-only `icheck-indicator-worker` performs two bounded
operations:

1. lock due bindings with `SKIP LOCKED`, create one durable occurrence, and
   move `next_run_at` forward from the current time so downtime does not create
   an unbounded catch-up storm;
2. claim occurrences with expiring leases, query the existing hardened Metric
   Backend boundary at `scheduled_for`, reduce the response, and publish an
   idempotent observation.

The source observation key is deterministic from binding and scheduled occurrence;
the durable observation UUID is allocated once. Observation, audit and terminal
poll completion now commit together, eliminating a separate observation-commit
gap. Temporary backend/no-data
failures retry up to three times with bounded exponential delay; invalid query
or result contracts dead-letter immediately. Run and binding health persist
only error type and SHA-256 fingerprint, never the remote error body. A stale
worker must revalidate its lease under a poll-row lock before observation
publication and completion. Upstream I/O holds no row locks. After the query,
the worker locks and rechecks binding/definition/backend revisions and enablement
until commit; a changed contract dead-letters without publishing its stale sample.
PostgreSQL READ COMMITTED with DBAPI autocommit disabled is required.
The binding is automatically paused when its indicator is disabled or changes
away from the Prometheus source type.

## Collector and Workflow Artifact publication

API, Collector, and business-system indicators can bind to one exact published
Artifact version. The binding is revisioned, can be paused or resumed, and is
automatically paused if the indicator is disabled or its source contract drifts.
It stores no target URL or credential and cannot become a second arbitrary HTTP
scheduler.

A Collector binding requires a published Collector Artifact that declares
`observation` output. Its deployed Collector Worker emits an ordinary normalized
envelope with kind `observation`, type
`icheck.service-indicator-observation/v1`, a stable binding key, finite value,
optional measured/estimated quality, bounded string dimensions, and a required
source idempotency key. The Knowledge Projection Worker matches the envelope to
the exact deployed Artifact version and binding key, then requires its
device/site authorization scope to overlap at least one current service
component. Observation, publication provenance, and projection completion
commit atomically; an unknown/disabled binding, cross-scope source, malformed
payload, or missing idempotency key dead-letters without a partial domain write.

A Workflow binding requires an exact published schedule-triggered Workflow, one
of its pinned read-only Tool dependencies, and schema-checked output paths. The
value path must be numeric, an optional observation-time path must be a JSON
Schema date-time string, and optional dimensions must be a string-only object.
Only a completed Investigation with exactly one successful call to that Tool
can publish. iCheck reads the typed Tool result at terminal checkpoint commit;
model conclusions and free-form/structured model output are never metric input.
The same Investigation cannot publish twice for one binding.

Every publication stores the exact Artifact version, binding revision, created
observation, and either the source Collection Envelope or the Investigation and
ToolCall. This provenance is first-class scoped data, not a string parsed from
model prose.

## Observation and freshness contract

Every observation carries a source observation ID, value, measurement quality,
bounded dimensions, optional evidence reference, source observation time,
ingestion time, and authenticated actor. The pair of indicator definition and
source observation ID is unique. An exact replay returns the original row; a
replay with different content fails with `409`.

The latest observation is selected by observation time, then ingestion time and
durable ID. This prevents a late-arriving old sample from replacing newer
current evidence. Source times more than five minutes in the future are
rejected.

iCheck exposes three related states:

- `threshold_status`: healthy, warning, critical, or informational;
- `freshness_status`: fresh or stale;
- `effective_status`: stale when expired, otherwise the threshold status.

Staleness therefore never masquerades as health. Threshold edits re-evaluate
live reads against the current definition. A persisted AI assessment separately
stores the definition revision and evaluated evidence snapshot, so later edits
cannot rewrite its historical basis.

## Situation and Agent integration

For every visible service in a bounded Situation impact graph, iCheck adds the
latest observation from each enabled indicator as a
`service_indicator:{definition_id}` evidence node. A durable
`service_indicator_observation:{observation_id}` edge connects it to the
service. Nodes expose the minimized value, unit, source reference, quality,
threshold/freshness status, observation time, expiry, and definition revision.

Critical and warning fresh evidence is prioritized before stale, healthy, and
informational evidence when graph limits are approached. The existing 100-node,
200-edge, and three-hop limits still apply. Summary counts distinguish all
indicator nodes, fresh breaches, and stale indicators.

The `situations.get_impact` LangGraph Tool validates and returns this same
schema. It remains deterministic context, not proof of root cause. When an AI
impact proposal identifies an affected service or indicator node, the connected
indicator evidence is copied into `indicator_context_snapshot` alongside the
service and dependency snapshots.

## Authorization and API

Reads use `services.read` plus the existing component-derived service scope.
Definition and observation writes use `services.manage` and require
manage visibility over every component of the service. This deliberately avoids
exposing an external machine-writer API: the dedicated Worker publishes through
the internal domain service. Artifact-binding writes additionally require
`capabilities.read`. The built-in `service_owner` receives `metrics.read` and
`capabilities.read` so the Service Intelligence UI can select only existing
governed backends and published Artifact versions.

| Purpose | Contract |
|---|---|
| List definitions and latest evidence | `GET /api/v1/services/{service_id}/indicators` |
| Create a revision-checked definition | `POST /api/v1/services/{service_id}/indicators` |
| Update, disable, or revise thresholds | `PATCH /api/v1/services/{service_id}/indicators/{indicator_id}` |
| Read bounded observation history | `GET /api/v1/services/{service_id}/indicators/{indicator_id}/observations` |
| Ingest idempotent evidence | `POST /api/v1/services/{service_id}/indicators/{indicator_id}/observations` |
| Read the Prometheus binding | `GET /api/v1/services/{service_id}/indicators/{indicator_id}/prometheus-binding` |
| Activate a revision-checked binding | `POST /api/v1/services/{service_id}/indicators/{indicator_id}/prometheus-binding` |
| Revise, pause, or resume polling | `PATCH /api/v1/services/{service_id}/indicators/{indicator_id}/prometheus-binding` |
| Queue an immediate durable occurrence | `POST .../prometheus-binding/poll-runs` |
| Read bounded run history | `GET .../prometheus-binding/poll-runs` |
| Read/create an Artifact publication binding | `GET/POST .../artifact-binding` |
| Pause or resume Artifact publication | `PATCH .../artifact-binding` |
| Read bounded publication provenance | `GET .../artifact-binding/publications` |

The dedicated `/services` workspace configures indicators, PromQL bindings,
reduction/schedule controls, exact-version Collector/Workflow bindings, recent
run/publication provenance, and latest evidence. It also offers manual sample
ingestion for lab validation. The AI L1 homepage does not duplicate this
configuration surface.

## Current boundaries

- This store is for low-cardinality service/business evidence and governed
  snapshots. High-volume time series remain in Prometheus-compatible storage.
- The public API accepts one direct observation per request. Prometheus,
  normalized Collector envelopes, and scheduled Workflow Tool results publish
  through internal domain services; a separate external batch-ingestion API is
  intentionally not present.
- Indicator breaches enrich Situation evidence but do not yet synthesize Alert
  events or mutate deterministic Situation severity.
- Prometheus instant-query polling and governed Collector/Workflow publication
  are implemented. Generic API and business-system collection still executes through
  a versioned Collector deployment or scheduled Workflow, never a second
  unrestricted scheduler in the Service Catalog.
- Credential-profile-backed queries use the process-local environment/Vault
  resolver, not secrets stored in the indicator or backend tables. Restricted-role
  native tests exercise an actual authenticated HTTP query and process-loss
  recovery; native systemd acceptance remains empty-queue only. Production
  authenticated Prometheus, rotation and live-source behavior remain lab gates.

The r30 controller record (private development evidence; not distributed)
documents the eleven-relation Indicator profile, dedicated native account/login,
transaction rollback and revision-fence tests. Timestamp-only reference-row
UPDATE grants permit PostgreSQL locks but cannot edit queries, thresholds,
credential references or configuration revisions. These are trusted core roles,
not delegated machine-writer or tenant credentials.
