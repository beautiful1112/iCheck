# Governed service catalog

Status as of 12 October 2026: **legacy feature, removed from the target preview
experience**. Services and Service Intelligence are outside the current
[development goal](codex-goal.md). Remove their navigation/routes and decouple
normal operator journeys. Preserve records and dependent alert/run history
until a reviewed migration retires the backend. The contracts below describe
existing implementation, not new requirements. Metric visualization moves to
[Grafana](grafana-monitoring-design.md).

## Product role

The service catalog supplies deterministic organizational facts to the AI L1
operator. A service record answers who owns an outcome, how critical it is,
which objective applies, and which current graph nodes implement it. It is not
an AI conclusion and it does not infer that a component failure has caused a
business outage.

Each record includes:

- a stable, lower-case `service_key`;
- owner team and optional contact;
- `tier_0` through `tier_3` criticality;
- critical, high, moderate, or low business-impact classification and a plain
  language impact statement;
- optional SLO target, RTO, and RPO;
- active or retired lifecycle state, bounded tags, and a monotonic revision;
- one or more scoped device, endpoint, or Knowledge Entity component bindings;
- reviewed, directional service dependencies classified as synchronous,
  asynchronous, data, or shared infrastructure, with critical-path state and
  a required architecture/evidence note.
- revisioned service-indicator definitions with typed sources, units, threshold
  direction, warning/critical boundaries, freshness duration, and lifecycle;
- idempotent, time-bound operational or business observations whose threshold,
  freshness, and effective status are calculated by iCheck.

The service key is immutable. Updates use `expected_revision`; a stale writer
receives `409` and must reload. Component additions and removals also increment
the revision. The final component cannot be removed, so an active catalog entry
cannot silently become unscoped.

A dependency means the source service depends on the target service. Creating
or removing it checks the source service's current revision, increments that
revision, and writes an audit event. Self-dependencies and duplicate
source/target/type assertions are rejected.

Indicator creation checks the parent service revision. Indicator edits check
the definition revision, and either operation increments the service revision.
Observation ingestion does not mutate catalog revisions. An exact replay of a
source observation ID is idempotent; conflicting content is rejected.

## Authorization boundary

`services.read` exposes a service when at least one component is inside the
caller's device/site scope. Only visible components are returned. A scoped
`services.manage` principal may change a service only when every component is
inside that principal's scope; cross-scope services require a globally scoped
owner. New components are resolved under the caller's current scope before the
transaction is committed. Out-of-scope direct reads return `404`.

Indicator reads inherit `services.read` and the parent service's component-
derived scope. Definition and observation writes currently require the existing
`services.manage` permission plus manage visibility over every component. A
dedicated machine-writer role remains subject to a separate RBAC review.

A dependency is returned only when both endpoint services are visible. Adding
or removing one requires manage access to both fully scoped services. This
prevents a readable service from becoming a side channel for an out-of-scope
service's name, owner, or existence.

The built-in viewer and operator roles can read scoped service context. The
built-in `service_owner` role can maintain fully scoped services. All create,
fact update, binding add, and binding remove operations are audited without
embedding credentials or raw telemetry.

## Situation and AI boundary

The bounded Situation impact graph matches catalog bindings against nodes that
are already present in the caller-authorized graph. An active service becomes a
`service:{id}` node connected by a durable `service_catalog_component:{id}`
edge. The node exposes only minimized service facts: criticality, business
impact, SLO target, and owner team. The same 100-node, 200-edge, and three-hop
limits still apply.

The graph then expands one reviewed dependency hop in either direction. Edges
preserve the catalog direction (`source depends on target`) and use the durable
dependency row as evidence. Related services are filtered through the same
service/component authorization clauses before any node or edge is returned.

This gives the Agent deterministic context such as “this device supports a
tier-0 checkout service.” It does not prove the service is unavailable. If an
AI impact proposal cites a service node, iCheck copies the relevant catalog
facts and catalog revision into `service_context_snapshot`. Later catalog edits
therefore cannot rewrite the historical basis of an accepted or rejected
assessment.
When an affected service touches a visible dependency edge, the dependency,
both service identities, classification, critical-path flag, evidence note,
and observation time are also copied into `dependency_context_snapshot`.
Enabled indicators with observations become minimized, freshness-aware evidence
nodes connected to the service by the durable observation row. When an affected
service or indicator is named, the definition revision, source, value, quality,
classification, observation time, and expiry are copied into
`indicator_context_snapshot`. This is measured context, not causal proof.

## APIs and UI

| Purpose | Contract |
|---|---|
| List scoped services | `GET /api/v1/services` |
| Create with initial components | `POST /api/v1/services` |
| Read one service | `GET /api/v1/services/{id}` |
| Revision-checked fact update | `PATCH /api/v1/services/{id}` |
| Bind a component | `POST /api/v1/services/{id}/components` |
| Remove a non-final component | `DELETE /api/v1/services/{id}/components/{component_id}` |
| List visible dependencies | `GET /api/v1/services/{id}/dependencies` |
| Add reviewed dependency | `POST /api/v1/services/{id}/dependencies` |
| Remove reviewed dependency | `DELETE /api/v1/services/{id}/dependencies/{dependency_id}` |
| List indicator definitions/latest evidence | `GET /api/v1/services/{id}/indicators` |
| Add a revision-checked indicator | `POST /api/v1/services/{id}/indicators` |
| Revise/disable an indicator | `PATCH /api/v1/services/{id}/indicators/{indicator_id}` |
| Read bounded indicator history | `GET /api/v1/services/{id}/indicators/{indicator_id}/observations` |
| Ingest idempotent evidence | `POST /api/v1/services/{id}/indicators/{indicator_id}/observations` |
| Configure Prometheus polling | `POST/PATCH /api/v1/services/{id}/indicators/{indicator_id}/prometheus-binding` |
| Trigger/read durable poll runs | `POST/GET .../prometheus-binding/poll-runs` |
| Bind an exact Collector/Workflow version | `GET/POST/PATCH .../artifact-binding` |
| Read Artifact publication provenance | `GET .../artifact-binding/publications` |

`/services` is a dedicated subpage rather than a home-dashboard block. It lets
an authorized owner create a service from existing devices, edit ownership,
criticality, impact, SLO/RTO/RPO and lifecycle state, and manage device
bindings. Endpoint and Knowledge Entity bindings are supported by the API and
can be added to later contextual UI selectors without changing the contract.
The same page lists incoming and outgoing dependencies and lets an authorized
owner add or remove outgoing assertions with an explicit evidence/rationale
note and source-revision check.
The same page contains indicator configuration, Prometheus polling contract/run
health, exact-version Collector/Workflow publication bindings, source
provenance, latest evidence, and a manual lab-sample path.
Full behavior and boundaries are specified in
[service-indicator-evidence.md](./service-indicator-evidence.md).

## Current limits

- Situation expansion follows one service-dependency hop; it is context, not
  transitive causal or availability inference.
- SLO values remain governed objectives; individual indicator evidence does not
  yet calculate rolling-window SLO compliance or error budgets.
- Business-impact classification remains human-owned. Business observations
  provide evidence but do not automatically change the classification.
- Scheduled Prometheus instant-query and generic API/business-system
  publication are implemented. The latter uses an exact published Collector
  version plus normalized envelope or a schedule Workflow's single successful
  pinned read-only Tool result; there is no catalog-owned arbitrary scheduler.
- Component existence is validated on writes and on reads; stale external
  bindings are hidden from impact graphs rather than treated as evidence.
- Automatic discovery may propose catalog bindings or dependencies in a future
  slice, but publication must remain reviewed and revisioned.
