# Service-indicator visualizations

Status as of 12 October 2026: **superseded for new development** by
[Grafana presentation](grafana-monitoring-design.md). Retire the custom
`/visualizations` journey and service-indicator designer from the preview UI;
new dashboard artifacts target Grafana. Preserve existing artifacts/history
until a migration exists. The following is a legacy contract, not a direction
to extend iCheck's chart renderer.

## Implemented boundary

Capability Studio can author an immutable `icheck.visualization/v1` Artifact
from natural-language intent. The first visualization type is deliberately
bounded to normalized service-indicator observations already governed by the
service catalog. It does not let a model emit PromQL, SQL, JavaScript, remote
URLs, or executable rendering code.

The authoring model receives only a capped catalog containing service and
indicator keys/names, criticality, kind, unit, threshold direction/values, and
whether observations exist. Owner contacts, component identities, source
references and queries, dimensions, evidence references, and observation
values are excluded. The model may select exact catalog pairs and propose:

- one to twelve line, stat, or status panels;
- a one-to-four-column layout;
- a 15-to-3,600-second refresh interval;
- a five-minute-to-seven-day lookback; and
- a one-to-500-point limit per panel.

Trusted platform code validates every selector, produces the canonical
Artifact documents and content hash, queries the normalized observation table,
computes threshold/freshness state, and creates the bounded Studio preview.
Only observed time, value, measurement quality, and derived threshold status
enter a render. Dimensions, evidence references, source observation IDs,
ingestion actors, and source queries remain outside the view contract.

## Lifecycle and runtime

`POST /api/v1/capability-studio/sessions/visualizations` creates the authoring
session. Generation and conversational refinement use the ordinary Studio
endpoints, with every refinement creating another immutable version. A human
must explicitly publish a validated version.

The dedicated runtime is `/visualizations`:

```text
GET /api/v1/visualizations
GET /api/v1/visualizations/{artifact_id}/render[?version=N]
```

Discovery exposes only current published versions whose complete referenced
service set is visible to the caller. Rendering requires `services.read` and
reapplies `service_scope_clause` before querying any definition or observation.
A partially visible multi-service view is hidden rather than partially
rendered, preventing the Artifact selectors from revealing an out-of-scope
service. The API returns the same 404 for missing and unauthorized views.

Every render revalidates the canonical definition, implementation, validation
test, content hash, and publication provenance. A retired service or missing or
disabled indicator becomes an explicit bounded panel drift state; it never
silently retargets another indicator. Point limits and the immutable lookback
apply on every refresh. The frontend renders the minimized response and does
not issue direct Prometheus or database queries.

## Investigation proposal path

A bounded Investigation may request `icheck.visualization-proposal/v1` and
produce a separate evidence-linked proposal. Trusted code checks cited evidence
ownership, validates selectors under the Investigation's frozen authorization
scope, and stores a minimized preview. The AI L1 home links this intent to the
dedicated `/studio/visualization-proposals` review queue. A reasoned global
human publish atomically creates and publishes an ordinary immutable
Visualization Artifact; rejection creates none. See
`docs/investigation-visualization-proposals.md`.

## Deliberate limits

This first slice is a service-health visualization, not a general dashboard or
arbitrary query builder. Cross-source panels, raw metric labels, PromQL
authoring, temporal topology replay, report scheduling, PDF delivery, and
report types beyond deterministic service-health snapshots remain future governed
capabilities. Prometheus-backed indicators still reach the view through the
existing scheduled indicator ingestion boundary, preserving credential and
query policy outside model and browser contexts.
