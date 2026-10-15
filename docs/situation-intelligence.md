# Situation intelligence

## Product boundary

A Situation is the durable operational issue that the AI L1 operator should
prioritize. It groups related Alert evidence without deleting, merging, or
hiding the original Alerts. An Investigation may be bound to a Situation, but
the two records have different responsibilities:

```text
Alert           deterministic signal and lifecycle
Situation       correlated issue, priority, ownership, evidence timeline
Investigation   bounded AI reasoning, tools, evidence, conclusion/escalation
```

The current implementation starts with deterministic `same_entity/v1`
correlation and may upgrade a live Situation to `reviewed_service/v2` when a
new Alert has one unambiguous, recent match through required components of the
same human-reviewed active service. If service correlation does not match,
`qualified_topology/v3` may group one-hop adjacent symptoms through fresh,
active, allowlisted topology evidence. The v3 policy is deliberately a
non-causal grouping policy. It separately persists evidence-linked AI hypotheses
and governed AI service-impact assessments. AI records are proposals with
explicit confidence and review state; they never rewrite deterministic
correlation or Alert truth. The platform does not claim cross-device causality
or infer service-to-service dependencies from proximity. It consumes reviewed
catalog and observed topology records as deterministic context. External incident state may be
captured through a schema-pinned MCP result and observed through the signed
inbound reconciliation contract, but it never rewrites local Situation truth.

## Correlation and lifecycle

The correlation key is a stable SHA-256 digest of the correlation version,
entity type, and entity ID. At most one non-resolved Situation may exist for a
key. PostgreSQL correlation takes a transaction-scoped advisory lock before
the active-key lookup, while a partial unique index is the final invariant.
For v2, correlation also locks the bounded set of reviewed service IDs in a
stable order so simultaneous component Alerts cannot independently create two
Situations before either can observe the other.
For v3, it takes stable topology-endpoint advisory locks and row locks on the
bounded current evidence before selecting a candidate Situation.

- A first active Alert creates an open Situation and is attached as evidence.
- A distinct active Alert for the same entity joins the live Situation.
- A distinct Alert on another required component may join only when its source
  and an active member are bound to the same active service, their observation
  times are within 15 minutes, and all reviewed-service evidence resolves to
  exactly one active Situation.
- Optional components, stale Alerts, more than 32 source-service bindings,
  more than 128 candidate rows, Situations with 100 Alerts, or two candidate
  Situations fail closed into an independent exact-entity Situation.
- If v2 does not match, v3 accepts only active wired attachments, active wireless
  sessions, or active undirected `network.link`, `network.l2_neighbor.cdp`, and
  `network.l2_neighbor.lldp` Knowledge Relationships observed no more than 15
  minutes before the new Alert, with at most five minutes of future clock skew.
  The source and neighbor Knowledge Entities must both be active. Directed,
  unknown, stale, oversized, or ambiguous topology evidence fails closed.
- V3 is one-hop symptom grouping only. It does not traverse a path, infer edge
  direction, select a root cause, or convert an AI hypothesis into fact.
- A repeat occurrence updates its existing Alert and Situation aggregate but
  does not append redundant timeline noise.
- Acknowledgement records the actor and optional reason without mutating the
  underlying Alert states.
- New Alert evidence on an acknowledged Situation reopens operator attention.
- A Situation auto-resolves only when every member Alert is resolved.
- A later Alert on the same entity creates a new Situation generation instead
  of reopening historical resolved evidence.

Priority v1 is deterministic: the strongest active severity is the base, with
bounded increments for active-symptom count and total occurrences. It is an
operational queue score, not a probability of root cause. Correlation
confidence is `1.0` for exact entity identity and `0.85` for the reviewed-service
membership hop. A qualified-topology membership uses `0.70`; a Situation
reports the minimum membership confidence. None of these values is AI
diagnostic confidence or proof of causality.

## Evidence and audit

`situation_alerts` preserves membership reason, confidence, state snapshots,
and a minimized immutable correlation-evidence document. A v2 document pins
the service ID and revision, both component IDs and entity identities, catalog
observation time, and correlation window. A v3 document pins the selected
topology record type and ID, relationship type, observation timestamp, source
and target identities, target Alert, evidence-age/window limits, and
`causal_claim=false`. The timeline stores its SHA-256
digest rather than duplicating it. Source
Alert title, description, type, timestamps, status, severity, and occurrence
count remain readable in the detail API. `situation_events` uses a monotonically
increasing per-Situation sequence for correlation, state, severity, lifecycle,
and Investigation-link events. Operator lifecycle actions also enter the audit
log.

Detail responses are bounded to 500 Alerts and 500 timeline events and include
truncation flags. Investigation links are bounded to the newest 100 records.
No model output participates in either correlation transaction.

## AI hypotheses and governed impact assessments

Situation-bound Investigation checkpoints may persist root-cause hypotheses as
separate records. Each normalized statement keeps an ordered confidence history
and every supporting or contradicting reference must already be present in that
checkpoint and belong to the same Investigation. Running checkpoints retain
`candidate` records; only completed Investigations expose `proposed` hypotheses.
An operator must supply a reason to accept or reject a proposal. The decision is
written to the Situation timeline and audit log; it does not change Alert state
or the deterministic correlation key.

Investigations started from the Situation or AI L1 workspace request the strict
`icheck.situation-impact-assessment/v1` completion contract. A completed result
must cite at least one persisted Investigation evidence record. Every affected
node ID must also exist in the current impact graph under the Investigation's
immutable authorization snapshot. Missing output, invented evidence, and stale
or out-of-scope node IDs fail the checkpoint transaction. A valid result is
stored as `proposed`, with impact level, confidence, affected nodes, uncertainty,
and evidence links; it also requires a reasoned human accept/reject decision.

The assessment is an AI interpretation, not the deterministic impact graph and
not an automatic business-impact fact. Current topology context can support a
proposal but proximity alone cannot prove cause. Accepted proposals remain
reviewed opinions and do not mutate the Situation's severity or priority.

Active service catalog entries whose reviewed component bindings intersect the
authorized impact graph are added as deterministic context nodes. They carry
minimized owner, criticality, impact-class, and SLO facts plus a durable catalog
component edge. When an assessment names one of those service nodes, the current
facts and catalog revision are copied into an immutable assessment snapshot.
One reviewed dependency hop is expanded in either direction only when both
services are visible under the caller's scope. The durable dependency row is
the edge evidence. A proposal touching that edge stores an immutable dependency
snapshot alongside the cited service facts.

Enabled service indicators contribute only their latest durable observation.
Each appears as a `service_indicator` node connected to its service by a
`service_indicator_observation` evidence edge. The node separates current
threshold status from freshness and uses `stale` as the effective state when
the observation has expired. Fresh warning/critical evidence, stale evidence,
and total indicator counts are explicit in the graph summary. AI proposals
copy connected evidence plus its definition revision into
`indicator_context_snapshot`; later observations or threshold edits do not
rewrite the proposal. See
[service-indicator-evidence.md](./service-indicator-evidence.md).

## Impact context, not causal truth

`GET /api/v1/situations/{id}/impact` derives a bounded live graph around the
Situation root. It reads current wired attachment, wireless session, and IP
observation records plus active Knowledge Entities scoped to participating
devices and their authorized one-hop relationships. It emits at most 100 nodes,
200 edges, and deterministic shortest paths of at most three hops. Every edge
includes its durable evidence type, evidence ID, and observation time; arbitrary
Knowledge Graph attributes and raw source payloads are omitted.

Every authorized Alert-member entity is also included. A v2 membership adds an
undirected `correlated_by_reviewed_service` edge backed by the durable
`situation_alerts` row. This edge explains grouping only; it is deliberately not
named or interpreted as a dependency or causal relationship.
A v3 membership similarly adds `correlated_by_fresh_topology`, backed by the
frozen Situation membership and the pinned topology-evidence reference. It is
also explanatory grouping evidence, not a causal edge.

The response boundary is always `deterministic_context_not_root_cause`.
Adjacency is useful evidence, but it is not proof that one node caused another
node's symptom and it is not a business-impact score. The read-only
`situations.get_impact` Agent Tool returns the same schema and creates a durable
Investigation evidence reference. A Situation-bound Investigation cannot use
that Tool to query a different Situation.

An authorized operator can open `/topology?situation_id=...`. The selected
published topology Artifact is revalidated and then rendered with the impact
node IDs as additional SQL filters. The Artifact's immutable selectors, node
and edge types, layout, authorization scope, and limits remain authoritative;
the Situation does not generate or mutate an executable view definition.

## Authorization

Situation list, detail, acknowledgement, resolution, dashboard counts, and
linked Investigation creation reuse the caller's device/site authorization
scope. Device and collector-device Situations require an authorized device;
endpoint and terminal Situations require endpoint visibility derived from an
authorized IP observation, wired attachment, or wireless controller session.
A cross-entity Situation is returned only when every member Alert passes the
same caller scope; partial results are never rendered from an authorized root.
Out-of-scope direct reads return `404`.

## APIs and UI

| Purpose | Contract |
|---|---|
| Prioritized queue | `GET /api/v1/situations` |
| Evidence and timeline | `GET /api/v1/situations/{id}` |
| Scoped external references | `GET /api/v1/situations/{id}/external-references` |
| Bounded impact context | `GET /api/v1/situations/{id}/impact` |
| AI hypothesis records | `GET /api/v1/situations/{id}/hypotheses` |
| Review an AI hypothesis | `POST .../hypotheses/{hypothesis_id}/accept` or `/reject` |
| Governed impact assessments | `GET /api/v1/situations/{id}/impact-assessments` |
| Review an impact assessment | `POST .../impact-assessments/{assessment_id}/accept` or `/reject` |
| Acknowledge | `POST /api/v1/situations/{id}/acknowledge` |
| Resolve after all Alerts resolve | `POST /api/v1/situations/{id}/resolve` |
| Reconcile legacy active Alerts | `POST /api/v1/situations/reconcile/active-alerts` |
| AI L1 counts and priority rail | `GET /api/v1/dashboard/summary` |

`/situations` provides filtering, priority and lifecycle state plus a rapid
evidence preview. Every queue row and AI L1 priority card links to the canonical
`/situations/{id}` focused workspace. That stable route loads the Situation
directly rather than depending on its presence in the bounded queue, and shows
correlated Alert evidence, deterministic impact context, AI hypothesis and
impact proposals, reasoned review controls, the ordered timeline, linked
Investigations, and first-class external references. Reference access uses the
same all-members Situation scope check; there is no partial cross-scope
disclosure. Opening detail is read-only; starting an Investigation remains a
separate explicit action.
Starting an Investigation writes `situation_id`, the primary entity scope, and
the requested impact-assessment contract into durable Investigation state. The
AI L1 home applies the same contract when a Situation seeds its composer.

## Operational migration

New and changed Alerts enter correlation inside the existing Alert transaction.
For Alerts created before this schema, a globally authorized operator may run
the bounded reconciliation endpoint in batches of at most 10,000. The operation
selects only non-resolved Alerts without a membership and is safe to repeat.

## Verified acceptance

- Alert creation, distinct evidence attachment, occurrence aggregation, and
  priority recomputation.
- Unique reviewed-service cross-entity attachment, frozen revision evidence,
  exact-member continuation, ambiguity rejection, stale-window rejection,
  optional-component rejection, and all-members scope enforcement.
- Fresh one-hop topology attachment through native and generic evidence,
  allowlist/direction/age enforcement, inactive-entity rejection, unique-
  Situation selection, immutable provenance, non-causal impact edges, and
  fail-closed ambiguity.
- Acknowledgement, attention reopening, all-members resolution, and new
  post-resolution generations.
- Situation detail, timeline, dashboard summary, Investigation binding, legacy
  reconciliation, and device/site denial behavior.
- Evidence-bound hypothesis confidence history and human review.
- Fail-closed impact-assessment output, evidence and authorized-node validation,
  persistence, human review, timeline, audit, and out-of-scope denial.
- Revision-checked dependency lifecycle, one-hop Situation expansion,
  assessment snapshots, and cross-scope non-disclosure.
- Investigation-generated topology proposals validate cited evidence and
  selectors under frozen scope, then require reasoned human publication.
- Revision-checked service indicators, invalid-threshold rejection, idempotent
  observation replay/conflict, fresh breach/stale classification, Agent-visible
  Situation edges, and immutable assessment evidence snapshots.
- Revision-checked Prometheus bindings, strict scalar/vector reduction,
  schedule misfire bounds, leased Worker success/retry/dead-letter behavior,
  hash-only failures, and automatic shutdown on indicator disable/source drift.
- Exact-version Collector/Workflow indicator bindings, schema-checked Tool
  result mappings, normalized-envelope and Investigation/ToolCall provenance,
  idempotent publication, permanent malformed-input dead letters, and atomic
  no-partial-write failure behavior.
- Pinned MCP output-path validation, exactly-once remote-reference capture,
  scoped reference reads, Ed25519 callback verification, bounded timestamp and
  payload checks, replay conflict detection, stale suppression, hash-only
  inbound records, and proof that remote status does not mutate local lifecycle.
- Full backend regression suite.
- Empty-database upgrade to Alembic head, downgrade to the previous head, and
  re-upgrade.
- Frontend lint and production build including the queue at `/situations`,
  canonical focused `/situations/{id}` routes, and the Situation-focused
  `/topology` flow.

## Next M4 slice

1. Validate live Prometheus/vendor MCP and webhook adapters plus PostgreSQL
   concurrency/failure behavior
   in the lab.
2. Keep multi-hop causal conclusions in the governed hypothesis/assessment
   path until an explicit, evidence-reviewed causal policy is designed.
