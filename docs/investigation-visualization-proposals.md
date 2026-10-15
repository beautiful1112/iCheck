# Investigation-generated visualization proposals

## Implemented boundary

A bounded Investigation may request the strict
`icheck.visualization-proposal/v1` output contract. The model can propose one
declarative service-indicator visualization, but it cannot create or publish an
Artifact directly. Completion persists a separate proposal only after trusted
code proves all of the following:

- every cited evidence reference is present in the final checkpoint and belongs
  to the same Investigation;
- every selected service/indicator pair is enabled and visible through the
  Investigation's frozen authorization scope;
- the specification is the canonical `icheck.visualization/v1` contract and
  contains no queries, code, credentials, URLs, source references, dimensions,
  contacts, or component details; and
- the scoped, bounded preview contains current normalized indicator evidence.

The stored preview contains only service/indicator display identity, observed
time, numeric value, measurement quality, derived threshold/freshness state,
and explicit drift/truncation state. It is supporting review evidence, not an
assertion of causality or a published operational view.

## Operator and API lifecycle

The AI L1 home exposes **Generate governed service visualization** as an output
intent. The Investigation model receives the typed output schema and rules to
cite existing evidence, select only governed indicators, and express
uncertainty. Completed proposals enter `/studio/visualization-proposals`.

```text
GET  /api/v1/visualizations/proposals[?status=proposed|published|rejected]
GET  /api/v1/visualizations/proposals/{proposal_id}
POST /api/v1/visualizations/proposals/{proposal_id}/publish
POST /api/v1/visualizations/proposals/{proposal_id}/reject
```

Proposal reads require global `capabilities.read`; review actions require
global `capabilities.manage`. Publish and reject require a human identity and
reason. Rejection creates no Artifact. Publication is one database transaction
that creates, deterministically revalidates, and publishes an ordinary
immutable Visualization Artifact with proposal and Investigation provenance.
Name conflicts, dependency drift, and validation errors roll back the complete
transaction and leave the proposal pending.

The resulting Artifact is not a privileged proposal type. It is discovered and
rendered through the ordinary `/visualizations` runtime, which reapplies the
caller's current `services.read` scope and current dependency/drift checks.

## Deliberate limits

- One completed Investigation creates at most one proposal.
- A proposal cannot edit an existing Artifact or bypass Studio lifecycle.
- The AI cannot select indicators outside its frozen Investigation scope even
  if the later human reviewer has global access.
- Publication does not freeze data values; it freezes selectors and bounds.
  Runtime values remain live normalized observations.
- Empty, invented, foreign, disabled, or out-of-scope evidence fails closed.
- Arbitrary queries, cross-source panels, alert mutation, automatic publish,
  report scheduling, and PDF/report Artifacts remain outside this slice.

## Acceptance coverage

Automated coverage proves evidence ownership, scoped selector rejection,
minimized previews, reasoned rejection, ordinary immutable publication, live
runtime discovery, and atomic rollback on Artifact-name conflict. Live-model
quality and real-lab indicator evidence remain release acceptance gates.
