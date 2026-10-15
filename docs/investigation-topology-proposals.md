# Investigation-generated topology proposals

## Contract and trust boundary

An Investigation requests `icheck.topology-proposal/v1` in its immutable
scope. A completed output contains a rationale, a strict
`GeneratedTopologySpec`, one or more persisted Investigation evidence-reference
IDs, and explicit uncertainty. Missing output, duplicate references, invented
evidence, evidence owned by another Investigation, invalid selector values, or
an empty authorized preview fail the checkpoint transaction.

The Agent does not create or activate an Artifact. The trusted platform builds
the canonical `icheck.topology/v1` documents and validates a bounded preview
with the Investigation's frozen device/site authorization snapshot. Proposal
previews use the same minimized topology fields and exclude raw payloads,
endpoint usernames, and arbitrary Knowledge Graph attributes.

## Human review and publication

Global capability reviewers use `/studio/proposals` or these APIs:

| Purpose | Contract |
|---|---|
| List the review queue | `GET /api/v1/topology/proposals` |
| Read one proposal | `GET /api/v1/topology/proposals/{id}` |
| Publish with reason | `POST /api/v1/topology/proposals/{id}/publish` |
| Reject with reason | `POST /api/v1/topology/proposals/{id}/reject` |

Publishing is one database transaction: create the Topology Artifact and first
version, revalidate it against current inventory, publish the immutable version,
link the proposal to both IDs, and write audit history. A name conflict,
validation drift, or any other failure rolls the whole transaction back. The
result appears through the ordinary Artifact Library and `/topology` runtime;
there is no second or privileged rendering path for AI-created views.

The proposal remains an AI-authored recommendation. Its scoped preview is
validation evidence, not live topology and not a root-cause conclusion.
