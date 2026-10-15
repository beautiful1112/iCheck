# Capability Catalog

The Capability Catalog is the runtime truth view for published iCheck
capabilities. It is intentionally separate from the Artifact Library. The
Library answers what was authored, validated, transferred, or restored; the
Catalog answers whether the current published version can be used by the AI
operator now.

The first local-catalog slice is available at:

```text
GET /api/v1/capability-catalog
UI  /studio/catalog
```

The read API requires global `capabilities.read`. It supports bounded `q`,
`kind`, `readiness`, `offset`, and `limit` parameters. Pagination is applied
after live readiness projection because dependency and activation state can
change independently of Artifact publication. `q` matches name, description,
and owner. At most 10,000 published candidates are projected per request; a
separate `scan_truncated` flag prevents that safety bound from looking like a
complete result.

The optional `preapproval_tool=true` filter is for the reviewed-change Tool
picker. It returns only published Tool versions that are currently `ready` and
declare a low-risk, device-bound change contract with desired-state
observations. Search runs before the bounded candidate scan; pagination runs
after readiness and preapproval filtering. This is a discovery aid, not
permission to approve or execute a change. The preapproval service rechecks
the exact Tool version, contract and runtime state when evaluating a plan.

## Readiness model

Every current published Artifact version is represented once. The Catalog
reports three separate dimensions instead of collapsing them into one status:

- `readiness`: `ready`, `blocked`, or `declarative`;
- `activation_state`: `active`, `inactive`, or `not_required`;
- stable `blockers`, such as `activation_required`, `dependency_drift`,
  `tool_registration_disabled`, or `mcp_server_disabled`.

`ready` means the executable contract passes the same current compatibility
rules used by its runtime and any required activation is live. `blocked` means
the published Artifact remains discoverable but must not be presented as
operator-ready. `declarative` identifies published Parser, Visualization, or
Report contracts that do not yet have a platform execution runtime.

The projection is kind-aware:

| Kind | Contract check | Activation check |
|---|---|---|
| Collector | Collector definition, adapter, runtime, and output kinds | At least one enabled deployment |
| Tool | Canonical MCP Tool contract and live registry binding | Active MCP activation, enabled Tool Registry entry and server, current protocol, policy-allowed endpoint, usable credential profile, matching handler/schema hashes |
| Skill | Published Skill contract and exact current Tool dependency snapshot | Not required; a Skill starts explicitly |
| Workflow | Published graph contract and exact current Tool dependency snapshot | Alert and schedule workflows require their matching enabled activation; manual workflows do not |
| Topology | Canonical immutable topology-view contract | Not required; publication exposes the governed view |

Counts, required permissions, dependency count, runtime name, and bounded
kind-specific summaries are returned for operator explanation. This endpoint
does not return Artifact definitions, implementations, test fixtures, Tool
schemas, deployment targets/configuration, credentials, or raw compatibility
exceptions.

## Provenance and safe projection

Signed imports expose only their algorithm, key fingerprint SHA-256, and
verification time. Artifacts installed through a verified organization pack
also expose the pack name, version, and digest, never its definitions or test
fixtures. Unsigned local publications are labelled as local origin. The content
hash is always visible so an operator can correlate the Catalog entry with an
immutable version.

Artifact `labels` are arbitrary input and therefore are not copied into the
Catalog. Only a bounded `labels.tags` allowlist of short strings is projected;
values containing common secret/key/token/credential terms are omitted. Runtime
failures are classified into stable blocker codes, not returned as internal
exception text.

## User interface

`/studio/catalog` is a supporting Studio page, not another panel on the AI L1
home. It provides:

- search and kind/readiness filters;
- ready, blocked, active-binding, and signed-origin summaries;
- per-capability activation, dependencies, permissions, bounded runtime facts,
  content hash, ownership, and provenance;
- explicit execution blockers with links back to the Artifact Library and MCP
  Gateway for remediation.

This keeps authoring history, runtime readiness, rollout operations, and the L1
operator workspace as separate information layers.

## Acceptance boundary

Automated coverage proves safe response projection, query/filter/pagination
bounds, inactive Tool blocking, active MCP binding readiness, transitive Skill
dependency drift after a Tool Registry entry is disabled, and signed-pack
provenance after a separately installed Artifact is published.

The first organization distribution boundary is available at
`/studio/catalog/packs`. A trusted `icheck.capability-pack.signed/v1` document
is verified, checked against platform API `icheck/0.1`, and previewed with exact
content-hash dependencies before installation. Installation is idempotent and
transactional across all embedded Artifacts; any target validator failure rolls
the entire pack back. Existing exact versions may be reused, while name/content
conflicts fail closed. Imported versions remain `validated`. A valid signature
never publishes, activates, deploys, or executes anything.

Installation now binds the whole selected tenant/region transaction, including
non-enforcing service callers. Namespace-local lineage/digest locks serialize
competing installs and signed revocations; current signer/domain authority is
refreshed and held until commit. Signer and rotation-proof expiry are checked
again after Artifact validation. Exact retries release their locks and return
one installation/audit outcome. A post-commit response error is preserved for
retry rather than masked by rollback of an already-committed Session.

The same preview/install API handles compatible signed upgrades. A successor
must name the current predecessor digest in its signed payload, advance the
semantic version, retain signer identity, and modify only Artifacts actually
introduced by that lineage. The transaction creates target-revalidated
versions on the existing Artifact identities and records `upgraded`
provenance, but leaves publication and every runtime binding untouched.

The pack ledger also provides preview-first compatible uninstall. Only the
current active lineage head can be removed; preflight rejects known active
successors and exact downstream pack dependencies. Successful uninstall retains the immutable
signed ledger while deprecating only versions introduced by that installation
and atomically stopping their runtime bindings. Retained and reused versions
remain untouched. Removing an upgrade restores its installed predecessor as
the lineage head; an entirely removed lineage accepts only a higher,
same-signer successor of the latest tombstone, never replay of the removed
digest.

Uninstall and install/upgrade share namespace-local lineage and digest locks.
Locked installation reads refresh lifecycle state, so a cached Session cannot
report a removed digest as successfully reinstalled or replace the original
uninstall operator/time. Exact uninstall retries release transaction locks and
retain one tombstone/audit outcome. Pre-commit database loss rolls back the
tombstone; a post-commit response error leaves it durable and replayable.
Uninstall also requires PostgreSQL `READ COMMITTED` with autocommit disabled
and binds the full selected namespace, including non-enforcing service callers.
Constraint conflicts after installation rollback fail closed instead of
returning an existing row without renewed authority/lifecycle checks.

Artifact creation/version allocation, validation and publication, pack admission,
uninstall and advisory quarantine now share namespace-local Artifact identity
locks. Complete identity batches are sorted before version row locks; external
dependency reads share locks while embedded/reused Artifacts and lifecycle
mutations take exclusive locks. A waiting consumer refreshes its exact version
state after admission. Unrelated identities and matching identities in another
namespace do not share a global write lock.

Publication refreshes its candidate and existing head, preventing cached state
from resurrecting a removed version. Before retiring a published head it checks
the latest installed head of every pack: exact external dependencies and reused
versions block retirement until their consumers migrate or are removed.
Uninstall likewise recounts dependent installations while holding the Artifact
boundary. Signed revocation remains a forced containment operation, not a
consumer-authorized retirement.

An exact retired or revoked origin cannot be repackaged as a reusable capability;
preview returns `unavailable` with `artifact_version_unavailable`. A compatible
higher same-lineage release may revalidate an identical retired candidate into
a new version instead of retaining the deprecated row. This never publishes or
executes the new candidate. Raw Artifact publication still rejects an already
published candidate; reconcile a lost response through its current version and
audit state instead of expecting another publication decision.

Studio generation now binds its exact candidate before releasing the Artifact
identity lock, retains failed drafts, and uses durable request ownership across
model calls and recovery. Its tested authoring boundary is documented in
[Capability Studio](./capability-studio.md); raw aggregate-returning creation
remains a lower-level API, not an authoring retry contract.

The bounded database acceptance does not accept every publisher authority/time
mutation, live transport, server
failover or production scale. Manual multi-Artifact promotion uses the same
batch boundary; see [governed promotion](./capability-promotions.md).

The same supporting page accepts admin-authorized
`icheck.capability-pack.revocations.signed/v1` feeds and shows their immutable
ledger, exact revoked digests, reason codes, and bounded quarantine counts.
Revoked installed packs are visibly marked. The backend blocks future install,
deprecates versions introduced by the pack, disables their executable
bindings, invalidates Collector leases, and prevents republish/canary bypass in
one transaction. Exact versions only reused by a revoked pack are not
quarantined on that pack's behalf.

Signed remote organization-catalog discovery is available at
/studio/catalog/remote. It pins catalog identity, HTTPS host, and trust key;
accepts only bounded, unexpired, monotonically sequenced signed indexes; and
projects metadata plus local install/revocation/trust compatibility. An
operator can then request a governed preview and installation: both independently
fetch and verify the full signed pack against the current pinned entry, while
installation stores immutable distribution provenance and stops at validated.
Trust-key distribution/rotation, external transparency witnesses, and signed
cross-environment promotion receipts are implemented. Promotion qualification
does not bypass Catalog publication/readiness gates. See
[the remote catalog contract](./remote-capability-catalogs.md).
