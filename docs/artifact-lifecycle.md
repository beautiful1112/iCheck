# Artifact lifecycle and portability

## Implemented controls

iCheck Artifact versions now support bounded semantic comparison,
integrity-checked and optionally signed portable bundles, target-environment
revalidation, immutable restore candidates, historical replay, bounded
Collector canary promotion, and governed fleet replacement/rollback.

### Semantic diff

```text
GET /api/v1/artifacts/{artifact_id}/diff
    ?from_version=1&to_version=2&limit=200
```

The comparison covers definition, implementation, tests, Artifact kind, and
the portable CollectorDefinition contract. Object keys are stable and named
lists such as workflow nodes, fixtures, and field mappings are compared by
their semantic identifier instead of only by array position. Results are
limited to at most 500 changes, stop at a fixed recursion depth, and replace
individual values larger than 2 KiB with their SHA-256, size, and type.

### Portable bundle

```text
GET  /api/v1/artifact-versions/{version_id}/export
POST /api/v1/artifact-imports
```

Only validated, published, or deprecated versions can be exported. The
`icheck.artifact.bundle/v1` document contains the complete executable or
declarative contract and source content hash, but excludes validation reports,
database-generated child IDs, timestamps, deployment state, credentials, and
conversation history. Bundles are limited to 5 MB.

Export adds a canonical bundle digest. Import verifies both the bundle digest
and the source content hash before creating anything, rejects unknown fields,
applies inline-secret checks, generates new target-environment IDs, and runs the
current deterministic validator again. The imported version remains validated;
publication is a separate human action.

The SHA-256 digest proves integrity, not publisher authenticity. Do not treat
an unsigned bundle as trusted merely because its digest is internally
consistent.

### Signed bundle envelope and provenance

```text
POST /api/v1/artifact-trust-keys
GET  /api/v1/artifact-trust-keys
POST /api/v1/artifact-trust-keys/{key_id}/revoke
POST /api/v1/artifact-signed-imports
GET  /api/v1/artifact-versions/{version_id}/signature-verification
```

An external CI system, vendor, or organization signing service may wrap the
portable bundle in `icheck.artifact.signed-bundle/v1`. The signature is Ed25519
over the domain-separated canonical message
`icheck.artifact.signed-bundle/v1\n{bundle_digest}`. iCheck stores only the
canonical public key, its raw-key SHA-256 fingerprint, trust-key lifecycle
metadata, and successful verification provenance. It never accepts or stores a
private signing key and exposes no server-side signing endpoint.

Import first verifies the declared digest and signature against an enabled,
non-revoked trust key. It then executes every ordinary bundle check: canonical
digest, source content hash, unknown-field and inline-secret rejection, new
target IDs, and current deterministic validation. A valid signature never
publishes or activates the imported version. The version remains `validated`,
is labeled with the verified fingerprint and bundle digest, and receives an
immutable verification record with verifier identity, time, signature hash,
and trust-key reference.

`ICHECK_ARTIFACT_SIGNATURE_POLICY=optional` accepts both unsigned and verified
signed imports. `required` rejects the unsigned import endpoint, allowing an
organization to enforce trust at the control-plane boundary. Revocation blocks
future imports but does not rewrite historical verification evidence.

### Signed organization capability packs

```text
POST /api/v1/capability-packs/preview
POST /api/v1/capability-packs/install
GET  /api/v1/capability-packs
GET  /api/v1/capability-packs/{installation_id}
GET  /api/v1/capability-packs/{installation_id}/uninstall-preview
POST /api/v1/capability-packs/{installation_id}/uninstall
UI   /studio/catalog/packs
```

`icheck.capability-pack/v1` carries 1–20 ordinary portable Artifact bundles,
an exact `icheck/0.1` platform API, a semantic pack version, and up to 200 exact
kind/name/content-hash dependencies. An external organization signing service
wraps it in `icheck.capability-pack.signed/v1` and signs the domain-separated
message `icheck.capability-pack.signed/v1\n{pack_digest}` with Ed25519. iCheck
stores no private key and accepts only an enabled Artifact trust key.

Preview verifies the pack digest, signature, every embedded bundle digest and
content hash, local name conflicts, platform compatibility, and dependencies.
A dependency is satisfied by the same signed pack or an exact currently
published local Artifact version. The response contains only identities,
hashes, stable states, and blockers—not definitions, implementation, tests,
credentials, or targets.

Install repeats every check and creates all missing Artifacts inside one
database transaction. Each target-environment validator still runs; one
failure rolls back the installation record and every Artifact created earlier
in the pack. Exact existing non-draft versions are reused and recorded. The
pack name/version and digest are unique, so retrying the same digest is
idempotent while same-version substitution fails closed. Every installed or
reused version receives durable pack provenance.

A later pack with the same name is treated as an upgrade only when its signed
manifest includes `predecessor_digest_sha256` for the current installed head,
its semantic version has strictly greater precedence, and its enabled signing
key fingerprint matches the predecessor or the pack embeds an explicit
dual-signed rotation. A rotation statement binds pack name, exact predecessor
digest, old/new fingerprints, and a validity window of at most 24 hours; both
enabled keys sign the same statement and the successor pack itself is signed
by the new key. The verified statement and signature hashes are retained in
the installation ledger. This prevents a different trusted publisher, stale
branch, replayed delegation, or version rollback from taking over an existing
pack identity.

Upgrade planning may create a new version only on Artifacts the predecessor
chain actually introduced (`installed` or `upgraded`). An Artifact the prior
pack merely reused is not pack-owned and cannot be modified by its successor.
New names are installed normally. Exact predecessor-owned content is recorded
as `retained`, so ownership survives an unchanged intermediate release without
pretending that release introduced the version; unrelated exact content is
`reused` and remains outside the lineage. The predecessor row is locked and
rechecked before writes; all new Artifact versions and the lineage ledger
commit together or roll back together. Upgrade versions end at `validated`,
so the currently published version, deployments, activations, schedules, and
running fleet remain unchanged until their normal governed lifecycle decisions.

Installation ends at `validated`. Publication, MCP activation, Collector
deployment, Workflow scheduling, and Tool execution remain separate governed
operations. Runtime-specific validation may therefore require that an external
Tool dependency is already registered and active in the target environment.

The same install boundary can be reached from a current signed remote catalog
entry. Remote preview and install independently fetch the pack and require an
exact match to the catalog-pinned digest, signer, identity, predecessor, and
counts before the ordinary verification above runs. Remote installations add
the immutable catalog/source/snapshot/entry/sequence/index-digest provenance
to the installation ledger; browser upload installations remain labeled
`upload`. See [remote capability catalogs](./remote-capability-catalogs.md).

Successful install/upgrade, signed revocation-feed ingestion, and compatible
uninstall also advance the same transactional
[capability transparency chain](./capability-transparency.md). This exposes a
stable cross-ledger sequence and checkpoint without placing pack or Artifact
implementation bodies in the transparency stream.

### Compatible capability-pack uninstall

Uninstall is a lifecycle tombstone, never a physical delete. A
manage-authorized operator first previews the exact installation. The preview
exposes stable blockers and bounded impact counts but not Artifact
implementations. It fails closed when the pack has an active signed successor
or another installed pack references one of its introduced versions through
exact dependency or reuse provenance.

Execution locks and rechecks the installation, requires its exact digest, and
performs one transaction. Versions introduced by that installation
(`installed` or `upgraded`) become `deprecated`; `retained` and `reused`
versions are untouched. Collector leases and deployments, canaries, MCP
activations, Workflow dispatch, active Skill/Workflow investigations, Service
Indicator bindings, and Situation integrations bound to removed versions are
stopped through the same quarantine primitive used by signed revocation. The
signed origin, per-Artifact provenance, human reason, impact summary, and audit
event remain durable.

Only the active lineage head may be removed. Removing an upgrade makes its
still-installed predecessor the active head again. If no active version
remains, an exact digest replay stays blocked, but a higher signed successor may
name the latest tombstoned digest and recover the lineage under the same signer
and Artifact-ownership rules. Uninstall never restores a previously deprecated
runtime binding automatically.

### Signed capability-pack revocation feeds

```text
POST /api/v1/capability-pack-revocations
GET  /api/v1/capability-pack-revocations
GET  /api/v1/capability-pack-revocations/{feed_id}
UI   /studio/catalog/packs
```

An organization security authority publishes
`icheck.capability-pack.revocations/v1` with a monotonically increasing
per-key sequence, issue time, and 1–500 exact pack digests. Each entry has an
immediate effective time and one bounded reason code: `compromised`,
`malicious`, `vulnerable`, `policy_violation`, or `superseded`. The authority
wraps the document in
`icheck.capability-pack.revocations.signed/v1` and signs the domain-separated
message
`icheck.capability-pack.revocations.signed/v1\n{feed_digest}` with Ed25519.

Ingestion requires global `auth.admin`; reads require global
`capabilities.read`. iCheck verifies the canonical digest, enabled trust key,
signature, timezone-bearing timestamps, immediate-effect policy, and strictly
increasing sequence before changing state. Identical signed sequence replay is
idempotent. Sequence rollback, same-sequence substitution, unknown fields,
future activation, invalid signatures, and digest tampering fail closed.

Feed acceptance and quarantine occur in one database transaction. A revoked
digest blocks pack preview/install. Artifact versions introduced by that pack
(`install_action=installed|upgraded`) are deprecated; exact versions merely
retained or reused by the pack are not newly attributed to it. The transaction
disables Collector
deployments and invalidates leases, aborts affected Collector canaries,
deactivates MCP Tools, disables alert/schedule Workflow activations and their
future dispatch, cancels active Skill/Workflow Investigations and invalidates
their Agent execution leases, and disables Service Indicator and Situation
integration bindings. Publication and canary admission also consult the
durable revocation ledger, so an operator cannot reactivate a quarantined
version through an ordinary lifecycle endpoint.

The feed, signature provenance, human reason, entries, audit event, and bounded
quarantine counts are retained. Raw signing keys and Artifact implementation
payloads are not stored in the feed ledger. Revocation is irreversible: deploy
a fixed capability as a new signed pack digest and pass its normal
publish/activation gates. Revoking an Artifact trust key and revoking a pack
digest remain distinct operations—the former blocks future signature trust;
the latter is the explicit runtime quarantine event for already installed pack
content.

Trust keys can be locally pinned or reconciled by a signed
[organization trust bundle](./organization-trust-distribution.md). All
signature consumers enforce a purpose specific to their contract plus key
validity and current trust-domain state; registering or distributing a public
key no longer grants it an implicit cross-purpose signing role.

### Immutable restore candidate

```text
POST /api/v1/artifacts/{artifact_id}/restore-candidates
```

A restore never changes history or directly flips the published pointer. It
copies a selected non-draft version into the next version number, reruns current
validation (including sandbox fixtures or live Tool Registry dependency checks),
proves the resulting content hash matches the source, and records the reason in
audit. The candidate is left in `validated` state. A separate publish action
deprecates the current version and promotes the candidate.

All portability, diff, and restore endpoints require both the relevant
capability permission and global authorization scope.

### Historical Collector replay

```text
POST /api/v1/artifact-replay/artifacts/{artifact_id}/cases
GET  /api/v1/artifact-replay/artifacts/{artifact_id}/cases
POST /api/v1/artifact-replay/cases/{case_id}/runs
GET  /api/v1/artifact-replay/cases/{case_id}/runs
```

A replay case stores up to 200 sanitized, normalized pre-transform envelopes,
the corresponding golden output envelopes, and non-secret configuration. It
is immutable and bound to one Collector Artifact. Inline-secret shapes are
rejected and the whole case is limited to 2 MB.

Replay accepts validated, published, or deprecated versions, but never a
draft. The initial runtime supports only `python_sandbox_v1`, so every run uses
the same Landlock/seccomp process isolation as fixture validation and live
generated transforms. It compares ordered output envelopes exactly. The run
record contains counts, content hashes, isolation metadata, and at most 50
index-level hash differences; it does not copy raw input or output into the
response, run record, or audit event. Sandbox errors are persisted by type and
message hash so failed evidence remains traceable without exposing content.

Replay is evidence, not deployment. A passing run does not publish, activate,
promote, or roll out the tested version.

### Bounded Collector canary

```text
POST /api/v1/collector-canary-rollouts
GET  /api/v1/collector-canary-rollouts
GET  /api/v1/collector-canary-rollouts/{rollout_id}
POST /api/v1/collector-canary-rollouts/{rollout_id}/abort
POST /api/v1/collector-canary-rollouts/{rollout_id}/promote
```

The initial canary runtime accepts one validated polling Collector candidate
and creates one explicitly targeted scheduled shadow deployment. The normal
Worker lease, credential-reference, target-schema, configuration-schema, and
worker-selector checks still apply. Validated versions are claimable only when
they are attached to a running canary; ordinary deployments remain restricted
to published versions.

Canary envelopes do not enter `collection_envelopes`. Each accepted batch is
reduced to a SHA-256 plus counts, and a run qualifies only when it succeeds and
meets `min_records_per_run`. The rollout passes after its required number of
qualifying runs, or automatically aborts when its failure threshold or deadline
is reached. Either terminal result disables the shadow deployment. Deadline
reconciliation occurs in the Worker claim loop and rollout reads, so it remains
effective even if the browser is closed.

A passed rollout still requires a reasoned human promotion. Promotion verifies
that the published baseline has not changed, then publishes the candidate and
deprecates the baseline in one transaction. Once a candidate has entered a
canary, the generic Publish endpoint cannot bypass this state machine. The
initial promotion changes Artifact publication state only; it does not mutate
or replace existing fleet deployment records.

Canary administration requires global scope with both `capabilities.*` and
`collectors.*` permissions. The initial runtime excludes event, stream, and
PSRP/CIM Collectors.

### Governed Collector fleet replacement

```text
POST /api/v1/collector-fleet-rollouts
GET  /api/v1/collector-fleet-rollouts
GET  /api/v1/collector-fleet-rollouts/{rollout_id}
GET  /api/v1/collector-fleet-rollouts/{rollout_id}/items
GET  /api/v1/collector-fleet-rollouts/{rollout_id}/rings
POST /api/v1/collector-fleet-rollouts/{rollout_id}/apply-next
POST /api/v1/collector-fleet-rollouts/{rollout_id}/rollback-next
POST /api/v1/collector-fleet-rollouts/{rollout_id}/automation/pause
POST /api/v1/collector-fleet-rollouts/{rollout_id}/automation/resume
POST /api/v1/collector-fleet-rollouts/{rollout_id}/automation/abort
```

Fleet replacement begins only after canary promotion. Planning selects existing
deployments still pinned to that canary's deprecated baseline, optionally
limits them to one site and enabled records, revalidates every deployment
against the published candidate, and persists a canonical SHA-256 plan. The
plan response exposes deployment identity, before/after fingerprints, and
bounded reason codes—not target documents, Collector configuration, credential
material, or raw validation errors.

Deployments governed by an active DeviceConnectionActivation are recorded as
`activation_approval_required` and never mutated by this path. This preserves
the device onboarding preview, fingerprint, and approval boundary. Candidate-
incompatible records are also blocked before execution.

Every apply or rollback request must echo the exact plan hash and a human
reason. Apply locks one configured batch, verifies that the candidate remains
the current published version, rechecks schema/credential compatibility, and
requires the current deployment fingerprint to match the plan. An active lease
or RUNNING run defers the item without revoking Worker ownership. Drift or the
configured cumulative failure threshold stops replacement. Successful changes
modify only the version pointer and runtime lease/schedule fields; all other
deployment configuration remains unchanged.

Rollback is a separate bounded action over only successfully migrated items.
It requires the post-change fingerprint, revalidates the deprecated baseline,
defers active leases, stops on the first rollback failure, and restores the
original version pointer. Per-item errors are stored as stable codes plus
SHA-256 digests, while audit events contain plan/reason hashes and counts only.

An operator may instead create an opt-in automatic plan with strictly
increasing cumulative percentages ending at 100. Planning deterministically
assigns every actionable deployment to one immutable ring; blocked records do
not distort ring targets. A separate region-pinned `icheck-rollout-worker`
holds PostgreSQL advisory-lock leadership and is the only batch writer while
automation is armed. It preserves the ordinary plan hash, drift, lease,
compatibility, and failure checks rather than creating a privileged path.

After a ring is migrated, progression stops for its configured observation
window. Every deployment in that ring must contribute the configured number
of fresh successful Collector runs after observation begins. Failed and
cancelled runs count against a per-ring limit. The controller stores only
bounded counts and a canonical SHA-256 over per-deployment
status/time/count groups. Exceeding the limit pauses closed; it never
automatically rolls back
or asks an AI model to waive the gate. Resume starts a fresh observation
window, while abort returns subsequent application to explicit manual control.
Pause, resume, abort, ring pass, and ring failure transitions are audited.

The production controller is independently deployable with
`deploy/systemd/icheck-rollout-worker.service`. It requires PostgreSQL for
leader election and a fixed tenant/region assignment; no Docker runtime is
required.

## Artifact Library UI

`/studio/artifacts` is the dedicated lifecycle subpage. It keeps version and
portability administration out of the AI L1 home while allowing an authorized
user to:

- select any Artifact and inspect all immutable version statuses and hashes;
- compare two versions with the bounded semantic diff;
- export a validated version as a local `*.icheck.json` bundle;
- select and verify a bundle, optionally rename it, and import it through the
  target-environment validator;
- automatically recognize a signed envelope, verify it through the signed
  import endpoint, and display verified provenance on the imported version;
- create a reasoned restore candidate from an older healthy version; and
- explicitly publish a validated version.

The UI does not weaken the API gates. Restore still creates a new validated
version, import still generates new database IDs, and both publication and
import remain server-authorized operations.

`/studio/replay` is the dedicated historical test surface. It lets a reviewer
choose a Collector, create a sanitized golden case, execute any eligible
immutable version, and inspect bounded comparison evidence without adding raw
captures to the AI L1 home or Artifact Library.

Failed Collector runs, Artifact replay runs, and Skill or Workflow agent
executions can now open an idempotent conversational revision through
`POST /api/v1/capability-studio/sessions/from-runtime`. The revision is pinned
to the exact failing Artifact version and the trusted Studio specification
that produced it. Only bounded counts, status codes, and SHA-256 evidence are
copied into the new session; targets, configuration, runtime inputs, exception
text, credentials, and arbitrary replay output are excluded. The evidence is
explicitly treated as untrusted data. Opening a revision neither invokes a
model nor publishes a change: the operator must request refinement, pass the
ordinary platform validators, and use the normal human publication and rollout
gates.

`/studio/rollouts` is the dedicated rollout surface. It exposes canary health
gates, bounded shadow evidence, deadline/failure state, the publication gate,
immutable fleet impact plans, per-deployment status, next-batch application,
governed rollback, automatic ring evidence, and pause/resume/abort controls
without putting rollout controls on the AI L1 home.

## Remaining lifecycle work

- live vendor recovery-gateway/drill and CI identity-provider acceptance, plus
  external attestation catalogs; verified HSM/KMS
  recovery signing, durable witness,
  quorum-backed regional gossip, promotion delivery with endpoint mTLS
  rotation, and manual atomic promotion publication are implemented.
