# Service-health Report Artifacts

## Implemented boundary

Capability Studio authors metric-only `icheck.service-health-report/v1` and
retained-proof `icheck.service-health-report/v2` Artifacts. Trusted runtime code
calculates normalized service metrics and resolves exact immutable control-plane
records. The AI selects governed indicators and operator-supplied proof references;
it does not write proof narratives, queries, calculations, code, or delivery
configuration. Existing v1 contracts and stored export bytes remain unchanged.

The authoring model receives the same bounded safe indicator catalog used by
service visualizations: service/indicator keys and names, criticality, kind,
unit, threshold direction/values, and whether observations exist. Source
references and queries, contacts, components, observation values, dimensions,
evidence URLs, actors, and credentials remain outside model context.

Trusted code validates the canonical contract and exact selectors, then
computes a preview for one to twenty sections. Each section contains only:

- current value and deterministic threshold/freshness status;
- bounded sample count, minimum, maximum, and arithmetic mean;
- first and last observation time;
- a deterministic improving/degrading/stable trend relative to breach
  direction; and
- explicit no-data, truncation, or dependency-drift state.

No raw time series, dimensions, source observation IDs, queries or ingestion
identities enter metric sections. V2 proof sections intentionally retain the
exact authorized domain record, including its historical relationship IDs.

## Retained proof contract

V2 accepts exact `source_replacement_request`, `source_retirement` and
`situation_closure_receipt` references. A report may contain proof alone or mix
proof with at most twelve metric selectors, within a shared twenty-section
budget. Proof-only reports have unknown health and zero fabricated samples.
The records are historical: they grant no future execution authority and do not
automatically prove repair causality or physical device truth.

The operator selects the kind and UUID in Studio. Model context contains only
those references, not full proof material; substitution or omission is rejected.
Saved reports store a typed v2 snapshot, an immutable initiating-reader admission
and exact foreign-key references. Every read checks persisted current read roles
and both current and capture-time scope. An expanded role cannot enlarge the
original capture scope after a device moves. Old execution gates, peers and
origin attestations are not refreshed merely to read history.

## Lifecycle and runtime

```text
POST /api/v1/capability-studio/sessions/reports
POST /api/v1/capability-studio/sessions/{id}/generate
POST /api/v1/capability-studio/sessions/{id}/messages
POST /api/v1/capability-studio/sessions/{id}/publish

GET  /api/v1/reports
GET  /api/v1/reports/{artifact_id}/generate[?version=N]

POST /api/v1/reports/{artifact_id}/instances
GET  /api/v1/reports/{artifact_id}/instances[?limit=20&after_id=UUID]
GET  /api/v1/reports/instances/{instance_id}
GET  /api/v1/reports/instances/{instance_id}/export[?format=pdf|html|csv|json]
GET  /api/v1/reports/storage
PUT  /api/v1/reports/storage
```

Conversational refinement creates another immutable version. A human must
explicitly publish a validated version. `/reports` lists only current published
service-health report versions whose complete service set is visible to the
caller. Generation requires `services.read`, reapplies current service scope,
revalidates the canonical Artifact and provenance, and resolves current
normalized evidence. Missing and unauthorized reports return the same 404.

The dedicated `/reports` page generates the snapshot on demand and displays
scope, version, content hash, generation time, status, aggregates, trends, and
drift. The Capability Catalog treats this exact Report format as runnable,
declares `services.read`, counts its indicator dependencies, and blocks
readiness when selectors drift. Older unrelated declarative Report Artifacts
remain declarative and are not exposed by this runtime.

## Retained snapshots and document export

`POST /instances` accepts only `version_id` and `request_key`, both UUIDs.
The exact version must be published, canonical, hash-verified, unrevoked, and
fully visible under the authenticated principal's current namespace and service
scope. The server generates a fresh minimized snapshot; it never trusts a
browser-submitted report body, version hash, generation time, or actor. Capture
is a `services.read` operation with an audited, append-only application ledger.
There are no snapshot update, delete, or automatic-pruning endpoints.

The idempotency key is bound to principal identity and tenant/region. A successful
retry returns the same instance with HTTP 200; first capture returns 201.
Reusing that key for another exact version or Artifact is rejected. Lost network
responses can therefore be retried without inventing another historical report.
The UI retains a failed attempt's key until successful capture or version change.

Storage governance is namespace-local. `GET /storage` reports exact retained
instance/byte usage and optional limits; `PUT /storage` requires a global
`services.manage` principal, an expected policy revision, a bounded reason,
and replacement limits (`null` means no limit). The additional
`max_attachment_bytes` limit counts stored rendered documents; older clients
that omit this new field preserve its existing value. A reason digest and
revision are audited. Capture records the canonical snapshot's exact byte size,
serializes quota checks on one namespace policy row, and increments usage in
the same transaction as the immutable instance. A same-key retry consumes no
new capacity. Exceeding either limit returns 507 with no stored report or
counter change. A legacy-data migration backfills sizes and counters before
enabling the policy table; configured limits block downgrade. This is
storage-admission control, not an automatic-deletion policy.
Locked reads refresh cached usage, limits and revision. PostgreSQL mutations
require `READ COMMITTED` with DBAPI autocommit disabled; an old transaction
snapshot or per-statement autocommit cannot bypass admission. Commit-enabled
idempotent retries release accounting locks too, without changing the
caller-owned `commit=False` composition contract.
The `/settings/report-storage` subpage exposes usage and revisioned policy
changes away from the AI L1 home; unauthorized scopes receive 403.

Retention is still indefinite by default, with no background pruning. A
separate `/reports/instances/{id}/retention` page and namespace-scoped API now
provide explicit archive acknowledgement, legal hold, purge request, independent
review and execution. The acknowledgement pins the snapshot digest, size and
version to an external archive reference, and remains **operator-asserted**.
A separate `https_exact_bytes` receipt now requires actual retrieval and hashing
of the complete snapshot-plus-attachments package from an allowlisted,
credential-bound HTTPS source. New requests bind that receipt; execution
fetches the external bytes again before deletion. This verifies observed byte
equality, not external physical independence, WORM policy or future durability.
See [Report archive verification](report-archives.md) for the export/gateway,
administration, migration and failure contracts.
The purge requester and approver must be different authenticated principals;
the hold placer cannot release their own hold. Every transition stores a
reason digest and audit event. A purge is blocked by active holds, pinned Agent
Investigation evidence and delivery receipts, with checks repeated at request,
approval and execution. Database foreign keys protect linked evidence and
receipts against concurrent deletion; the namespace storage-policy row
serializes capture and governance writes. Successful deletion atomically
reclaims usage and leaves a namespace-local tombstone with the snapshot digest,
archive and approval references. The original capture idempotency key cannot
regenerate a purged snapshot. This does not revoke already downloaded copies.
Numeric live Report deliveries reference a Report version. Both inline v2 proof
delivery and saved-attachment delivery pin the exact stored instance in their
receipt; attachment receipts also pin the original document. Pending
Investigations pin the snapshot as evidence. Purging an unreferenced v2 report
removes its report admission/reference ledgers, not the underlying source or
closure record. The real PostgreSQL
database gate now accepts quota/purge contention, non-owner RLS, bounded
failure/retry, a data-bearing accounting backfill and native logical restore.
Live external gateway/Vault/storage policy, production upgrade datasets,
backup encryption/off-site/PITR/HA and capacity remain production gates.

The retention read endpoint requires global `services.read` and either
`services.manage` or `changes.approve`; it shows current blockers and the
post-purge tombstone. Archive acknowledgement, hold placement, purge request
and execution require global `services.manage` plus `services.read`. Approval
requires global `changes.approve` plus `services.read`; hold release requires
global `services.manage` plus `changes.approve`. The API returns 409 for failed
governance checks and 404 for hidden/nonexistent records. Operators enter a
reason for each action; the UI additionally requires typing the full snapshot
ID before irreversible execution. These frontend prompts supplement, not
replace, the server-side authorization and reference checks.

Each instance pins the exact Report version, original generation time, complete
typed snapshot, service membership, SHA256, and canonical byte size. The size
is visible in saved history for storage planning. Snapshot material is canonical
sorted compact ASCII JSON with non-finite numbers forbidden, bounded to 256,000
bytes. The JSON export is `icheck.service-report-instance/v1` for metric-only
snapshots and v2 for retained proofs; recompute its
digest after removing only `content_sha256`. This is an integrity checksum, not
a provider signature or protection against a privileged database operator.
Version provenance and current service ownership are checked on every read and
export, not just when saved. Missing and unauthorized instances return the same
404; invalid stored provenance or content returns 409. Deprecated source
versions remain readable as history while new captures require publication.
Historical reads do not reactivate or execute a deprecated/revoked capability.

History uses namespace/scoped SQL membership filtering before keyset pagination
(creation time plus durable ID), with at most 100 entries per page. Candidate
discovery selects IDs only and checks at most 256 candidates, materializing and
authorizing one snapshot at a time. Unreadable proof records are skipped; public
cursors always name fully authorized records. Budget exhaustion returns an
explicit conflict, never a hidden cursor or a false end-of-history. Agent discovery
uses the same boundary with at most ten results. This bound is not sustained
large-history performance qualification. Current ownership may hide old reports;
v2 capture-time scope also remains a permanent read bound.

All four formats use that saved data, never a fresh query:

- JSON carries the canonical machine-verifiable snapshot and namespace.
- CSV has fixed section/aggregate/provenance columns, UTF-8 with BOM, and formula
  protection for text cells. Negative numeric measurements remain numeric.
- HTML is escaped data with fixed styling, no scripts, external images, active links,
  caller templates, or arbitrary markup; CSP and attachment headers restrict it.
- PDF uses trusted ReportLab layout and an embedded, checksum-verified,
  open-licensed Chinese-capable font. Section headings, metrics and status stay
  together across pages. Unsupported glyphs are visibly identified by Unicode
  code point rather than silently dropped. No remote resource fetching occurs.

HTML/PDF display numbers to eight significant digits; JSON/CSV preserve stored
numeric values. Documents are capped at 4 MB, PDFs additionally at 30 pages.
`X-Icheck-Snapshot-SHA256` identifies the canonical snapshot;
`X-Icheck-Content-SHA256` hashes the actual downloaded bytes, which are different
materials. `X-Icheck-Renderer` identifies the renderer, and for PDFs its
ReportLab version and font checksum. Fixed renderer/version/font inputs produce
repeatable bytes; this is not a cross-library-version byte compatibility promise.
Exports use authenticated, namespace-bound reads, `no-store`, `nosniff`, safe
server-generated filenames, and hash-only export audit records. Authorization
must still be checked regardless of cache validators; no token is placed in a
download URL. The browser checks snapshot identity and the document-byte digest
before download and requires HTTPS or localhost for secure browser crypto.

`/reports` separates live preview, fresh capture, saved history and exports.
Opening history or exporting does not regenerate observations. Capture explicitly
replaces the displayed live preview with the newly saved result. This is a
dedicated inspection workspace, not a new dashboard on the AI operator homepage.
An exported local file cannot be withdrawn by a later ownership change; handling
and access controls outside iCheck remain the recipient's responsibility.

Offline visual fixtures can be regenerated without starting the product:

```bash
python -m icheck.report_samples
pdftoppm -png output/pdf/service-report-synthetic.pdf tmp/pdfs/service-report
pdftoppm -png output/pdf/service-report-long-cjk-synthetic.pdf tmp/pdfs/service-report-long
```

These visibly synthetic fixtures are layout checks, not live lab acceptance.
The font's upstream commit, source/bundled checksums, reproducible weight
instantiation command, copyright and SIL OFL license ship in
`icheck/assets/report_fonts/`. Packaging acceptance includes isolated installed
wheel PDF generation so source-tree fonts are not an undeclared dependency.

## Scheduled delivery composition

A schedule-triggered published Workflow may now bind one exact published
service-health Report version to one typed input key. Every occurrence
generates its snapshot under the current run-as principal and scope,
validates the combined Workflow input, and may pass it only to a
directly bound state-changing MCP Tool dependency. The ordinary Workflow
approval, post-check, rollback, durable outbox, retry, and dependency-drift
controls remain mandatory. Static input cannot override the generated key. A
validated Tool-output mapping creates an immutable delivery receipt only when
the exact Workflow reaches its completed terminal checkpoint with actual
successful producer and subsequent post-check execution evidence and no
rollback; the receipt pins
Report/Workflow hashes, occurrence, Investigation, ToolCall, provider, external
delivery ID, and optional safe URL/status.

Inline v2 delivery stores the snapshot before Investigation creation and injects
`icheck.workflow-retained-report/v1`: the saved instance/version identity plus
the exact JSON snapshot. Capture, accounting, proof ledgers and Investigation
evidence commit together. Activation preview stores nothing, and retrying a
dispatched occurrence does not regenerate historical proof. Every fixed Tool
consumer, including post-check and rollback, rechecks live read authority and
the exact saved input before external I/O.

Workflow Agent loops receive a separate references-only model context, never
the inline proof body or initiating-reader admission. Each model turn rechecks
the scheduled report's saved evidence binding, exact input and live scope.
The core proof Tool may return bounded authorized facts when explicitly called;
fixed delivery nodes still consume the unchanged approved snapshot. Nested
report-reference bindings are also subject to the full report read boundary.

Activation can also select `report_attachment_format`. Each occurrence then
atomically stores a snapshot, its rendered document and an Investigation
evidence link. Workflow input carries only the fixed document's manifest;
the adapter retrieves its original bytes through an independently authenticated
API. Send and post-check must both confirm the approved document digest.
The receipt pins snapshot and document identities. Saved metric-document
receipts export as v2; inline or document-based retained-proof receipts export
as `icheck.report-delivery-receipt/v3`. Receipt lists and exports reapply source
snapshot visibility and use `no-store`.
A separate namespace document-byte quota bounds this storage. See
[saved report attachment delivery](./report-attachment-delivery.md) for the
contract, adapter client, transaction and retention behavior.

The schedule pins an immutable version rather than resolving “latest.” Report
deprecation, provenance/contract failure, loss of scope, schema drift, or Tool
dependency drift fails closed before an Investigation is created. Capability-
pack revocation/uninstall also disables schedules that reference an affected
Report version. See [governed scheduled report delivery](./report-delivery-schedules.md).

## Deliberate limits

This slice is not a general report builder. Built-in SMTP/email delivery,
arbitrary prose, cross-source joins, PromQL/SQL, custom calculations, alert
mutation, and automatic publication are not implemented. PDF/HTML/CSV/JSON
downloads do not prove delivery and do not create a delivery receipt.
Scheduled delivery is composed through an exact-version
governed Workflow and separately activated MCP output adapter; delivery
credentials and vendor templates do not enter this Artifact.

Retention defaults to retain indefinitely with no automatic deletion.
Storage quotas, complete external archive byte verification and explicit
archive/hold/reviewed-purge controls are implemented. Policy-driven expiry,
live archive gateway/storage acceptance and live vendor attachment adapters
remain production gates. Agent-native saved
snapshot discovery/read Tools now use `reports.list_saved` and
`reports.get_saved`. The Agent discovers at most ten scoped instances per page
and reads one exact instance as bounded numeric sections. Both Tools recheck
source/version/snapshot integrity and current ownership, including before a
persisted Tool result is replayed. Titles, descriptions, display names,
private source references, PDF/HTML bytes and report templates do not enter
the model result. Evidence pins the instance ID and digest and labels the
values historical. Service keys and Artifact kind/name identities are now
tenant/region-local. An Alembic migration preserves existing IDs and records,
allows duplicate names across namespaces, and rejects same-namespace duplicates.
Signed capability-pack name/version and digest uniqueness follow the same scope.
Downgrade fails closed if cross-namespace duplicates cannot fit the old schema.

Automated coverage verifies safe model context, canonical publication,
deterministic aggregates/trends, scope hiding, minimized output, runtime drift,
Capability Catalog readiness, governed schedule composition, immutable-instance
retries/history, current ownership changes, authenticated non-default tenant and
region isolation, integrity/provenance failures, safe document rendering,
CSV/HTML/PDF injection rejection and maximum-size Chinese PDF pagination.
Browser component checks use isolated synthetic responses, not a live demo. Live data
quality and delivery adapters remain lab/product gates.

## Verification update - 2026-10-02

- Saved-document delivery now passes API and real approval/resume/rollback graph
  tests with an HTTP adapter fixture and the reusable retrieval client. Coverage
  verifies stable bytes across renderer changes, digest/header/size/redirect
  rejection, current ownership/identity/permission changes, pending and receipt
  references, quota admission/reclaim, preparation/start rollback, v1/v2 export
  checksum material and guarded legacy-schema migration. The Workflow designer
  receives the strict manifest contract without document bytes. The attachment
  migration has a single head, `d6e8g0i2k4m7`. Frontend lint, TypeScript and
  production build passed; no live vendor delivery or integrated demo ran.
- Explicit report retention now has authenticated two-principal API coverage for
  archive acknowledgement, hold placement/release, independent purge approval,
  late hold and Agent evidence blockers, receipt blockers, digest/size-bound
  tombstones, exact quota reclaim and prevention of old-key recapture. The
  legacy Agent evidence migration backfills exact namespace-matched references;
  both new migrations refuse destructive downgrade while governed history or
  linked references remain. The dedicated retention page passes frontend lint,
  TypeScript and production-build checks. A later slice now implements actual
  complete-package retrieval and byte hashing with execution-time refetch;
  live PostgreSQL concurrency/RLS and external archive gateway acceptance are
  still not complete.
- Namespace-local instance/byte quotas have API and migration coverage for
  exact-byte accounting, idempotent retries, 507 rejection, revision conflicts,
  site-scoped denial, current usage isolation, legacy backfill, and guarded
  downgrade and re-upgrade while preserving membership rows. The dedicated
  settings page passes lint, TypeScript no-emit and production build checks.
  Live PostgreSQL contention and crash acceptance remain open.
- Full backend suite: 447 tests passed, including scoped Agent discovery/read,
  persisted-result replay after ownership changes, authenticated same-name
  tenant/region authoring, and actual Alembic upgrade from legacy rows.
- The new migration preserves legacy service, Artifact and pack records;
  cross-namespace duplicates are accepted, same-namespace duplicates rejected,
  and downgrade refuses incompatible duplicate names without deleting records.
  This SQLite acceptance does not replace PostgreSQL concurrency/RLS testing.
- Same pack payload installs independently in two authenticated tenants with
  distinct trusted signatures, distinct Artifact IDs and distinct transparency
  log IDs. A separate migration preserves legacy transparency rows and refuses
  downgrade after cross-namespace sequence/digest duplicates. PostgreSQL
  first-writer races and external-witness deployments still need live checks.
- `git diff --check` passed. No integrated demo or live lab acceptance was run.

## Verification record - 2026-09-30

- Full backend suite: 414 tests passed (13 new snapshot/export tests).
- Frontend: ESLint with no warnings, TypeScript no-emit check and production
  build passed.
- Browser component check: version-pinned live preview, exact-version capture,
  saved-history read, successful JSON byte verification/download, and corrupted
  byte-digest rejection passed with synthetic API responses. Saved-report
  layout was inspected. This was not integrated product/lab execution.
- PDF visual check: all eight final fixture pages (one typical, seven maximum-
  section Chinese pages) were rendered and inspected after section-pagination
  correction. The same installed-wheel renderer produced the identical long
  fixture SHA256 `EXAMPLE_SHA256`.
- Actual Alembic upgrade from the older receipt schema through then-head
  `x0y2a4c6e8g1` passed the complete model-column comparison. This is a SQLite
  migration/data-shape check, not live PostgreSQL FK/RLS acceptance.
- Dependency consistency and `git diff --check` passed. An isolated installed
  wheel verified the report renderer and checksum-verified licensed font;
  Alembic migrations are distributed with the source deployment tree.

Production backup/recovery policy, real normalized data quality, live external
archive/Vault/storage policy, real delivery adapters, and the
overall demo release gates are still required. Nothing in this record marks
the complete product or integrated demo ready.

## PostgreSQL database verification on 3 October 2026

The combined non-owner PostgreSQL acceptance suite passed 33 tests, including
22 report storage/purge/migration/restore cases. Tests reproduced the cached
quota overspend, stale revision overwrite and stale rejection overwrite before
the locked-state refresh fixes. Exact attachment retries no longer hold the
accounting row after returning. A late legal hold and a real FK-protected
Investigation Evidence insertion both stop deletion without quota drift.
Pre-commit backend termination and post-commit response-loss retry preserve
the correct report/document/tombstone/audit state. The data-bearing quota
backfill and native logical restore preserve canonical bytes, hashes, counters
and permanent purged-key rejection. The full backend regression passed 548
tests. Both runs retain one existing non-failing TestClient warning.

These database tests use a controlled archive gateway and fixture data, not
live HTTPS/Vault, WORM, external durability, production HA or vendor delivery.
See the PostgreSQL runbook (private development evidence; not distributed). The integrated
demo remains deferred.
