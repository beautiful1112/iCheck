# Independently retrieved Report archives

An operator acknowledgement records an external object reference; it does not
prove that a copy exists. New purge requests require a separate iCheck-generated
`https_exact_bytes` verification receipt. The control plane retrieves the whole
package from a configured source and hashes the actual returned bytes. It does
not accept a caller's verification flag, remote checksum header or digest-only
attestation as proof.

## Complete package and external gateway

`GET /api/v1/reports/instances/{id}/archive-export` returns canonical
`icheck.report.archive/v1` JSON, capped at 22 MB. It includes:

- the namespace-bound saved-instance material and its snapshot digest/size;
- every retained attachment's exact manifest and base64-encoded immutable bytes;
- stable ordering by attachment ID, with canonical JSON encoding.

Current visibility, Report provenance, snapshot integrity and attachment hashes
are checked before export. Existing files are not rerendered. The response has
`Cache-Control: no-store`, an attachment filename, snapshot identity and a
SHA-256 of the whole package. The browser independently checks that byte digest
before download. The ordinary JSON Report export is not a substitute for this
complete snapshot-plus-documents package.

Store these unchanged bytes outside iCheck under the acknowledged object
reference. A vendor adapter/gateway implements:

```text
GET https://<configured-origin>/v1/report-archives/<reference>/content
Authorization: Bearer <server-resolved-token>
X-Icheck-Tenant-ID: <selected-tenant>
X-Icheck-Region-ID: <selected-region>
Accept: application/json
Accept-Encoding: identity
```

It returns HTTP 200 with uncompressed `application/json` and the exact package
bytes. The gateway must enforce its own identity, object/namespace authorization
and external storage policy. iCheck only reads this endpoint: it does not upload
archives, configure buckets, manufacture vendor receipts or enable retention
deletion jobs.

## Source administration and verification

`/settings/report-archives` creates server credential references and registers
immutable origin/profile bindings. A profile must be enabled, namespace-local,
permit `report_archive`, and have no Worker selector. Tokens stay server-side;
Vault is supported, including lease-scoped resolution and cleanup on success or
failure. Environment references are a local-development option, not a reason to
put token values in the browser.

The origin must be HTTPS, match an exact host in
`ICHECK_REPORT_ARCHIVE_ALLOWED_HOSTS`, and contain no path, query, fragment,
inline credentials, whitespace or controls. TLS verification is enabled.
Redirects and ambient proxy settings are disabled; each reference is a bounded
object ID, never a supplied URL or filesystem path. Retrieval has a ten-second
socket timeout, a fifteen-second monotonic read budget (plus at most one bounded
socket operation), and a streaming byte ceiling equal to the approved package.
Compression, incomplete transfers, incorrect media types, changed lengths and
digest mismatches fail closed.

```text
GET  /api/v1/reports/archive-sources
POST /api/v1/reports/archive-sources
POST /api/v1/reports/archive-sources/{id}/state
POST /api/v1/reports/instances/{id}/archive-verifications
GET  /api/v1/reports/instances/{id}/retention
```

Source writes require namespace-wide `auth.admin` and `services.manage`. Source
names are unique only inside that tenant/region. Origin/profile changes require
a new source, not editing an accepted binding. Enabled-state changes use an
expected revision. Verification requires namespace-wide `services.manage` and
`services.read`, and names the acknowledgement, source and a human reason.

After a successful fetch, the control plane acquires accounting/source/credential
locks, discards cached ORM values, and rechecks the retained package and source
binding. A concurrent attachment, source-state or credential revision change
prevents a receipt. Immutable receipts pin the package digest/size, attachment
manifests, source binding, source/credential revisions and observation time.
Repeated verification creates another read-only observation; it is not a remote
write. Failures create hash-only audit evidence and no verification receipt.

## Reviewed deletion

New purge requests bind both `archive_acknowledgement_id` and
`archive_verification_id`. Request and separate-principal approval recheck the
exact current package, source, holds and protected references. A new attachment
invalidates a snapshot-only or older complete package's coverage.

Execution always retrieves the external object again. Network I/O happens
before namespace accounting and source locks, then all approval, provenance,
archive, source/credential revision, hold and reference checks are repeated
under the deletion transaction. Missing/substituted external bytes, late holds
or new documents leave the snapshot, approval and quota intact. Only successful
revalidation allows atomic local deletion and quota reclaim. The durable
tombstone pins the original verification receipt and the new retrieval time.
An exact executed-request retry returns the tombstone without another fetch.

An approved request may be rejected by an authorized principal distinct from
its requester. This withdraws an unsafe approval and permits a new request after
updated archive verification; it does not delete anything. Prior decisions
remain in audit history.

## Migration and verification limits

Migration `f8g0i2k4m6p9` adds sources, receipts and nullable historical purge
bindings with PostgreSQL namespace RLS. Old acknowledgements stay
`operator_asserted`; old tombstones retain null verification/time fields and are
not retroactively called verified. Pending assertion-only approvals cannot
execute; reject them and obtain a new verified request/review. Empty new tables
allow downgrade, but configured sources or verification history refuse it.
PostgreSQL downgrade must be able to inspect every namespace, not an RLS-hidden
subset.

Local regression tests exercise exact snapshot/document bytes, substituted and
truncated/oversized/protocol-invalid responses, lease cleanup, unsafe origins,
two tenants/three regions, legacy approval refusal, and changes during execution.
Real SQLite Alembic tests preserve legacy history and guard downgrade. Browser
validation uses isolated mock APIs; it is not live vendor acceptance or the
integrated demo.

V2 archive packages retain the exact typed source/closure record inside the
saved-instance v2 wrapper and include original JSON attachment bytes. Archive
source administration is separate from the report reader and independent purge
reviewer. The proof-delivery acceptance (private development evidence; not distributed)
verifies all three record kinds through retrieval, independent review and purge
under the migrated non-owner PostgreSQL runtime. Native cascade removes only
the report admission/reference ledgers and accounting; domain proof remains.
Delivered reports remain pinned by Investigation evidence and delivery receipts.

A receipt proves byte equality at the observed source and time, not independent
physical storage, external WORM retention, durability, future availability or a
provider signature. Live gateway/Vault authorization and storage-policy
acceptance, PostgreSQL concurrency/RLS and backup/restore remain production
gates. Automatic expiry remains unimplemented and disabled.
