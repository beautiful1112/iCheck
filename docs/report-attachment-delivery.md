# Saved report attachment delivery

A scheduled Workflow can deliver a stored PDF, HTML, CSV or JSON document from
one saved Report snapshot. Configure `report_attachment_format` when activating
the exact published Workflow and Report versions. Metric-only v1 and proof v2
snapshots share this document contract. Omitting the field preserves v1 numeric
input or selects the durable inline-v2 contract described in
[scheduled report delivery](report-delivery-schedules.md). The Workflow, delivery Tool, approval,
verification and rollback contracts still apply.

Each occurrence captures one exact snapshot and renders one document before
starting its Investigation. Snapshot, document bytes, accounting and the
Investigation's saved-report evidence link commit together. A preparation or
Investigation-start failure rolls them back. The capture key derives from the
durable occurrence ID; retrying a dispatched occurrence keeps the original
snapshot and document. Schedule activation validates the real input and
renderer without storing a preview.

The document is stored as bounded binary data, with its snapshot digest,
document digest, byte count, media type and renderer identity. Repeated creation
for the same instance and format returns the existing document. Retrieval uses
those original bytes even after a renderer upgrade. Integrity failure blocks
retrieval rather than silently regenerating a replacement.

## Workflow and adapter contract

The generated input is `icheck.report-attachment/v1`. Its fields are:

| Field | Meaning |
| --- | --- |
| `attachment_id`, `instance_id` | Exact stored document and snapshot |
| `artifact_id`, `artifact_version_id`, `content_hash` | Exact Report provenance |
| `snapshot_sha256`, `document_sha256` | Separate snapshot and document digests |
| `size_bytes`, `export_format`, `media_type` | Expected bytes and representation |
| `renderer`, `filename` | Pinned renderer identity and server-generated filename |

The manifest contains no document body, title, observations, URL or credential.
`ReportAttachmentManifest.model_json_schema()` is the strict input contract.
The in-product Workflow designer receives this schema and instructions to
select an enabled MCP adapter from its Tool Registry. The schedule page offers
the content format alongside the exact Report selector.

The primary Tool must accept the entire manifest through one direct input
binding. Both its send output and the declared read-only post-check output must
expose a string document digest at the same configured path. Activation requires
the `document_sha256` receipt mapping and validates both output schemas. For
example:

```json
{
  "report_input_key": "report",
  "report_attachment_format": "pdf",
  "report_delivery_provider_key": "configured-provider",
  "report_delivery_receipt_mapping": {
    "delivery_id": "delivery_id",
    "document_sha256": "document_sha256"
  }
}
```

Before the send Tool runs, the runtime checks the exact input identity, current
run-as identity, service-read permission, service ownership and stored-document
integrity. The MCP adapter uses its own separately provisioned identity to
retrieve the bytes. That identity must have `services.read` for the complete
current service set in the selected tenant and region. Retrieval authorization
is checked independently on every request. Adapter and vendor credentials stay
in their configured credential stores.

The adapter must confirm the SHA256 of the bytes it actually delivered. Its
post-check must confirm the provider's stored document or equivalent vendor
evidence against that same digest. Missing or mismatched digest evidence marks
the Tool execution as failed and routes through the Workflow rollback path.
Use strict output schemas containing receipt metadata; do not return document
bodies as Tool results. The adapter should use occurrence/Investigation and
attachment identity as its vendor idempotency key.

## Authenticated storage API

| Endpoint | Result |
| --- | --- |
| `POST /api/v1/reports/instances/{id}/attachments` | Save one format; 201 when created, 200 on an exact-format retry |
| `GET /api/v1/reports/attachments/{id}` | Verified manifest |
| `GET /api/v1/reports/attachments/{id}/content` | Original verified bytes |

Creation accepts `{"export_format":"pdf"}`. All endpoints require
`services.read` and complete visibility of the source snapshot. V2 additionally
checks current persisted proof-read roles and capture-time scope; a retrieval
manifest never grants access to its document.
Unknown/cross-scope records return 404; invalid stored integrity returns 409;
quota admission returns 507. Downloads have no token in their URL, use
`no-store`, attachment disposition, `nosniff`, restrictive CSP and separate
snapshot/document digest headers. Downloading does not create a delivery
receipt or authorize deletion.

`icheck.action_adapters.report_attachment_client.ReportAttachmentClient`
provides the adapter retrieval client. It takes a configured HTTPS origin,
access token, tenant and region, fetches only the fixed attachment endpoint,
refuses redirects, bounds the read by the approved byte count, and checks
response identity and the actual byte digest. The origin comes from trusted
adapter configuration rather than a Tool argument or manifest. For example,
inside an adapter with credentials already resolved:

```python
with ReportAttachmentClient(
    configured_icheck_origin,
    access_token=resolved_platform_token,
    tenant_id=configured_tenant,
    region_id=configured_region,
) as reports:
    document = reports.fetch(arguments["report"])
# Deliver document using the adapter's separately resolved vendor credentials.
```

## Accounting, evidence and receipts

Rendered documents are capped at 4,000,000 bytes each. A separate namespace
`max_attachment_bytes` budget and `used_attachment_bytes` ledger count stored
document bodies. Existing instance/byte limits continue to count snapshots;
on-demand exports do not consume the document budget. Creation and purge lock
the same namespace policy row. The storage settings page shows all three
budgets. Older policy clients that omit the new limit preserve its existing
value; explicit `null` removes it.

The Investigation's evidence link protects the snapshot during approval and
execution. A verified terminal receipt pins `report_instance_id`,
`report_attachment_id` and `report_attachment_sha256`, in addition to the
existing producer and verification execution evidence. Its export uses
`icheck.report-delivery-receipt/v2` for metric snapshots and v3 for retained
proof snapshots. Numeric/legacy exports retain their v1
material and digest. Receipt creation rechecks the exact manifest and both
digest results. These are governed adapter claims and Workflow evidence, not
provider digital signatures.

Active holds, Investigation evidence and saved-document delivery receipts block
snapshot purge. An approved purge of an unreferenced snapshot deletes its
documents, reclaims both byte ledgers in the same transaction and preserves
document manifests in the tombstone. Retained delivery receipts cannot be
pruned through this API.

## Verification and remaining acceptance

Automated tests exercise the actual approval/resume/rollback graph with an HTTP
adapter transport fixture, retrieve the original stored bytes through the
adapter client, check digest mismatch rollback, idempotent occurrence recovery,
current ownership and identity changes, stored-byte tampering, admission and
transaction rollback, quota reclaim, portable receipt hashes and migration
history preservation. This is code acceptance with synthetic observations.

The proof-delivery acceptance record (private development evidence; not distributed)
adds all three proof kinds through real scheduled approval/delivery, exact
attachment retrieval, v3 receipt reads, failed capture rollback and revoked-read
post-check denial. Restricted PostgreSQL acceptance also verifies native
reference constraints and reviewed archive/purge cascade while preserving
underlying domain records. This does not qualify live recipient semantics,
process-loss recovery or sustained load.

Live vendor adapters, recipient policy, independently signed provider
acknowledgements and production process-loss/backup operations remain acceptance
work. The integrated product demo is still
deferred until its code and release gates are complete.
