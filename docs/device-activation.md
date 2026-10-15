# Device collection activation

## Purpose

Device activation is the governed bridge between a verified onboarding intent
and a runnable collector deployment. Verification proves only the level stated
by its evidence. Activation determines which published collector artifact will
run, the rendered target and configuration, the worker scope, and the schedule.

The control plane never activates an arbitrary browser payload. It renders a
versioned policy, validates the resulting deployment against the published
collector contract, returns an immutable plan hash, and requires an operator to
approve that exact hash with a reason.

## Lifecycle

```text
activation policy draft
        ↺ edit with expected draft revision; audit digest, not template values
        ↓ validate collector schema and placeholders
validated
        ↓ publish; prior published version is deprecated
published
        ↓ render one capability for a verified device connection
preview plan + warnings + SHA-256 plan hash
        ↓ operator approves exact hash and reason
active capability slot + enabled CollectorDeployment
        ↓ repeat for metrics, topology, or diagnostics on the same connection
multiple independently healthy capability slots
        ↓ operator deactivates one exact activation with reason
deactivated capability + disabled deployment, history retained
```

Approval is idempotent per connection and capability key (the stable policy
name). Repeating an approval for the same current plan does not create another
deployment. Re-activating an unchanged deactivated plan re-enables its existing
deployment. Approving a newer published version of the same capability creates
the replacement and disables the prior deployment atomically; different
capability keys can remain active together. If a plan changed, a new preview
and approval are mandatory.

## API

Policy administration:

```text
GET  /api/v1/assets/activation-collectors
POST /api/v1/assets/activation-policy-proposals
GET  /api/v1/assets/activation-policy-proposals?device_id=...
GET  /api/v1/assets/activation-policy-proposals/{proposal_id}
GET  /api/v1/assets/activation-policy-proposals/{proposal_id}/scope-preview?device_id=...
POST /api/v1/assets/activation-policy-proposals/{proposal_id}/interrupt
GET  /api/v1/assets/activation-policy-proposals/admin/recovery
POST /api/v1/assets/activation-policy-proposals/{proposal_id}/admin-interrupt
POST /api/v1/assets/activation-policies
PATCH /api/v1/assets/activation-policies/{policy_id}
POST /api/v1/assets/activation-policies/draft-scope-preview
GET  /api/v1/assets/activation-policies
GET  /api/v1/assets/activation-policies/{policy_id}
POST /api/v1/assets/activation-policies/{policy_id}/validate
POST /api/v1/assets/activation-policies/{policy_id}/publish
```

Connection activation:

```text
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/preview
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/approve
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activations/{activation_id}/deactivate
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/deactivate
```

The final route is a backward-compatible single-activation endpoint. It fails
closed with `409` when more than one active capability exists, because a
state-changing request must not guess its target.

The Assets page exposes only published policies compatible with the verified
connection transport. It displays every active/deactivated capability and its
independent runtime health, plus the rendered target, schedule, worker selector,
artifact version, warnings, and plan hash before each approval.

The dedicated `/assets/activation-policies` page lets an asset operator choose
a published collector version, inspect its target/configuration schema, create
a transport-specific draft, revise it, validate it, and publish it. `version`
identifies a lifecycle artifact; `revision` identifies edits within one draft.
The edit API requires `assets.activate`, an `expected_revision`, the full draft,
and a trusted actor. It changes only a `draft`, requires the policy name to stay
fixed, rejects inline credentials, and atomically advances the revision if the
client still has the latest one. A stale revision or a non-draft returns `409`;
missing policy returns `404`. An unchanged save does not advance the revision
or add an audit event. The edit audit records changed field names and before/
after SHA-256 digests, not template contents. Formal validation accepts an
optional revision pin for legacy untouched drafts but requires one after an
edit; it locks the current row before checking the exact revision and policy
contract. Validated and published policies cannot be edited: the UI can load
one into the editor only to create a new lifecycle version. Unsaved browser
fields are retained after a conflict for manual reconciliation, never silently
overwritten. A database trigger also seals policy identity and validated
content against direct SQL changes by the runtime role, permits only the
defined draft/validation/publication/deprecation transitions, and refuses
history deletion. It keeps validated content sealed even when a write bypasses
the service method; it is not a substitute for role grants, audit review or
deployment approval. Draft
edit audit still depends on using the service transaction; the trigger does
not independently attest semantic validation or model/provider correctness.
Policy names and lifecycle versions are unique within a tenant and
region, not globally; two tenants can independently publish the same policy
name and version. A disposable PostgreSQL contention check (private development evidence; not distributed)
confirmed one winner, one revision conflict and one edit audit in each of five
two-operator races. A non-owner runtime role also failed raw reads and updates
across either the tenant or region boundary. It does not prove production role
provisioning or load. Its protocol-filtered
collector selector uses bounded, name-prefix-searchable keyset pages of
summaries (`GET /activation-collectors/page`), then fetches only the selected
version's full contract (`GET /activation-collectors/{version_id}`). A Studio
deep link resolves the exact version even beyond the first page and derives
its protocol when one was not supplied. The policy lifecycle list similarly
uses `GET /activation-policies/page` with bounded pages and name-prefix search.
Existing list endpoints remain available to earlier clients. Collector pages
and exact contracts require `assets.activate`; policy pages require
`assets.read`. Neither exposes generated source code or requires the broader
`capabilities.read` role.
The page does not auto-activate a device. A verified connection still requires
preview, exact-plan approval, and a reason on the Devices page.
An isolated 525-item PostgreSQL keyset and RLS check (private development evidence; not distributed)
passed; this is functional scale acceptance, not production throughput sizing.
An isolated browser draft-edit check (private development evidence; not distributed)
covered copying a published policy into a new version, reopening and saving a
draft, stale-revision reconciliation, keyboard submission, malformed-JSON
announcement, validation and publication. It found and fixed a same-collector
reload gap and 390px horizontal overflow. The check used disposable SQLite and
development authentication; it is not full accessibility, production-identity
or live-device acceptance.

An operator can also ask the configured `capability.authoring` structured model
to suggest a draft in that page, then refine the last suggestion with another
brief. Studio links a published collector version into this editor; each device
connection links its scoped device/protocol context. The proposal endpoint is
`assets.activate`-gated and returns a contract-checked suggestion only. It
creates no policy or deployment. The operator can edit the fields before
explicitly saving a draft; validation, publication, preflight, plan preview,
and approval remain independent steps. If no model route is configured, the
suggestion request fails closed with `503` and manual policy authoring remains
available.

Each model request now reserves a durable, namespace-scoped proposal receipt
before invocation. The browser sends a UUID `request_key`; repeating the same
actor/key/input returns the recorded result without calling the model again.
Key reuse with different input, an in-flight request, or a previously failed
request returns `409`; a new key is required after a terminal failure. A
refinement cites `parent_id`, and the server loads its sealed suggestion rather
than trusting a browser-supplied prior output. Parent, actor, collector version,
protocol, and device context must match. Successful and failed requests retain
bounded briefs, status, token usage, model identifiers where available, and
audited results; a database guard seals terminal receipts. The GUI lists the
last 30 requests for the current actor and selected device (or that actor's
unbound context) and can restore a successful suggestion for review. It does not persist
unsaved manual edits. A process lost after model invocation but before result
commit leaves an in-flight receipt: recovery may inspect it, but the same key
is never automatically retried. Each key starts at most one structured
generation operation; that operation may try configured fallback models. This
is not proof that an external provider charged exactly once.

The editor can request a **read-only scope preview of a successful, sealed AI
suggestion**. For a bound proposal the server uses its original device only;
an unbound proposal may supply an authorized device ID. The endpoint requires
`assets.activate`, the original actor and device-site access. It resolves the
current management IP only after model generation, renders the saved target,
combines policy and connection Worker selectors, checks the credential
profile's enabled/adapter/required-label constraints, and counts matching
registered Workers with fresh heartbeats in a capped 1,000-Worker scan. It
returns the credential profile reference but never its `secret_ref`. The
preview neither calls the model nor writes a policy, deployment, or audit
event. It evaluates the saved suggestion, **not** unsaved browser edits; its
result is advisory and may become stale immediately. A zero or partial Worker
count does not prove that a future Worker assignment will fail or succeed.
Formal publication, connection preflight, exact plan review, Worker target-host
allowlisting and approval are still separate gates.

The same editor also offers a `POST /activation-policies/draft-scope-preview`
for its **current form fields**, whether AI-derived or manually authored. It
requires `assets.activate` and device-site access when a device is selected;
it binds the result to a SHA-256 of the trusted input and hides it after the
fields change. The server uses the same deterministic template/collector
contract check as formal policy validation, then the same current-state
device/credential/Worker evaluator as the saved-suggestion preview. Obvious
inline credentials, URL userinfo and credential query keys are rejected before
preview or draft creation. This endpoint makes no model call and writes no
policy, deployment or audit event. It does not replace later validation,
publication, preflight or exact-plan approval.
An isolated browser check (private development evidence; not distributed)
confirmed the exact rendered target, stale-result clearing and credential-query
rejection without creating a policy; it is not real-device acceptance.

An in-flight receipt is never silently replayed. Its history record shows a
`recovery_available_at` time two hours after creation, beyond the configured
model-route maximum timeout. After that time, the same authorized actor can
explicitly mark the request interrupted with a reason. The server atomically
changes only a still-generating receipt to terminal `failed` with
`failure_code=Interrupted` and audits that the external charge is unknown.
Repeated interrupt calls return the sealed record; a prior success or failure
cannot be interrupted. A late model completion uses a conditional database
transition, so it cannot overwrite the interrupted record; its known token
usage is audited as a discarded late result. The old request key remains
unusable, and a new request always requires a new key and a deliberate operator
action. This is a safety recovery path, not provider cancellation, refund, or
automatic retry. Clock drift and provider billing reconciliation remain
operational acceptance concerns.

When the original actor has departed or lost access, a separate recovery page
at `/settings/ai/proposal-recovery` serves global administrators only. The
recovery list is limited to 100 generating requests in the administrator's
tenant and region, oldest first, with exact actor/device filters. Both API
operations require global `auth.admin` **and** `assets.activate`; a device- or
site-scoped operator cannot use them. A closure request must present the
listed request SHA-256 and an incident reason of at least ten non-space
characters. The server enforces the same two-hour database-clock wait and
conditional terminal transition as owner recovery. Its audit event records
the administrator, original actor, reason, request digest, and unknown external
charge. A digest mismatch or changed state fails closed. This administrative
path does not grant access to the original actor's completed suggestion, write
a policy, invoke a model, or release the spent request key. Recovery through a
real provider and PostgreSQL race testing remain acceptance work.

The proposal history displays **known provider-reported tokens**, not a bill.
If a candidate returns valid usage but invalid structured output, those tokens
are counted before fallback. The next candidate's output-token parameter is
capped by the remaining route budget; if a provider nevertheless reports a
cumulative overrun, the receipt is sealed as failed with the full known usage
and an audit event. Network errors, invalid usage metadata, and process loss
can leave an additional provider charge unknown. New receipts persist that
uncertainty separately; pre-migration rows show an unverified legacy state.
No configured route budget can guarantee an external financial ceiling without
provider idempotency and charge reconciliation. Live billing acceptance remains
separate work.

An administrator may now configure a durable structured-authoring admission
quota at `/settings/ai/authoring-quota`. The activation editor shows the
operator's available daily headroom. The shared gateway reserves the selected
route's whole token budget before model I/O, so concurrent AI drafts cannot
both pass on the same remaining capacity. Known unused tokens are released
after settlement; unknown charges retain the reservation. A denied request
returns `429` without a provider call and records a failed proposal receipt;
the same request key is not replayed. This admission quota covers Studio
authoring too, including custom route purposes, but does not yet cover
LangGraph investigations or guarantee the provider's final bill.

The model request includes only the selected published collector's target and
configuration contract, the operator's brief, optional prior suggestion, and
optional authorized device kind/vendor/model/site/port/verification state.
The server does not add the device management IP, name, credential references,
or collector implementation source. Briefs with apparent credential literals
are rejected before model invocation. Generated templates are checked against
the collector schema, placeholder allowlist, secret-shape rules, device site,
HTTPS URL and credential-query constraints, and `psrp_cim` execution mode
before they reach the browser. This is structural validation, not proof of
vendor endpoint correctness, authentication, Worker availability, or live
collection. Human review remains mandatory.

## Template contract

Policies may use only these placeholders in target, configuration-default, and
worker-selector templates:

```text
${device_id}
${device_name}
${management_ip}
${port}
${protocol}
${site}
```

Unknown, malformed, or unavailable placeholders fail validation or preview.
Rendered targets and configuration are checked against the selected collector
artifact's JSON Schemas. A policy cannot cross protocol/adapter boundaries, use
an unpublished collector artifact, contain inline secret-shaped values, or
contradict a connection's worker scope.

SNMP is a transport family: one verified SNMP connection can activate both
`snmp_exporter` metric and `snmp_topology` adjacency collectors. Other protocols
retain their explicit adapter allowlist. HTTPS API permits `http_json` and
Studio-generated `http_json_sandbox`; SSH permits `ssh` and
`ssh_command_sandbox`. The device's base adapter is used for transport preflight,
while the published policy selects the actual deployment adapter. A Worker must
advertise both capabilities to run both stages. Credential Profiles must allow
the base preflight adapter and the selected deployment adapter explicitly;
allowing one does not grant the other. HTTPS target hosts must also be on the
Worker's outbound HTTP allowlist. The sandbox transform never receives network
access or resolved credentials.

The plan hash includes policy content, connection identity, latest verification
time, artifact version, rendered inputs, execution mode, schedule, credential
reference, and worker selector. A new verification result therefore invalidates
an older approval preview.

## Built-in policies

The seed command idempotently publishes four defaults:

| Policy | Protocol | Execution | Target |
|---|---|---|---|
| `builtin-snmp-site-local` | SNMP | scheduled, 300 s | site-local SNMP Exporter and device management IP |
| `builtin-snmp-device-adjacency` | SNMP | scheduled, 300 s | reviewed LLDP topology through the site-local SNMP Exporter |
| `builtin-windows-exporter` | windows_exporter | scheduled, 300 s | device `http://IP:port/metrics` endpoint |
| `builtin-psrp-cim-diagnostics` | WinRM HTTPS | on demand | TLS-only PSRP/CIM host and port |

HTTPS API and SSH connections intentionally have no universal built-in policy.
A validated collector artifact and an environment-specific published policy are
required because authentication, paths, command sets, and output contracts vary.
ICMP is currently a preflight capability, not a continuous collector artifact.

## State and safety boundary

All enabled connections must be verified before runtime activation can raise
device readiness. With no active capability, the device remains `verified`.
One or more active capability deployments produce `monitoring_configured` while
scheduled collection is awaiting evidence. This means the approved collector
configuration exists; it does not prove that collection is healthy. Connections
such as ICMP that are intentionally used only for preflight do not require a
dummy deployment.

Runtime reconciliation is implemented in worker polling and run completion. A
fresh successful scheduled run promotes that capability to `healthy`; every
active scheduled capability must be healthy before the device becomes
`active`. A later failure becomes `degraded`; three
missed schedule intervals (with a minimum five-minute freshness budget) become
`stale`. Missing, disabled, or fingerprint-mismatched deployment content becomes
`drifted`. Re-approving the unchanged preview restores the exact approved
deployment fields and requires fresh run health before returning to `active`.

Exact deactivation prevents new scheduled assignments for only that capability
by disabling its deployment
and clearing its next-run time. It does not terminate a run whose lease is
already in flight; the audit event records that condition. Complete run,
deployment, policy, approval, and deactivation history remains available.

## Verification

Automated coverage includes:

- policy protocol/adapter compatibility and secret rejection;
- placeholder and collector-schema validation;
- published-version replacement;
- verified-connection requirement and credential/worker scope reuse;
- deterministic preview and stale-hash rejection;
- multiple capability slots on one verified connection;
- atomic deployment creation, same-capability version replacement, approval
  idempotency, exact deactivation, and reuse;
- device state aggregation and audit events;
- idempotent built-in policy seeding;
- clean Alembic migration through `e84b7a2d19c3` and 38 full backend tests.

Live firewall, switch, router, Linux, Windows, wireless-controller, remote-write,
and scale acceptance remains deferred until the user's test lab is ready.
