# Device onboarding control-plane contract

## Native verification and connection controls

The deployed r19.4 preview defaults Add device to SNMP only; ping is optional.
The form reads the authorized Collector registry and identifies methods not
advertised by an online Collector at the selected site. An unavailable selected
method must be deselected or its Collector configured before submission. If the
registry cannot be read, support is explicitly unknown rather than falsely absent.
Availability does not authorize a target or prove successful monitoring.

Existing connections have a confirmed Enable or Disable control under Device
settings. Disabling cancels outstanding verification authority, withdraws that
connection's continuous monitoring, and retains the device, credentials, template
configuration and verification/observation histories. Active legacy collection
capabilities must first be deactivated. Re-enabling queues fresh verification;
it never restores old continuous approval automatically. Stale device revisions
and late results from revoked leases are rejected. Verification history loads
the last twenty retained checks, including their scope and authentication limits.

Native ICMP/SSH preflight names are accepted separately from ordinary collection
adapters. ICMP is opt-in and requires ping plus local socket permission; no root
identity or kernel permission is granted by the product. The current server does
not enable it. An unconfigured node_exporter, cAdvisor or VMware connection can
prove TCP reachability, not authentication or fresh metrics. Studio must bind and
test a measurement template before enabling its continuous metric collection.
This update is deployed and source/build verified; real targets remain separately
unqualified. The historical
sections below retain their original checkpoints.

## Inventory-first Assets and template assignment (r17)

`/assets/devices` opens the inventory and current collection status. Manual
enrollment is a separate `/assets/devices/add` route reached through Add device.
Categories cover wired devices, wireless infrastructure, firewalls, physical
servers/registered Linux or Windows hosts, storage, and other devices. Category
counts and cursor-bound filtering use authorized server-side inventory, not only
the first fetched page. Observed wired/wireless terminals retain their separate
endpoint inventory; association/presence is not an independently monitored host.

Manage opens three sections: Live status, Monitoring templates and Device settings.
Apply template opens Monitoring templates directly. The existing published
collection-policy path selects a compatible immutable capability, previews its
device/credential/worker/schedule binding, and applies only the approved exact
plan. Draft MIB proposals blocked on external generator validation are explicitly
not deployable choices. This UX does not claim the missing end-to-end AI SNMP
module generator/installer has been implemented. Raw exporter module/custody
controls are under Advanced continuous collection settings rather than the default
inventory. The original encrypted credentials, approval and namespace rules remain.

Live status polls bounded device batches every 30 seconds. Prometheus `up` is paired
with the actual sample timestamp, current enrollment ID/revision, authorized device
identity and namespace. Fresh success reports Up · collecting, failed collection
reports Poll failed, old evidence reports Stale, and unavailable/ambiguous evidence
reports Unknown. Protocol verification never reports live Up. Scheduled published
Collector capabilities use current approved deployment fingerprints and freshness;
on-demand readiness is not continuous health. Metrics access requires metrics.read,
and backend-selection/query/authority failures remain Unknown without raw errors.
Counts cover registered inventory; they are not hardware-health or live-up counts.

## Catalog-validated SNMP and observed identity (r16)

Collector adapter permissions (`snmp_exporter`, `snmp_topology`) are not exporter
module names. New/manual/conversational enrollment and monitoring approval validate
against the root-provisioned, modules-only native catalog. `/api/v1/assets/snmp-modules`
exposes names only; the Collector independently validates its local catalog before
using managed runtime custody. Hosts without the native catalog support only
portable `if_mib`/`system` defaults at enrollment, not arbitrary unknown names.

Managed SNMP verification uses an attempt-private fixed four-scalar GET for
`sysName`, `sysDescr`, `sysObjectID`, and `sysUpTime`: no interface/sysOR walk,
no retransmission, bounded time/body/sample counts, and the actual connection port.
The root-controlled modules-only catalog is safely cached by file identity and
rechecked for custody on each use. Private exporter configs include only requested
modules, avoiding repeated parsing/serialization of every vendor MIB. No credential
material enters that cache.
Continuous monitoring remains independent and normally uses `if_mib`. External
exporter authentication references use its installed `system` module for identity.
An identity response does not prove every requested interface metric is available.

Successful, current leased SNMP results persist the bounded `sysName` in connection
evidence and preflight history. The server binds discovery to the verified target
and current device identity revision. API `discovered_name` and hostname search
only expose that current verified result. The inventory displays sysName as the
primary label for an IP placeholder, while preserving any operator alias and
showing the observed name separately. Device kind/vendor are not guessed from an
arbitrary sysName. No schema migration or secret/name overwrite is required.
The built-in `inventory.get_device` output contract adds `discovered_name` as an
optional field, retaining compatibility with historical receipts. Only the exact
bootstrap-owned legacy definition is extended; customized definitions are not
overwritten and receive no undeclared extra output.

**Manage → SNMP module configuration → Save modules and reverify** repairs an
existing connection using the installed catalog. It checks current permissions,
device revision and active verification/capabilities, preserves target/profile/
worker selector, audits the old/new module names, and queues one preflight. Any
old continuous approval is withdrawn and must be approved again after verification.
Historical failures remain in preflight history. Pending/running inventory rows
refresh automatically (at most ten visible devices per poll); Refresh remains available.

Exporter errors retain bounded, recognized `Unknown module`/`Unknown auth`
diagnostics with HTTP status and a next action. Arbitrary response bodies are never
shown/stored. Unrecognized HTTP errors remain explicitly unknown rather than being
misreported as bad credentials. Legacy HTTP 400 details cannot be reconstructed;
the operator's invalid module list can be diagnosed directly from saved configuration.

## Optional placement and direct conversational enrollment (r15)

Native MCP SSH also supports an unset inventory site. **Manage → Add SSH for
native MCP tools** lists enabled saved SSH-password credentials; selecting one
preserves its exact connection scope without assigning a device site. An explicit
conflicting site or remote-worker selector is rejected. Registration leaves SNMP
unchanged and does not contact the device or queue a Collector preflight.

In **Assets → device settings → Device access**, read its SSH fingerprint.
Discovery does not send credentials or run commands. Explicitly confirm the
first-use identity before a tool connects. Later calls reuse it across MCP packages.
A changed key or target requires renewed confirmation; never blindly accept an
unexpected replacement. This access setup is independent of package installation.
The GUI needs no pasted public key. Credentials remain write-only references.

For older switches, **Assets → device settings → Device access**
offers **Legacy Cisco — group14 / SHA-1** in r19.22. Saving requires
explicit device-specific risk acceptance and does not connect or save trust.
Modern SSH remains the default; no automatic fallback exists. The exception is
bound to the current device/address/port/identity, not to its reusable credential.
Changing profile invalidates frozen calls and legacy target-bound installations.
Reusable packages resolve the current profile at each invocation and do not need
reinstallation. Fingerprint trust remains separate. Group1-only, DSA-only, 3DES-only
and MD5-only devices are not covered.
This profile applies to native MCP SSH, not the separate AsyncSSH collector path.

Site is optional: omitted, null, empty and whitespace-only values are stored as
NULL, never as an invented `LAB` or `default`. Physical placement is a separate
structured `location`: optional `zone`, `building`, `floor`, `room`, `rack`, and
`height` (integer rack U position, 1–1000). Partial paths are valid. The Add device
form starts blank; **Manage → Device metadata** edits/clears placement with a
revision check without changing the target, credential scope or verified identity.
Legacy Site values are preserved. Physical location never grants network access.

A clear request such as either of these uses the built-in deterministic
`explicit-device-enrollment/v1` path inside the existing LangGraph runtime:

```text
Add switch 198.18.0.123 using credential profile lab
please add new switch, use the snmp profile-lab, the Mgmt ip is 198.18.0.123
Add switch 198.18.0.123 using credential profile lab zone East building DC1 floor 2 room NOC rack R1 height 12
```

The bounded grammar recognizes explicit unicast IP lists and an exact saved
profile name, plus optional Site/placement after the profile. It does not fuzzy-
classify write authority, guess credentials, scan ranges, follow tool-output
instructions or apply to Skills/scheduled workflows. Other phrasing goes through
the ordinary Agent and preview/approval path. `Prepare/show a plan`, negative,
quoted-document, ambiguous and multi-action requests do not authorize direct
writes. The original initiating human must remain enabled, have `assets.read`
and `assets.write`, and satisfy the captured authorization and current AgentProfile.

The fixed workflow validates original intent → resolves saved credential metadata
→ atomically commits devices, connections, finite monitoring intent and an owned
Tool receipt → queues asynchronous Collector preflight → returns durable IDs and
an **Open device inventory** link. It uses zero external model calls. Failed writes
escalate with the retained cause; a completed enrollment requires the real receipt.
History is not rewritten and previous failed/clarification tasks are not replayed.

A blank Site does not strip credential custody: connection worker labels inherit
the selected profile's exact selector. An explicitly supplied Site must still
match it. Creating unassigned inventory requires namespace-global authorization;
site-limited operators cannot exploit null placement to widen their access.
Collector network/adapter allowlists and lease checks are unchanged.
The protected, configured monitoring-gateway service has a narrow connection-
level exception: for NULL Site, its snapshot matches the connection's credential
worker Site against the gateway principal's authorized sites. Namespace, verified
identity, finite intent, credential and native network checks still apply. This
does not expose unassigned inventory to ordinary site readers or other services.

For managed SNMPv2c, direct Add also requests the existing `preview-snmp` gateway
profile: `if_mib`, 30s interval, 10s timeout, seven-day lifetime. Manual GUI enrollment
offers the same opt-in checkbox (checked initially); old API callers preserve
their behavior unless `request_monitoring=true`. This is finite monitoring intent,
not verified health. No scrape target is issued until successful Collector
verification. The gateway's approved worker site (from the credential selector),
CIDRs, ports and modules remain authoritative; blank physical location does not
bypass them. Renew/withdraw via Manage. External credentials and non-SNMP methods
retain their compatible collector/custody setup path, rather than inventing it.

Preview requests remain pure, now also accepting blank placement. They require
their exact **Approve enrollment** action. Legacy reviewed collection activation
is separate; the direct managed-SNMP continuous path does not silently activate
unrelated topology/SSH/API collectors. Existing configuration, secrets, routes
and devices are retained by the additive location migration `s6w8y0b2d4f7`.

## AI time versus SNMP time (r14 historical behavior; superseded above)

Conversational enrollment uses the shared bounded LangGraph Agent kernel. It is
not currently automatically bound to a dedicated, deterministic SNMP Workflow
template. The registered internal Tools include `credentials.list_device_profiles`,
`inventory.preview_onboarding`, `inventory.find_devices` and
`inventory.preview_activation`. Their handlers are embedded control-plane
services, not fabricated chat responses or an external MCP requirement. The
credential-list and enrollment-preview operations read metadata only; they do not
decrypt the community, contact the switch or activate monitoring.

The actual staged workflow is:

1. AI interprets the stated IPs, site and saved profile name, then requests eligible
   credential metadata and an exact onboarding preview through typed Tools.
2. The operator reviews the deterministic plan and approves enrollment in the GUI.
3. The control plane atomically creates device/connection records and queues
   bounded site-Collector preflight.
4. The Collector resolves the scoped credential and uses the SNMP exporter for
   the actual protocol query; it persists verification results, not a guess.
5. Collection activation and continuous monitoring have their own exact approvals.

The October 12 screenshots show zero Tool calls: no SNMP packet was sent by that
investigation. Its first external-model decision exceeded a 20s provider limit,
even after the whole-task budget was set to 800s. An 800s route is not an 800s
model attempt. r14 exposes the attempt limit and permits 120s without expanding
the task, lease, output or device-network scope. Provider queueing/inference or
connectivity can still be slow; the timeout record alone cannot distinguish them.
Several AI turns can add external inference latency to an otherwise simple
inventory operation. A key/readiness check is not full onboarding acceptance.
The Agent prompt now explicitly states decision invariants and the credential →
preview → approval sequence, avoiding unrelated diagnostics for simple enrollment.
At r14, if the site was missing it asked rather than guessed. This guidance was not a new compiled
SNMP template and does not bypass human approval.

For deterministic enrollment without model latency, use the existing **Add device**
GUI. User-authored fixed/agent-loop templates remain available in Workflow Studio;
do not claim a template is deployed merely because its steps are documented here.

## Managed credentials and AI onboarding (r9)

Open `/settings/credentials` to create a write-only encrypted SNMPv2c community,
Windows username/password, HTTPS token, SSH password or validated SSH private-key
profile. Use a friendly name such as `lab-snmp-ro` and site `LAB`. Rotation is
revision-checked; revocation denies future leases. Secrets must not be pasted into
AI conversations. The old Credential reference form is only for external backends.

On the AI operator home page, ask: “Prepare SNMP onboarding for 198.18.0.10 and
198.18.0.11 at site LAB using lab-snmp-ro. Show the enrollment plan for approval.”
`credentials.list_device_profiles` returns eligible names/IDs, not secret values or
external secret paths. `inventory.preview_onboarding` validates up to 50 explicit
unicast IPs, checks adapter/site compatibility, and returns a deterministic preview.
It performs no scan and writes no inventory. The proposal card shows the exact
device list, references, blockers and warnings. A human with `assets.write` supplies
a reason and selects **Approve enrollment**. The server rechecks the hash and
credential revision, commits the batch atomically, and retains a replay-safe receipt.

Approval starts bounded Collector preflight. `inventory.find_devices` finds the
enrolled records by explicit IPs and site, so follow-up questions do not require
copying internal device IDs. SNMP uses the selected credential for
a real protocol query, not just TCP reachability. Once verified, ask AI to preview
the published `builtin-snmp-site-local` policy for the enrolled connection. Its
`inventory.preview_activation` result has a separate **Approve collection** action
with the exact activation hash. Collection success must be checked in run history.
Continuous Prometheus monitoring remains a distinct finite enrollment in **Manage**,
using `preview-snmp`; no implicit continuous enrollment follows device creation.

Windows/WMI credentials use the existing fixed read-only CIM/PSRP operations over
WinRM HTTPS, not legacy WMI/DCOM. SSH requires an approved command collector and
verified host keys; HTTPS APIs require a published compatible collector and valid
TLS trust. Their preflight remains transport-only. Saving any credential does not
configure the remote device, publish a collector, change trust, or widen network
allowlists. The existing lab CIDRs remain authoritative.

## Purpose

The Assets page lets an operator add lab or production devices without editing
configuration files or asking a developer to modify iCheck. It records what the
operator wants monitored; it does not claim that an unverified target is live.

Open the page at the frontend's `/assets/devices` route (for example, on a
local development frontend):

```text
http://localhost:3000/assets/devices
```

The frontend uses `NEXT_PUBLIC_ICHECK_API_URL` and calls these APIs:

```text
POST /api/v1/assets/devices
GET  /api/v1/assets/devices
GET  /api/v1/assets/devices/page?limit=50&search=...&cursor=...
GET  /api/v1/assets/devices/{device_id}
PATCH /api/v1/assets/devices/{device_id}/metadata
POST /api/v1/assets/devices/{device_id}/identity-correction/preview
POST /api/v1/assets/devices/{device_id}/identity-correction/commit
GET  /api/v1/assets/devices/{device_id}/connections/{connection_id}/preflights
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/verification/retry
GET  /api/v1/assets/activation-policies?policy_status=published
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/preview
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/approve
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/activation/deactivate
GET  /api/v1/assets/devices/{device_id}/connections/{connection_id}/monitoring
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/monitoring/approve
POST /api/v1/assets/devices/{device_id}/connections/{connection_id}/monitoring/withdraw
POST /api/v1/credential-profiles
GET  /api/v1/credential-profiles
```

## Operator flow

1. Create or select a credential profile. Secure managed credential entry is on
   `/settings/credentials`; the inventory form stores references only. External
   secret-reference profiles remain available for configured enterprise backends.
2. Enter identity, management IP, type and optional physical location, legacy Site, vendor/model and labels.
3. Select one or more monitoring methods and optionally bind a compatible,
   site-scoped credential profile to each method.
4. Submit the device. Device identity and all connection intents are committed
   together and an audit event is written.
5. iCheck reports the device as `pending_verification` and each connection as
   `pending` until a site worker performs protocol preflight.
6. For a verified connection, select a compatible published activation policy
   and preview the exact target, configuration, worker scope, schedule, and
   warnings.
7. Approve the unchanged preview hash with a reason. iCheck atomically creates
   or re-enables the collector deployment and records its policy and audit link.
8. Deactivation disables future assignment without deleting run or approval
   history. Re-activation requires a fresh preview and approval.
9. Open **Manage** on a device to correct its type, vendor, model, or labels.
   The save includes the revision read by the browser; a concurrent edit
   returns `409` and the browser reloads the current record before retry.
10. Use **Correct device identity** for name, IP, site, or credential-binding
    changes. Preview blockers, deactivate old capabilities and wait for active
    leases to finish, then commit the unchanged preview with a reason. The
    connections return to pending verification at the new target.
11. For continuous SNMP/Windows time series, use the separate continuous
    monitoring section: approve the current preview and revision with an
    operator-provisioned gateway custody profile, modules/collectors, interval,
    timeout, finite lifetime and reason. Update/renew or withdraw that intent
    without changing root-owned Prometheus/exporter configuration. This feature
    is installed on the preview server; approval is not scrape health. See the
    [continuous monitoring contract](continuous-monitoring.md) for native and
    live acceptance gates.

For a new device, each credential dropdown shows only enabled profiles that
allow its adapter and whose Worker selector matches the form's site selector.
The form currently supplies only `{site}`; a profile requiring another Worker
label is not offered. If a selected reference becomes ineligible after the
operator changes the site, the form keeps it visible with a warning and blocks
submission before sending a device-create request. The operator can choose an
eligible reference or leave the optional binding blank. Server-side scope and
credential validation remains authoritative. The focused helper tests and a
controlled browser check (private development evidence; not distributed)
cover this GUI behavior with synthetic API data, not a live device.

The inventory page uses server-side search and keyset pagination, rather than
filtering only the first 100 rows returned by the legacy list endpoint. The
page API returns `{items, next_cursor}` in `(name, id)` order, defaults to 50
items, and caps each response at 100. A cursor is bound to the current tenant,
region, principal scope, and filters; malformed or mismatched cursors fail
closed with 422. Every page re-applies authorization, so a cursor cannot widen
site or device access. The GUI offers **Load more devices** until
`next_cursor` is null and searches the whole authorized inventory. The legacy
`GET /devices` list stays compatible for existing callers. Pages describe a
live inventory, not a frozen snapshot; refresh after concurrent renames or
scope changes. Row-level retry, approval, and deactivation refresh only the
affected device, so an action on a later page does not discard loaded rows.

Supported intent mappings are:

| Operator choice | Adapter contract | Default port |
|---|---|---:|
| SNMP | `snmp_exporter` | 161 |
| HTTPS API | `http_json` | 443 |
| SSH | `ssh` | 22 |
| Windows exporter | `windows_exporter` | 9182 |
| WinRM HTTPS | `psrp_cim` | 5986 |
| ICMP | `icmp` | none |

The mapping is a platform default, not hard-coded device behavior. Future
collector artifacts may extend or replace adapters behind the same onboarding
contract.

## Validation and security

- Device names and management IPs are unique.
- Management addresses must be valid IPv4 or IPv6 values.
- A device cannot declare the same protocol twice.
- Ports are limited to 1–65535.
- If supplied, connection Site selectors match the legacy device Site. If device
  placement is blank, inherit the exact saved credential worker selector.
- Credential profiles must be enabled, allow the selected adapter, and match
  the connection worker scope.
- Configuration payloads are checked for inline secret-shaped keys and rejected
  if found.
- Audit metadata records the device and protocol choices, not secret references
  or resolved credentials.
- The metadata PATCH requires `assets.write` and access to the device's current
  site. It accepts only `kind`, `vendor`, `model`, `labels`, `actor`, and
  `expected_revision`; names, management IPs, sites, connections, and
  verification state cannot be altered through this route. Successful changes
  increment a per-device revision and write `device.metadata.updated` with
  changed field names and label keys, not label values. A no-op preserves the
  revision and writes no audit event.
- Worker claims require the registered worker bearer token, match site and
  adapter capabilities, and receive a separate expiring lease token.
- Preflight evidence is capped at 32 KiB, checked for secret-shaped fields, and
  never includes the worker or lease token.
- Device responses contain only the latest verification summary. Immutable
  history is queried separately with a maximum of 100 records per request.

## Identity correction lifecycle

The identity-correction API is separate from the descriptive metadata PATCH.
Preview accepts the expected device revision, proposed name, management IP,
site, and optional per-connection credential-profile references. Commit
requires the same fields, the exact preview hash, authenticated actor, and an
operator reason. Both routes require `assets.write`, device access, and
authorization for the old and new sites. Duplicate name/IP, incompatible
credentials, active preflight leases, active capabilities, enabled deployments,
or in-flight collector leases block commit. An expired preflight lease can be
retired by the commit; a merely pending connection is not a blocker.

Commit locks the device's connection rows, rechecks the preview and revision,
and atomically updates identity, site worker selectors, credential bindings,
and verification summaries. It increments both the general device revision and
the separate `identity_revision`, then writes
`device.identity.corrected`. Old approved deployments stay disabled with
their old targets; they are not retargeted in place. New preflight claims
snapshot the target IP and site. Legacy preflight rows missing a snapshot
receive the old target/site before correction. A late worker completion must
still own the exact unexpired lease in a compare-and-swap update, so it cannot
verify the corrected device with old evidence. Worker claims compare the
selected device revision with the current revision before assigning a target.
Descriptive metadata edits increment only the general revision, so changing a
vendor, model, type, or label does not unnecessarily invalidate collection.

Device-scoped Collector deployments carry the exact `identity_revision` used
to approve their target. Activation previews include this binding in the plan
hash, and direct Collector/canary creation must supply the expected revision.
Creation rejects a changed identity, a conflicting `target.device_id`, or a
site hint inconsistent with the device. Scheduled Worker claims and on-demand
triggers check that the bound revision, site, and enabled device still match;
a stale scheduled deployment is disabled and audited before any assignment is
returned. Worker claims re-read the device after winning the deployment row
lock so a PostgreSQL pre-wait statement snapshot cannot issue a stale target.
After correction, the operator must re-verify the connection and approve a
fresh activation plan. Old deployment targets and run history remain intact.

Migration `k0m2p4r6t8v1` deliberately marks pre-existing device-scoped
deployments with binding `0` (unreviewed), disables them, and clears their next
run time and expired lease tokens. It cannot prove that a legacy target still
points to the current device. Plan an approval/redeployment window when
upgrading an installation with such deployments. Drain Worker leases before
upgrade; the migration refuses to run while a device-scoped lease is unexpired.
It cannot be rolled back while any scoped deployment or changed identity epoch
remains. New deployments use positive
identity revisions.
Focused API, populated migration, and
native non-owner PostgreSQL lock-wait checks (private development evidence; not distributed)
pass; these are not live-device or production-load acceptance.

The same device ID is appropriate only for the same physical asset. A
replacement asset needs a new record so historical IP/MAC observations and
collector runs are not misattributed. Functional API, isolated browser, and
non-owner PostgreSQL RLS/race checks (private development evidence; not distributed)
pass. Required-auth browser, production-scale contention/TLS, and live-device
verification remain separate acceptance gates.

The blocker scan and identity epoch cover deployments explicitly scoped to the
device, including those with `target.device_id`. They cannot infer that an
unrelated, unscoped custom collector's arbitrary URL or hostname points at the
same old address. Such collectors must be reviewed separately; Studio must
require an explicit device binding for generated device-targeting collectors.

Provider values remain opaque references at the control-plane layer. For an
active collector run, the Worker obtains a lease-bound resolution grant and
resolves `vault`/`vault_kv2` references locally with its own Vault token file.
The control plane never retrieves or returns the secret. Environment references
are disabled by default on Workers and exist only as an explicit development
option. Activation continues to validate and store only the profile reference;
preflight remains transport-only except for the site-local SNMP Exporter check.

## Worker preflight execution

The standalone `icheck-collector` process polls for both collector runs and
device preflights. It fails closed unless the target IP is explicitly listed by
`ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS` as an exact address or CIDR.

| Adapter | Preflight evidence | Meaning |
|---|---|---|
| `icmp` | One bounded ICMP echo | Network reachability only |
| `http_json` | TCP connect to configured port | Transport only; authentication not tested |
| `ssh` | TCP connect to configured port | Transport only; authentication not tested |
| `windows_exporter` | TCP connect to configured port | Transport only; metrics not yet scraped |
| `psrp_cim` | TCP connect to configured WinRM TLS port | Transport only; credentials not resolved |
| `snmp_exporter` | Bounded site-local exporter query | Protocol query using a configured exporter auth module |

Worker settings:

```text
ICHECK_COLLECTOR_MAX_PREFLIGHTS=4
ICHECK_COLLECTOR_PREFLIGHT_TIMEOUT_SECONDS=5
ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS=10.0.0.0/8,192.168.0.0/16
ICHECK_COLLECTOR_PREFLIGHT_SNMP_EXPORTER_URL=http://127.0.0.1:9116
```

SNMP targets must also pass `ICHECK_COLLECTOR_SNMP_ALLOWED_TARGETS`, and the
exporter host must pass `ICHECK_COLLECTOR_EXPORTER_ALLOWED_HOSTS`. An absent
SNMP Exporter URL fails the preflight; UDP route selection alone is never
treated as proof that SNMP works.

WinRM preflight remains a credential-free TCP reachability check. An approved
on-demand `psrp_cim` run uses the separate production transport and additionally
requires the Worker to advertise `psrp_cim`, be installed with the `windows`
extra, match `ICHECK_COLLECTOR_WINDOWS_ALLOWED_TARGETS`, use a port in
`ICHECK_COLLECTOR_PSRP_ALLOWED_PORTS`, and verify the WinRM HTTPS certificate
against the system trust store or `ICHECK_COLLECTOR_PSRP_CA_FILE`. The GUI never
collects or stores the Windows password; it binds a scoped Credential Profile
reference resolved locally by the Worker.

## State model

```text
operator submits device
        ↓
device: pending_verification
connections: pending
        ↓
site worker claims a bounded preflight job
        ↓
connection: verified | failed
        ↓
policy creates or updates collector deployment
        ↓
device: monitoring_configured
        ↓
fresh collector-run evidence and reconciliation
        ↓
device: active | degraded
```

Onboarding, worker preflight, evidence history, explicit retry, and readiness
aggregation through device `verified`, `partially_verified`, or
`verification_failed` are implemented. Policy-controlled deployment creation,
preview, approval, deactivation, and reactivation are also implemented. A
configured deployment yields `monitoring_configured`, not `active`; continuous
run-health reconciliation promotes it only after a fresh successful scheduled
run. Later failures, freshness expiry, or approved-deployment drift degrade the
device and retain an explainable connection-level reason. All protocol paths
still require acceptance against the firewall, switch, router, Linux, and
Windows lab when that environment is available. See
`docs/device-activation.md`.

## Isolated browser acceptance

On 2026-10-03, a real Chromium browser connected the Assets page to a live,
loopback iCheck API backed by a disposable SQLite database. An operator created
a Vault reference, enrolled a synthetic firewall with SNMP and ICMP intents,
and read the record back after a full page reload. The API retained the SNMP
credential-profile reference; both methods and the device remained pending
verification. The browser reported no console errors. TypeScript, lint for the
touched page, and the production frontend build passed. The
browser smoke report (private development evidence; not distributed)
records the exact scope.

At 390px width, the original inventory table hid the Manage action in its
horizontal scroll area. The mobile view now shows identity, methods, status,
and Manage in one visible column; the same detail panel opens without page or
table overflow. The desktop table retains its columns and disclosure action.
This SQLite check did not perform site-worker preflight, activation, live
collection, production authentication, or PostgreSQL GUI acceptance. The
subsequent isolated PostgreSQL check below covers only the last of those gaps;
the live lab and production gates remain open.

A subsequent required-auth PostgreSQL browser check (private development evidence; not distributed)
covered the GUI flow against a freshly migrated, isolated PostgreSQL 16.15
database with a non-owner runtime role. A bootstrap administrator opened a
browser session, created a scoped Vault reference and synthetic firewall with
SNMP and ICMP intents, then reloaded the page. Database and API reads retained
the credential reference and both pending connection states. Anonymous reads
returned 401, a browser write without a CSRF token returned 403, and GUI
sign-out revoked access. The operator sidebar now scrolls at 1280×720 so its
sign-out control remains reachable. This still did not contact a real device,
run a site Worker, or accept production identity and transport security.

An additional GUI-to-Worker acceptance check (private development evidence; not distributed)
on 2026-10-04 closed the local synthetic path through first collection. In a
disposable SQLite environment, the GUI enrolled a Windows exporter intent for
a loopback endpoint. A site-scoped Worker verified allowlisted TCP reachability;
the GUI showed the transport-only warning, previewed the exact target and site,
and approved the plan with a reason. The device moved from
`pending_verification` to `verified`, then `monitoring_configured`, and only
became `active` after a separate Worker cycle saved one normalized metric
sample. The browser had no errors or warnings, and 12 focused backend tests
passed. The endpoint was a static synthetic metrics file, control-plane auth
was disabled for this check, and neither the real Windows host nor other lab
devices were contacted. Production identity, PostgreSQL, TLS/mTLS, and the
final integrated demo remain separate gates.

A separate browser pagination check (private development evidence; not distributed)
loaded 50, then 100, then all 139 synthetic/seeded devices and found the last
synthetic row by server-side search. A second 59-row browser fixture retried a
failed connection on the last row and kept the expanded row and page count.
Required-auth API tests cover site-scoped page reads and cross-scope cursor
rejection. An automated SQLite test traversed 1,005 rows without gaps or
duplicates. The separate native PostgreSQL RLS check (private development evidence; not distributed)
repeated 1,005-row traversal as a non-owner runtime role, completed all 503
site-scoped rows, denied no-namespace reads, and kept duplicate identities in
other regions/tenants hidden. Its HTTP probe used development authentication;
required-auth PostgreSQL browser and production 1,000-target latency/concurrency
remain open. These are functional gates, not capacity results.

## Example

```json
{
  "name": "lab-core-01",
  "kind": "switch",
  "management_ip": "192.0.2.10",
  "site": "LAB",
  "labels": {
    "environment": "lab",
    "role": "core"
  },
  "connections": [
    {
      "protocol": "snmp",
      "credential_profile_ref": "lab-network-readonly",
      "worker_selector": {
        "site": "LAB"
      },
      "configuration": {}
    },
    {
      "protocol": "icmp",
      "worker_selector": {
        "site": "LAB"
      },
      "configuration": {}
    }
  ],
  "created_by": "assets.operator"
}
```
