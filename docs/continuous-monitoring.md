# GUI-approved continuous monitoring

Current direction on 13 October 2026: preserve the installed monitoring gateway
and approved targets while adding [Grafana presentation and AI management](grafana-monitoring-design.md).
The r16 deployment record (private development evidence; not distributed)
records the existing switch's successful Prometheus collection; the
r17 record (private development evidence; not distributed)
adds its inventory-first status UI. These do not complete conversational SNMP
module generation/installation. The 9 October status below is historical, not
the current installation. Later explicit-request onboarding can create finite
monitoring intent; actual scraping still requires current approval and custody.

Newer source also supports [HTTP/API monitoring templates](http-monitoring.md),
actual numeric target tests and protected username/password or token references.
It reuses this gateway and approval lifecycle rather than adding a polling loop.
The HTTP extension and approved LAB gateway profile are deployed in the current
paired preview. Fresh fixture samples passed private native Prometheus collection; real API/device and
conversational Grafana binding acceptance remain outstanding.

Historical status on 9 October 2026: implemented, source-verified and packaged in r34.
The installed backend is still r30 at `g4j6l8n0p2r5`; historical frozen artifacts
are unchanged. R34 and current source include migration `h5k7m9p1r3t6` and the
database-free `icheck-monitoring-gateway` command. Neither the production database
nor Prometheus configuration has been changed for this feature. The gateway
unit is not installed. This is not the integrated demo.

## Operator experience

Open `/monitoring` for managed devices and services, each shown once. Counts,
search, categories and pagination operate on resource identities, not connections.
Resource kind determines the category; older generic inventory records use a
deterministic collector fallback. HTTP/API endpoints use the existing inventory
model. The retired Service Intelligence catalog is not reintroduced.

Each resource contains its monitoring checks and related alerts/dashboard links.
SSH and Telnet access records are management transports, not monitoring checks.
An SSH-only device remains one resource marked **Not monitored**. Disabled and
pending resources remain visible. Multiple collectors never create duplicate
resource cards. Collection status is not a verdict that every interface is up.

Expand **Monitoring checks** and choose **Check
measurement freshness** for an enabled Studio template. This reads the template's
declared measurements from existing Prometheus samples; it does not poll or
enroll a device. A successful scrape alone is not complete measurement proof.
Freshness is checked on request, not precomputed for every row. Inventory stays
visible when metric evidence is unavailable. All reads retain namespace and
device scope; secret configuration is not included in the overview response.
The initial connection-based implementation shipped in r19.7; r19.23 corrects
its resource model. The earlier authenticated GUI correctly included
this server's disabled SNMP connection without claiming fresh samples; fixture
checks cover other categories and measurement failures. Deployment is recorded
in the current paired deployment receipt; engineer-owned lab acceptance is separate.

Open `/assets/devices`, select **Manage**, and use the continuous monitoring
section of a verified SNMP, Windows exporter or source HTTP/API connection. An operator with
`assets.write` can approve, update/renew or withdraw an enrollment. Readers see
its current authorization and expiry, not approval controls. An approval requires
the exact current preview and enrollment revision, a protected gateway profile
name, allowed module/collector names, interval, timeout, lifetime and reason.
The UI accepts no exporter password, community or token.

Verification and enrollment are separate. A transport-only preflight does not
prove authentication, live metric health or physical identity. Approval displays
authorized **intent**, not a healthy scrape. No automatic enrollment follows
device creation or preflight. Approval is valid for 1–720 hours, default 168;
intervals are 15–3600 seconds and timeouts 1–30 seconds, strictly below the
interval. Withdrawal preserves the enrollment, advances its revision and audits
the transition. Approval audit events retain each revision's public collection
settings and expiry, without credential references/material or private hashes.

## Ownership and trust boundaries

| Component | Authority and custody |
|---|---|
| Control plane | Namespace/site/device-scoped enrollment intent, revision, identity/configuration pins, expiry and audit; no exporter I/O or monitoring configuration writes |
| Gateway | One explicit namespace, protected network/profile allowlists, a scoped `assets.read` API identity, Prometheus caller authentication and optional exporter TLS/Bearer files; no ORM or database credentials |
| Prometheus | One operator-installed HTTP discovery job and its own private gateway-token copy; receives public targets/labels and current authorized metric bytes |
| SNMP exporter | Existing separately owned SNMP credential/configuration custody; gateway maps an approved credential-profile ID to an operator-chosen exporter auth name |
| Windows exporter | Device-side HTTPS metrics service, trusted CA and optional client TLS/Bearer; HTTP requires a protected operator exception |

API permissions do not let a user invent a gateway custody profile. Root-owned,
non-writable configuration independently binds protocol, site, literal target
CIDRs, ports, credential-profile IDs and permitted modules/collectors. A missing
credential profile is accepted only when that protected profile explicitly
permits `null`. Mapping a metadata credential ID to the correct physical exporter
auth realm requires operator/live-lab qualification, not merely matching names.

## Discovery is not scrape authorization

Prometheus retains previous HTTP discovery targets on fetch errors; HTTP 200
with an empty list clears them. This is documented in the
[Prometheus HTTP discovery contract](https://prometheus.io/docs/prometheus/latest/http_sd/).
Consequently discovery alone cannot implement immediate withdrawal.

The gateway returns authenticated HTTP 200 `[]` on discovery backend failures,
and every `/scrape/{enrollment_id}` independently checks current API authority
before exporter I/O and again before returning metric bytes. API failure,
disabled device/connection/credential, changed identity/configuration/scope,
withdrawal or expiry rejects the request. Protected configuration and exporter
file contents are compared across I/O, and Prometheus caller authentication is
checked again before the response. No durable or last-good authorization cache
survives failure or process restart.

Public discovery groups include pinned device/connection/enrollment/revision,
tenant/region, site, protocol and the actual target instance. They point to the
local gateway, not directly to the exporter. Discovery carries per-target
`__metrics_path__`, interval and timeout using the
[Prometheus configuration contract](https://prometheus.io/docs/prometheus/latest/configuration/configuration/).
`honor_labels: false` keeps the operator's discovery labels authoritative.

Authorization snapshots expire within 30 seconds; an individual scrape is
bounded by its timeout and initial authority expiry. The complete snapshot is
capped at 10,000 candidate enrollments: excess fails, never publishes a silently
truncated list. API/metric bodies, parser lines, samples and label counts/lengths
are bounded. Concurrency is bounded; the default listener is literal loopback.
No ambient proxy or redirect is followed. API and remote exporter TLS validate
certificates/hostnames; HTTP API access requires an explicit literal-loopback
exception. Secret files and their ancestors must be root-owned and non-writable,
with no world-readable private material or symlink-file substitution.

An already dispatched read can finish while authority is revoked; post-I/O
revalidation discards its result. SQL, file rotation and remote I/O are not one
atomic transaction. These checks do not promise zero-latency cancellation,
exactly-once remote activity or verified physical truth. Restart behavior is
verified with fresh source gateway objects, not an installed systemd process.

## Native deployment, only after approval

Use these source templates as inputs to a coordinated accepted candidate:

- [Gateway unit](../deploy/systemd/icheck-monitoring-gateway.service).
- [Protected profile example](../deploy/systemd/monitoring-gateway.config.json.example).
- [Prometheus job example](../deploy/prometheus/gui-continuous.yml.example).

Provision the isolated `icheck-monitoring-gateway` account, a required-auth,
namespace/site-scoped service principal with **only `assets.read`**, and root-owned
private files under `/etc/icheck-workers/monitoring-gateway`. The gateway and
Prometheus receive separate custody copies of the same gateway caller token;
the API token and exporter material remain separate. Configuration and secrets
are readable only by their owning component. Root decides any Windows HTTP
exception and the exact exporter auth mapping. Listener/concurrency changes
require a coordinated restart; profile/material changes are reread per attempt.

Apply the migration and deploy the coordinated API, frontend and gateway through
the native release process, not by starting the gateway against installed r30.
Then add the discovery job once to operator-owned Prometheus configuration.
Remove overlapping legacy manual targets to avoid duplicate scraping. Existing
manual file-discovery lists remain unchanged until that accepted cutover. The
Prometheus example passes installed `promtool --syntax-only`; missing private
files, real permissions, TLS and native lifecycle are not accepted by that check.

Current templates name 19 OS accounts, 21 total units and 14 required Python
units; the new gateway needs no SQL Worker profile. All nine existing internal
controller profiles are source-reviewed; six still await native provisioning.
Ten required native Python units remain unaccepted, including the gateway.
The prior privileged deployment refusal has not been retried or bypassed.

## Verification and remaining release work

The source record (private development evidence; not distributed)
accounts for 59 distinct ordinary cases, 27 disposable PostgreSQL cases and 36
static native-identity cases across corrected segments. PostgreSQL subjects use
the existing broader non-owner application grants, not a new restricted gateway
SQL role. RLS/trigger guards, actual editor contention, concurrent first approval,
audit rollback, transaction-mode refusal and populated downgrade protection pass.
The full empty SQLite migration roundtrip passes. Frontend typing/lint and a
real Chromium journey with synthetic API responses pass; that
browser journey (private development evidence; not distributed)
also corrected the HTML gateway-profile validation pattern and narrow-viewport
navigation overflow.

Four static release-boundary cases pass: the gateway is mandatory,
its command/unit and database-free custody agree, and the current verifier
rejects the frozen pre-gateway r31 operator tree, and the custody/job examples
are required operator files. Historical artifact helpers now load recorded
policies independently of the current r34 candidate gate. The current mandatory
unit remains required; historical snapshots do not satisfy that gate.

The subsequent [query checkpoint](metric-query-authorization.md) implements
generic metric series-scope authorization and stable Agent/device label
integration at source level. Backend-row RLS alone does not isolate series on a
shared Prometheus server. Remaining work includes an accepted batched native
candidate, required-auth live API/browser journey, installed gateway start/
restart/revocation, real exporter TLS/auth and metric ingestion, representative
fleet/API/exporter load, installed drain/capacity/recovery, production identity/
transport/secrets and the user's GUI-onboarded six-class lab. None of these is
replaced by synthetic UI/exporter fixtures. The demo remains deferred.
