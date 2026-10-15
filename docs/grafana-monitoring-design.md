# Grafana monitoring integration design

## Bounded metric discovery

Metric-name discovery ranks an exact name first, then prefix and substring
matches, before applying the result limit. Searching for `up` must not hide that
metric behind alphabetically earlier `*_updates_*` names. Responses include the
match count, exact match, truncation flag and a next action; no matches means
unavailable data, not an invented metric. Retained names do not prove fresh samples.

The existing reasoner also receives bounded prior observations from the same
investigation so a subsequent metric search does not discard discovered
connection and datasource IDs. Duplicate-call protection and reviewed Grafana
confirmation remain unchanged. See [the runtime contract](agent-runtime.md).

## Metric backend identity and sample queries

Deployed r19.13 distinguishes Grafana datasource UIDs from iCheck
metric backend IDs. `metrics.backends.list` discovers enabled backend IDs,
names and providers in the current namespace, with a bounded list and optional
exact-name filter. It requires `metrics.read` and returns no endpoint URLs,
credentials, health errors or external labels. It does not prove a mapping
between a backend and a Grafana connection. Existing scoped PromQL tools still
enforce namespace and device selectors.

For dashboard authoring, `grafana.metrics.query` reads existing samples directly
through the selected connection's configured datasource. It shares Grafana's
global-workspace permission and acknowledged shared-dataset boundary; it is not
available to device/site-scoped investigations. This matters for native platform
self-metrics, which do not carry iCheck namespace labels and are intentionally
invisible to generic scoped queries. No ingestion or scope rule is weakened.

The native query accepts concrete instant-vector PromQL over observed metric
names, a maximum of 100 samples and a three-second upstream query budget. It
uses the existing bounded, credential-redacting transport and returns sanitized
labels, explicit truncation and missing-data warnings. Evaluation timestamps
do not prove source freshness; `timestamp(metric)` can inspect stored sample
times. It neither probes devices nor applies dashboards. All 63 focused checks
passed with simulated transports. The deployed query returned the existing
Prometheus and SNMP exporter self-metrics, their stored sample times and an
aggregate scrape-up count of two. These are platform observations, not lab device
health. A separately approved r19.13 Studio demo subsequently completed two live
agent runs: create and revise. Both reviewed proposals were applied to the same
dashboard; the native page shows two platform targets and real stored-sample ages.
All ten tool calls succeeded, with 43,644 reported tokens. The original version
is retained and its rollback preview matches the original panels; restoration
was not applied. The model omitted the requested saved one-hour range, so this
remains a qualified dashboard journey with an intent-fidelity limitation, not
complete support for every requested setting.

Deployed r19.14 explicitly advertises native `time.from`/`time.to`,
`refresh`, timezone and description in the existing typed tool contract. An
empty refresh string means off; omission is not silently replaced. Revisions
are instructed to preserve current settings. Both the API and tool boundary
check bounded field shapes, leaving native date-math interpretation to Grafana.
The human review surface shows the proposed saved range, browser refresh and
timezone outside Advanced, including a warning when a setting was omitted.
These use [Grafana's native JSON model](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/view-dashboard-json-model/),
not new collection schedules or a second renderer. Sixty-four focused backend
cases and seven frontend cases pass; the native build and type check pass.
Guarded catalog synchronization accepts only recognized system-owned prior
schemas and preserves custom registrations and disabled state. Source checks
do not prove the model will honor a future request; no paid rerun is included.
The live registered schema and authenticated review page passed, alongside
password sign-in and read-only API checks. Existing dashboard definitions were
not rewritten, and SQL, runtime configuration and custody keys were preserved.

## Product decision

Accepted direction on 12 October 2026. Native Grafana, baseline dashboards and
full-page Operator/device links are deployed. The native AI tool adapter,
confirmation UI and monitoring/Studio workflows are deployed through the paired
preview. Live create/revise/review/apply is verified for a platform dashboard;
saved time-range intent and representative lab acceptance remain outstanding.
The target is an engineer-usable preview, defined in the [development goal](codex-goal.md).
iCheck handles intent, configuration, capability authoring, investigation,
inventory, and approvals. Prometheus handles continuous metrics collection and
storage. Grafana owns every monitoring chart, panel, and metric dashboard.

The deployment added `grafana-server.service` alongside the unchanged
`icheck-prometheus.service` and `icheck-snmp-exporter.service`. See
[Grafana access and operation](grafana-access.md) and its live deployment record.
The current deployment record (private development evidence; not distributed)
identifies the selected backend, GUI and SQL head. The initial Grafana installation
was a GUI-only change; subsequent paired releases added native integrations while
preserving existing devices, credentials and monitoring boundaries.

## Ownership and data flow

```text
Engineer conversation or guided input
                 |
       iCheck AI Operator and Capability Studio
                 |
       LangGraph and typed plugin tools
          /                    \
 approved collection plan    approved Grafana dashboard definition
          |                    |
 native exporter or adapter   Grafana HTTP API
          |                    |
 Prometheus scrapes ----------> Grafana queries and displays
          |
 Prometheus rules -> Alertmanager -> iCheck alert and investigation

Inventory collectors -> PostgreSQL IP, MAC, Wi-Fi, identity and history
AI investigation -> scoped metric queries, inventory and diagnostic tools
```

An inventory status, run receipt, evidence table, or pending approval is still
iCheck UI. An interface utilization graph, CPU history, availability gauge, or
metric topology belongs in Grafana. Do not rebuild those panels in React or
mirror continuous high-cardinality samples into PostgreSQL. Existing bounded
evidence samples may remain; they are not the new time-series store.

## Native deployment and browser access

Install a dedicated, pinned Grafana OSS package using a native systemd service
and a separate service account. Discover occupied ports before installation;
the existing Next.js frontend uses port 3000, so use a free loopback port such
as 3001. Preserve the existing Prometheus TSDB, jobs, exporter configuration,
device approvals, and all application credentials. Grafana uses its own data
directory and backup; it must not own iCheck's database tables or secret keys.

Expose Grafana through the existing HTTPS ingress under `/grafana/`, configuring
its external root URL and subpath routing. Do not expose an unauthenticated
port on the LAN. Keep Grafana's own sign-in for the first preview; an iCheck
session is not automatically a Grafana session. The initial setup hands the
operator a separate account securely, with no default/shared password in source.
Native installation is supported by [Grafana's Ubuntu installation guide](https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/).

The Dashboards menu opens the Grafana landing dashboard. Device, alert, and AI
results expose **Open in Grafana**, with a safe return link to iCheck. Carry the
dashboard UID, approved variables, time range, and time zone; never a token.
Use a normal link/new tab for the initial release. Optional iframe embedding
and shared identity are later UX improvements, not requirements for displaying
metrics. Grafana embeds still require an authenticated session unless anonymous
access is enabled; this design keeps anonymous access off.
[Grafana sharing documentation](https://grafana.com/docs/grafana/latest/visualizations/dashboards/share-dashboards-panels/).

Device status and device-source alerts resolve the last applied native Studio
dashboard for each connection, including HTTP, Linux, Windows, containers and
VMware. `GET /api/v1/grafana/devices/{device_id}/dashboards` reads retained saved
changes in the selected namespace; it does not call Grafana, Prometheus or the
target. It requires global `metrics.read`, `assets.read` and device access.
Links carry `var-device`, `var-connection` and the selected time range; alerts use
15 minutes before and after their last observation. Disabled target connections
retain historical links. Pending proposals do not appear as saved dashboards.
The bounded resolver covers native-template UIDs, not arbitrary custom dashboard
associations. Externally deleted or edited resources may leave a historical URL.

AI tool-result cards offer actual saved resource URLs for applied changes and
native Grafana read/search/link results. Proposals retain a separate local review
link; unknown writes never become presumed saved resources. URLs require HTTPS,
bounded native resource paths and non-secret context parameters. Tool names in
the retained call listing are display metadata, not new execution authority.

Provision one Prometheus data source with a stable UID, for example
`icheck-prometheus`, pointing server-side at the existing private Prometheus
endpoint. The URL is installation configuration, not model input. Do not expose
Prometheus credentials to the browser. File provisioning owns this baseline
data source; the AI diagnoses it or proposes an operator-applied connection
change instead of making a conflicting API edit. Grafana supports configuration
and provisioning of the built-in [Prometheus data source](https://grafana.com/docs/grafana/latest/datasources/prometheus/configure/).

Preview access is limited to a trusted engineering team allowed to read the
whole connected metric data set. iCheck object permissions do not automatically
transfer to Grafana, and dashboard variables are filters, not security controls.
Do not grant direct Grafana access to a restricted device/site user until query
isolation exists. Folder permissions do not provide series-level isolation.

## Native adapter first and optional MCP

Implement `grafana` as a small native plugin behind the existing Tool Registry,
using Grafana's supported HTTP API for the installed version. Reuse the platform
HTTP client, credentials, permission checks, execution receipts, and timeouts.
Store the internal API URL, public browser URL, data-source UID and managed folder
UID in the selected iCheck workspace. The native API uses Grafana's `default`
namespace and the service token's organization. The service token is encrypted
server-side, bound to the connection identity, namespace, endpoints and revision.
The native v1 resource API is qualified on the installed OSS 13.2.3: custom change
annotations survive readback and stale `resourceVersion` updates are rejected.

The first tool surface is deliberately small:

| Tool | Purpose | Mutation boundary |
| --- | --- | --- |
| `grafana.health` | Check API and configured data-source readiness | Read only |
| `grafana.connections.list`, `.health`, `.metrics.discover` | Discover connection readiness and actual metric names | Read only |
| `grafana.dashboards.search`, `.folders.search`, `grafana.dashboard.get`, `.folder.get` | Find managed resources and their exact current versions | Read only |
| `grafana.dashboard.preview` | Validate a proposed dashboard and show the change | No Grafana write |
| GUI confirmation endpoint | Create or update an iCheck-managed dashboard or folder | One human confirmation of exact plan and expected version |
| `grafana.dashboard.link` | Return a safe contextual URL | Read only |
| `grafana.dashboard.restore.preview` | Propose the retained previous definition | New confirmation required |
| `grafana.changes.get` | Read durable proposal/apply status and saved URL | Read only |

These eleven tools are registered in the existing typed Tool Registry and
advertised to permission-scoped agent profiles. None can apply a Grafana write.
The current source proposal schema describes native integer panel IDs, Prometheus
query targets, the configured data-source shape, grid bounds and query/custom/
constant variables. Data-source and layout fields may be omitted for server-owned
defaults; explicit unapproved sources are rejected. Local source/query/secret
checks remain mandatory. This guidance update does not validate earlier rejected
model proposals or change an applied dashboard.
The AI returns a local review link; `/dashboards` shows panel queries, variables,
target, current version and retained definition. The human's single confirmation
calls `POST /api/v1/grafana/changes/{id}/confirm` with the exact plan hash.
API access requires global `metrics.read`; configuration and confirmation require
a human user with global `metrics.manage`. Device/site-scoped profiles cannot gain
shared-dataset access; service identities cannot configure or confirm changes.
Existing scoped PromQL tools still provide metric querying; there is no arbitrary
HTTP tool. A create operation uses a stable planned UID. An admitted write is
durable before HTTP I/O; after response loss, inspection of the same UID and
change annotation can finish its receipt but never repeat that write. An update uses the installed API's version/concurrency
guard and never blindly overwrites a dashboard edited in Grafana. Keep old and
new definitions plus the real remote result. A conflict asks the user to reload
or save a copy. Dashboard deletion is not necessary for the first slice.

Use a separate Viewer service account with Edit permission on the managed root
folder, preserving its existing ACL. Use a service-account token with only the permissions needed for the managed
organization/folder, as supported by the installed edition. Keep bootstrap admin
authority separate. Tokens remain in server-side secret custody, never model
context. Grafana documents service accounts as the API automation identity,
with edition-dependent permission granularity.
[Service accounts](https://grafana.com/docs/grafana/latest/administration/service-accounts/),
[dashboard API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/dashboard/).

Connection settings are at `/settings/grafana`, including readiness, enable/disable
and token rotation. URLs and data/folder bindings are immutable for a connection;
use a new connection for a different destination. Rotation invalidates pending
proposals; uncertain admitted writes may be inspected using fresh credentials
only against the original binding. The shared-data acknowledgement is explicit.
The protected key may be a dedicated `ICHECK_GRAFANA_SECRET_KEY_FILE` or the existing
`ICHECK_AI_MANAGED_SECRET_KEY_FILE`; different authenticated-encryption contexts
separate the integration secrets. Retain that key with PostgreSQL backups.

The preview bounds resources to the root and its immediate child folders, 20
standard metric panels, 8 queries per panel, and 12 query/custom/constant variables.
All queries use the configured Prometheus source and explicit observed metric
names. External links, credential-bearing URLs and foreign/plugin data sources
are rejected. A catalog entry can be historical: validation does not prove fresh
samples. Search reads at most 100 resources and reports truncation. Remote Grafana
versions, deep folder nesting and deletion are not qualified for this slice.

The official [Grafana MCP server](https://github.com/grafana/mcp-grafana) already
offers dashboard and query tools and a read-only mode. It is a valid optional
transport plugin when external agents or remote deployments need MCP. Do not
build a new bespoke Grafana MCP server for the preview, or run both transports
as competing owners. The native adapter minimizes additional service setup and
reuses current iCheck governance. An MCP adapter must honor the same user scope,
query limits, secret custody, and approved mutation contract.

## Dashboard generation

Use supported Grafana panels and dashboard JSON, with reusable templates for
network interfaces, Linux, Windows, HTTP probes, containers, and VMware. Inspect
real metric names, labels, units, and freshness before choosing queries. Never
invent vendor OIDs or metric names because a desired panel needs them. Show
missing/unsupported data explicitly. Counter charts need rates; interface
utilization needs an observed link speed and a clear unknown state when absent.

An AI-authored dashboard is validated against the installed Grafana version,
allowed data source, supported panel types, and bounded queries. Validate
external links and disallow injected scripts or arbitrary plugin installation.
User-created panels may be edited through Grafana. iCheck must detect version
conflicts and import those changes before its next update.

Choose one owner per resource: file provisioning for baseline data-source
configuration; API-created resources for AI-managed dashboards. Do not also
file-provision the same dashboard UID. Provisioning can overwrite database/UI
changes; the ownership split follows [Grafana's provisioning behavior](https://grafana.com/docs/grafana/latest/administration/provisioning/).

## Monitoring plugins

| Monitoring type | Collection path | First usable outcome |
| --- | --- | --- |
| SNMP network devices | Generated and installed snmp_exporter module; existing approved gateway/discovery path | Interface state, traffic/errors, available device health; Grafana dashboard |
| HTTP and HTTPS | Blackbox Exporter for probes; generated HTTP/API adapter for numeric JSON data | Status, latency, TLS expiry; authenticated API metric |
| Linux | node_exporter with approved scrape access | CPU, memory, disk and network dashboard |
| Windows and WMI | windows_exporter for routine metrics; bounded WMI/CIM adapter for custom queries/diagnostics | Windows host dashboard and one working CIM query |
| Containers | cAdvisor or runtime/API exporter selected for the target | Per-container resource and restart evidence where exposed |
| VMware | A reviewed vSphere API exporter/adapter and a read-only account | Host/datastore/VM metrics with supported API/version limits |

These are target integrations, not installation claims. Validate the selected
exporter license, maintenance, supported target version, and authentication
before adding its dependency. A custom WMI/API metric adapter must expose a
scrape endpoint or safe cached metric output; on-demand diagnostic results do
not automatically become a continuous metric pipeline. Prometheus describes
the SNMP/blackbox pattern in its [multi-target exporter guide](https://prometheus.io/docs/guides/multi-target-exporter/).

Parse supported curl syntax into a structured URL/method/header/body request;
do not execute the supplied shell string. Reject shell substitution, file
uploads, unsupported flags, and unapproved network destinations with a clear
explanation. Secrets are entered through protected fields or existing references
and redacted before authoring. Require confirmation for methods/operations that
can change target state. Prefer GET/HEAD for routine probes.

A monitoring template binds the collector/module version, metric schema,
credential reference, allowed targets, interval/timeout, optional alert rules,
and Grafana dashboard template. Activation records each phase independently:
validated, collector installed, target enabled, samples observed, dashboard
ready. Partial failure stays visible and retry resumes only the failed phase.
Rollback restores owned configuration; it never deletes shared exporters or
unrelated dashboards. An explicit enable confirmation covers the displayed
plan, avoiding a stack of repetitive approval forms.

## Alerts and troubleshooting

Prometheus evaluates metric thresholds; Alertmanager groups and routes their
notifications. Add the Alertmanager deployment/ingestion adapter as a planned
feature, not an assumption about the current host. Retain iCheck inventory-event
alerts and map incoming metric alerts to device/time evidence and investigations.
Create one deduplicated episode per source alert, including resolution and
unknown-source states. Do not simultaneously provision the same rule in Grafana
Alerting and Prometheus. Grafana displays the metric evidence; iCheck owns AI
analysis, acknowledgement, proposed next actions, and approved execution.

For a known task, reuse deterministic LangGraph nodes. For an investigation,
loop through bounded evidence collection and hypothesis revision with tool,
step, wall-time, and model-cost limits. Missing capabilities can start a Studio
draft, but the loop cannot silently enable new collectors, broaden a network
scope, or grant itself permissions. Self-improvement means reviewed reusable
capability revisions and measured outcomes, not privileged self-patching.

## Acceptance and exclusions

The first slice must show real existing Prometheus series in Grafana and a
working contextual link from iCheck. Follow it with an AI-created dashboard and
one confirmed update, then conversational SNMP/HTTP template activation. Check
fresh metric timestamps and values, not only an HTTP 200 or dashboard existence.
Use a controlled lab fault for one alert and evidence-backed investigation.

Keep one focused workflow check plus relevant auth/secret/configuration
regressions for each changed slice. A desktop browser smoke and narrow-screen
usability check are sufficient for the preview UI changes. Do not rebuild every
historical release, run unrelated full suites, or repeat whole-tree SHA checks
for a documentation change. Necessary package integrity and security checks
remain at the actual installation or distribution boundary.
