# Monitoring integrations and portable operation packages

## Delivery and deployment boundary

N1–N3 are included in engineering prerelease **r19.28**. The public distribution
contains application code, reusable built-ins and empty configuration templates.
It contains no private deployment receipts, accounts, credentials or lab inventory.
Installation does not activate a source, package import, alert feed, recurring
schedule or AI investigation policy.

The schema head is `h1n3q5s7u9w2`, following provider migration `g0m2p4r6t8v1`.
Back up SQL and configuration before migration. Restart the API, agent workers,
integration inventory worker and integration alert worker with the same release.
No new container, queue, secret service or Python dependency is required.

Offline fixtures, temporary PostgreSQL and synthetic browser checks are not live
vendor qualification. Complete the lab checklist below before enabling automatic
investigation in a real environment.

See the [public qualification record](../acceptance/public-preview-qualification.json)
and the prerelease's native installer acceptance asset for verification evidence.
Live vendor interoperability and representative fleet acceptance remain pending.

### Server readiness before lab tests

The native installer creates one protected policy file,
`/etc/icheck/monitoring-integrations.env`, shared by the API, inventory worker,
alert worker and investigation dispatcher. Its
`ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS` setting retains the prior API
policy across those consumers. The initial value is empty and denies external
connector requests until an administrator approves a source.

Before testing a new monitoring product, the server administrator adds only its
approved exact HTTPS origin, including a non-default port, for example:

```ini
ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS=https://zabbix.example.test,https://orion.example.test:17774
```

These are documentation examples, not installed endpoints. Keep API paths,
passwords and tokens out of this setting. Install the source's trusted internal
CA if needed; do not disable TLS verification. After an approved policy edit,
restart the four consumers:

```sh
sudo systemctl restart icheck-control-plane.service \
  icheck-integration-sync-worker.service icheck-integration-alert-worker.service \
  icheck-workflow-dispatch-worker.service
```

Then perform connection setup, source-group selection, synchronization, mapping,
package review/import and explicit activation through the GUI. Creating a saved
connection alone does not contact the source.

## N1: external monitoring

Open **Monitoring → Integrations**. The supported choices are:

| Product | Authentication | Initial scope |
| --- | --- | --- |
| Zabbix | Read-only API token | Zabbix 7.0/7.4 host groups, trigger alerts, numeric item history |
| SolarWinds Platform / Orion | Read-only SWIS username/password | SWIS v3, 2024.2 entity schema; groups containing nodes, node alerts, detailed response-time/loss/availability history |
| REST / webhook bridge | Read-only bridge token | The versioned `icheck.monitoring-bridge/v1` contract |

SolarWinds Observability SaaS is not the Orion API. Orion cumulative alerts and
non-node entities are not projected by this initial adapter. The limitation is
intentional: a multi-object alert must not be guessed to belong to one device.
Detailed Orion history uses `Archive=0`; an empty window may reflect source
retention and does not imply healthy operation.

The administrator approves exact HTTPS origins with
`ICHECK_MONITORING_INTEGRATION_ALLOWED_ORIGINS`. A typical Orion origin includes
port 17774. Install an appropriate trusted CA for an internal certificate; TLS
verification is never disabled. Credentials are encrypted using existing native
key custody, write-only in the GUI, and unavailable in exports or audit details.

1. Save a connection. It starts disabled and does not contact the source.
2. Discover groups, choose scope once, and preview resources.
3. Enable and synchronize inventory. Imported inventory does not enroll duplicate
   SNMP or other polling.
4. Review bulk mappings to existing canonical assets.
5. Enable the separate alert feed if wanted.
6. Enable an existing standing investigation policy only when ready for AI use.

The inventory and alert workers use the same provider factory, protected
transport, limits, current scope and cancellation rules. No provider-specific
agent or duplicate collection pipeline is introduced.

### Alert semantics

- Acknowledgement does not stop investigation.
- Source muting/suppression, disabling the source alert, source reset/clear,
  local silence and local closure stop automatic investigation.
- Orion effective suppression is read through the fixed read-only
  `Orion.AlertSuppression.GetAlertSuppressionState` verb, including inherited
  parent muting. No suppression or acknowledgement write verb is exposed.
- Orion episode identity is the trigger's `AlertHistoryID`. Reset/clear evidence
  must match both `AlertActiveID` and `AlertObjectID`. A missing active row without
  historical reset/clear evidence is unknown, not recovery.
- Closed episodes do not restart automatically. A new source episode has a new
  identity. In-flight requests may finish; no further step is admitted.
- Unavailable, inconsistent or out-of-scope evidence blocks further automatic
  work. Source text is untrusted data, not agent instructions.

SolarWinds implementation references:
[REST and parameterized queries](https://solarwinds.github.io/OrionSDK/docs/rest/),
[alert entities and suppression](https://solarwinds.github.io/OrionSDK/docs/alerts/),
[group membership schema](https://solarwinds.github.io/OrionSDK/2024.2/schema/Orion.ContainerMembers.html),
[response-time schema](https://solarwinds.github.io/OrionSDK/schema/Orion.ResponseTime.html).

### Connector bridge and webhook contract

See [the bridge template contract](monitoring-bridge-contract.md). A vendor
connector implements fixed read operations at one approved HTTPS endpoint.
Different products can implement this contract without changing iCheck core.
Bridge code runs at its operator-controlled endpoint, not as unrestricted code in
the API process.

An authenticated `POST /api/v1/integrations/connections/{id}/notify`, with
`{"expected_revision": 2, "confirm": true}`, is a recheck hint. Use an existing
platform API identity with workspace-wide `metrics.read`, `metrics.manage` and
`alerts.manage` permissions. It cannot carry alert contents, URLs, credentials,
commands or AI instructions. The connection and alert feed must already be
enabled. Notifications are coalesced at the configured feed cadence. The worker
reads the source before persisting a state or admitting investigation. API
authentication and revision checks apply; this is not a public anonymous webhook.

## N2: portable capabilities

Open **Capability Studio → Packages & built-ins**.

The new `icheck.operations-package/v1` format is a portable recipe layer over the
existing Artifact lifecycle. It supports workflows, Skills, external MCP tool
contracts, generated multi-tool MCP servers, collectors and connector requirements.
It is not an executable archive or a new unrestricted runtime.

### Export

Select validated/published versions, enter a package name, version and description,
and download JSON. The exporter:

- omits source Artifact IDs, Tool Registry IDs, deployment/session/history records
  and runtime schedules;
- exports semantic tool contracts and rebuilds destination-local registry IDs;
- pins generated MCP implementation hashes, not just familiar tool names;
- clears collector-level credential bindings;
- refuses known local-binding fields, non-documentation IPv4 literals, non-example
  endpoint URLs and recognizable credential material instead of silently
  exporting them.

Use runtime input schemas for targets. Use documentation addresses in synthetic
fixtures. Review source and fixtures before sharing: detection is a guardrail,
not a proof that arbitrary prose or code contains no confidential information.
The exporter does not rewrite arbitrary code or remove customer-specific meaning
from free text.

### Import and local setup

Choose the JSON file. Select existing local connections for connector requirements
and local MCP servers for external tool contracts. Never paste credentials into
the package. Connection bindings establish local dependency readiness; they do
not grant execution permission or override the alert/device chosen at runtime.
Current runtime authorization is still checked on every tool call.

**Check readiness** compares dependency contracts. **Approve and import** performs
local validation and records the package transactionally. Validated components
appear in the normal capability library.

If a workflow or Skill depends on an MCP server included in the same package,
import stages that dependent component as an inactive draft. Install the included
MCP server through its **Install / manage MCP server** link, then choose
**Recheck dependencies and validate drafts**. This compiles local registry
references only if the tools and immutable implementation still match.

Import does not publish artifacts, register tools, contact devices, run paid AI,
enable collection or start schedules. Publish reviewed workflow/Skill versions,
install MCP packages, and activate recurring work through the existing controls.
An MCP server is installed once with all its tools; no per-device installation
or mandatory live test is required.

Repeated imports of the same package/version/digest return the same receipt.
Different content under an existing package version is rejected. Existing
Artifact names are not overwritten. Use the existing version/restore controls
for revisions, and advanced signed packs for governed upgrade lineage,
revocation and uninstall impact. A package receipt is not a health assertion
and does not silently reactivate a disabled MCP server.

### Trust

The default optional-signature policy permits an explicitly reviewed unsigned
recipe import. Under `ICHECK_ARTIFACT_SIGNATURE_POLICY=required`, external recipes
require an Ed25519 signature from an enabled local key with `capability_pack`
purpose. Upload an envelope with `package` and `signature` fields. The signed
message is UTF-8 `icheck.operations-package/v1`, a newline, then the package's
lowercase SHA-256 digest. Use the existing trusted-key administration.

Shipped built-ins are accepted only when their entire package matches the
server's shipped catalog; a client cannot assert that uploaded content is
built-in. Advanced signed packs retain their separate format and full lifecycle.

## N3: shipped operations

| Package | Included capabilities | Additional readiness |
| --- | --- | --- |
| Zabbix Operations | Connector requirement, alert-triage Skill, bounded investigation workflow | Local Zabbix connection; mapped alert for execution |
| SolarWinds Operations | Connector requirement, alert-triage Skill, bounded investigation workflow | Local Orion connection; mapped node alert |
| Connector Bridge Operations | Connector requirement, triage Skill and workflow | A conforming local bridge connection |
| Network Diagnostics | Cisco IOS, Cisco NX-OS and Juniper Junos MCP servers; device-health and WAN Skills; health and coverage workflows | SSH inventory and credentials only when executing network tools |
| HTTP/API Diagnostics | Service-health Skill and bounded diagnosis workflow | An enrolled service with observed metrics |
| Configuration Backups | Scheduled Cisco IOS protected-backup workflow | Install the Cisco IOS server from Network Diagnostics, then explicitly activate a schedule |

Each network server contains two tools: interface status and protected configuration
backup. Raw configuration remains in protected platform custody; AI receives a
receipt, not the configuration body. The interface parser returns observed link
states, not an assertion that every vendor/OS output has been qualified.

HTTP/API diagnostics uses enrolled monitoring evidence; it is not a new arbitrary
HTTP client or an HTTP MCP server. Network configuration writes, automatic OS
upgrades, ISP email delivery, CVE remediation and new CMDB products are outside
N1–N3. No schedules or paid calls start when the catalog is opened or imported.

## Lab acceptance

After a separately approved deployment:

1. Add one Zabbix or Orion connection using the GUI. Verify credential rotation,
   group scoping, inventory sync and bulk canonical mapping.
2. Trigger an alert. Enable a bounded standing policy. Check source attribution,
   metric discovery/history and absence of duplicate device polling.
3. Test acknowledgement, source mute, inherited Orion mute, reset/clear, local
   silence and local closure. Check that only acknowledgement permits continuation.
4. Disconnect the monitoring API. Confirm unknown evidence stops further automatic
   work and does not fabricate recovery.
5. Export a package, import into a clean namespace/installation, bind local
   connections, install its MCP server and prepare dependent workflows.
6. Invoke interface status and protected backup against a permitted test device.
   Confirm one server/two tools and retained backup receipts.
7. Publish the backup workflow and explicitly configure a test schedule. Verify
   scope, cancellation and custody. Disable the schedule after the test.

Live product/version compatibility, fleet-scale performance and sustained
production behavior remain lab/release acceptance tasks, not claims made by
synthetic fixtures.
