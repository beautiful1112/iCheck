# iCheck — AI-Native IT Operations Agent Platform

## 1. Project Name

**Recommended name: `iCheck`**

`iCheck` is preferable to `Icheck` because it is visually cleaner, easier to read, and naturally suggests:

- **i** = intelligent / infrastructure
- **Check** = observe, verify, diagnose, validate

Possible positioning:

> **iCheck — AI-Native Infrastructure Operations**

Alternative tagline:

> **Observe. Understand. Act.**

---

# 2. Vision

iCheck is an **AI-native IT infrastructure agent platform** for monitoring,
investigation, management, and change governance.

It is not intended to be a traditional NMS with an AI chatbot added on top.

It is also not merely a monitoring product whose capabilities are fixed by the
vendor's release cycle. The product itself is an agent runtime and an in-product
capability studio. A user should be able to describe a requirement in natural
language and have iCheck create, test, publish, operate, and later revise the
required capability without leaving iCheck for a separate IDE.

The core idea is:

> The AI acts as an infrastructure engineer, while the GUI provides visualization, evidence, operational awareness, governance, and human authorization.

The intended product experience is closer to a general AI agent than a
traditional monitoring console:

```text
User states an operational purpose
             ↓
AI investigates or designs the missing capability
             ↓
iCheck validates it in a governed runtime
             ↓
User reviews evidence or an artifact diff
             ↓
The capability is published and becomes reusable by other agents
             ↓
The user iterates it through further conversation
```

The platform should combine:

- Infrastructure discovery
- CMDB / infrastructure knowledge
- Metrics
- Events
- Logs
- Topology
- Alerts and incidents
- AI investigation
- Root-cause analysis
- Infrastructure management
- Change automation
- Peer review
- Human approval
- Audit
- External platform integration
- In-product creation of collectors, topology views, tools, skills, and workflows
- Versioned capability publishing, validation, rollback, and reuse

---

# 3. Design Principles

## 3.1 AI-First, Not GUI-First

Traditional monitoring systems force users to navigate:

```text
Dashboard
  → Device
    → Interface
      → Metric
        → Logs
          → CLI
```

iCheck should instead allow:

```text
User:
"Why is the payment service slow?"

AI:
- identifies affected services
- checks application telemetry
- checks Kubernetes
- checks VM/host status
- checks network path
- checks interface health
- checks recent configuration changes
- correlates events
- produces evidence
- proposes remediation
```

The GUI remains important for:

- Topology
- Incidents
- Evidence
- Time series
- Configuration diffs
- Change review
- Approval
- Audit
- Asset browsing

---

## 3.2 The Product Is Its Own Capability Development Environment

Users must be able to extend iCheck from inside the running product through a
conversation with the AI. Creating a capability must not require a separate AI
coding agent, local IDE, source-code merge, or vendor software release.

First-class user-created artifacts include:

```text
Collector
Parser / normalizer
Entity and relationship mapping
Topology view
Metric and alert definition
Diagnostic or change tool
Skill
Deterministic workflow
Agentic workflow
Visualization
Report
```

These artifacts are executable specifications, not arbitrary prompt fragments.
Every artifact must have a schema, owner, permissions, version, test fixtures,
compatibility metadata, audit history, and rollback target.

The common authoring lifecycle is:

```text
CONVERSE
   ↓
DESIGN — AI produces a typed artifact and explains its assumptions
   ↓
VALIDATE — schema, policy, secret, dependency, and security checks
   ↓
TEST — sandbox execution against fixtures, replay data, or approved targets
   ↓
PREVIEW — output sample, topology preview, workflow trace, or configuration diff
   ↓
APPROVE — policy-driven human approval where required
   ↓
PUBLISH — immutable version enters the registry
   ↓
DEPLOY / RUN — scoped rollout with telemetry and health checks
   ↓
OBSERVE / ITERATE / ROLLBACK — continue through conversation
```

"User extensible" does not mean that an LLM may silently modify production code.
The AI may propose and generate artifacts, but deterministic platform controls
own validation, credentials, publishing, rollout, and rollback.

## 3.3 Everything Is an Entity, Relationship, Observation, Event, Artifact, or Tool

The internal data model should normalize infrastructure around five fundamental concepts.

### Entity

Examples:

```text
Device
Interface
Server
VM
Kubernetes Cluster
Pod
Database
Application
Storage Array
Site
Rack
Service
```

### Relationship

Examples:

```text
Device A --connected_to--> Device B
VM --runs_on--> ESXi Host
Pod --runs_on--> Kubernetes Node
Server NIC --connected_to--> Switch Interface
Application --depends_on--> Database
Device --located_at--> Site
```

### Observation

A time-related measured state.

Examples:

```text
CPU = 43%
Interface utilization = 72%
Optical RX = -4.8 dBm
BGP state = Established
Disk latency = 7 ms
```

### Event

Something happened.

Examples:

```text
Interface changed to DOWN
BGP adjacency reset
Configuration modified
VM restarted
SNMP trap received
Windows event generated
```

### Tool

A capability that an AI agent can call.

Examples:

```text
get_interface_status()
get_bgp_neighbors()
get_windows_cpu()
query_wmi()
ping()
trace_path()
restart_service()
configure_vlan()
```

### Artifact

A versioned capability created by iCheck, a vendor, or a user.

Examples:

```text
REST API collector for an internal IPAM
Wireless-controller terminal normalizer
WAN topology view
Payment latency investigation workflow
Windows service recovery skill
```

---

# 4. High-Level Architecture

```text
┌────────────────────────────────────────────────────────────────────┐
│                    AI-NATIVE PRODUCT EXPERIENCE                    │
│                                                                    │
│ AI Operations │ Situations │ Approvals │ Generated Views │ Assets │
│ Capability Studio: Collector │ Topology │ Tool │ Skill │ Workflow │
└────────────────────────────────┬───────────────────────────────────┘
                                 │ intent, feedback, approval
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│                         AGENT RUNTIME                              │
│                                                                    │
│ Supervisor │ Specialist Agents │ Planner │ Tool Loop │ Checkpoints │
│ Evidence   │ Budget / Stop Rules │ Human Interrupts │ Escalation   │
└──────────────────┬──────────────────────────────┬──────────────────┘
                   │ use capability              │ create/revise artifact
                   ▼                             ▼
┌──────────────────────────────┐   ┌─────────────────────────────────┐
│ CAPABILITY RUNTIME           │   │ CAPABILITY CONTROL PLANE        │
│                              │   │                                 │
│ Tool / Collector Runtime     │   │ AI Designer + Artifact Registry │
│ Workflow Engine              │   │ Versioning / Tests / Replay     │
│ Execution Router             │   │ Validation / Approval / Rollout │
│ MCP Client / Gateways        │   │ Compatibility / Rollback        │
└───────────────┬──────────────┘   └───────────────┬─────────────────┘
                └──────────────────┬───────────────┘
                                   ▼
┌────────────────────────────────────────────────────────────────────┐
│                    TRUST AND GOVERNANCE PLANE                      │
│ Policy │ RBAC │ Credential Broker │ Sandbox │ Audit │ Change Mgmt │
└────────────────────────────────┬───────────────────────────────────┘
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│                  DISTRIBUTED DATA AND EXECUTION PLANE              │
│                                                                    │
│ Site Collectors: API / SNMP / WMI-CIM / gNMI / Logs / Custom     │
│ Action Workers: Ansible / Nornir / Netmiko / PSRP / Vendor APIs   │
│ Knowledge: PostgreSQL │ Metrics: Prometheus-compatible TSDB        │
│ Events / Logs │ Object Artifacts │ Queue / Scheduler               │
└────────────────────────────────────────────────────────────────────┘
```

The agent runtime is the product kernel. Monitoring, topology, and automation
are capabilities consumed and extended by that kernel rather than separate
legacy modules with a chatbot placed above them.

---

# 5. Core Modules

## 5.1 Infrastructure Knowledge / CMDB

PostgreSQL is the preferred primary database.

The CMDB should store relatively stable infrastructure objects.

### Core hierarchy

```text
Organization
  → Region
    → Site
      → Building
        → Room
          → Rack
            → Device
              → Component
                → Interface
```

### Example device attributes

```text
device_id
hostname
vendor
model
serial_number
os
os_version
management_ip
site
rack
device_role
resource_type
monitoring_profile
credential_profile
lifecycle_state
```

---

## 5.2 Dynamic Infrastructure State

Dynamic operational information should not be treated as static CMDB fields.

Examples:

```text
ARP table
MAC table
LLDP neighbors
CDP neighbors
interface operational state
routing table
BGP state
OSPF state
wireless client associations
VM state
Kubernetes pod state
```

These should use:

```text
first_seen
last_seen
observed_at
source
confidence
```

This allows AI to reason about change over time.

---

# 6. Discovery Engine

Discovery is responsible for building and maintaining the infrastructure knowledge model.

Possible discovery methods:

```text
SNMP
ICMP
LLDP
CDP
ARP
MAC address tables
REST APIs
NETCONF
gNMI
SSH
WMI/CIM
VMware API
Kubernetes API
Cloud APIs
```

Example discovery flow:

```text
Seed IP
  ↓
SNMP sysObjectID
  ↓
Identify vendor/model
  ↓
Collect interfaces
  ↓
Collect LLDP/CDP
  ↓
Discover neighbors
  ↓
Collect ARP/MAC
  ↓
Update topology
  ↓
Repeat
```

## 6.1 Generalized Collector Runtime

SNMP is one collector implementation, not the definition of collection in
iCheck. Any source that can produce observations, events, entities, or
relationships through a stable contract can become a collector.

Supported collector transports may include:

```text
REST / GraphQL / SOAP
SNMP
gNMI / NETCONF
SSH / CLI
WMI / CIM / PSRP
SQL
Prometheus scrape
OpenTelemetry
Syslog / traps / event streams
Cloud and SaaS SDKs
Files and object storage
User-defined APIs
```

A collector artifact must define:

```yaml
metadata:
  name: internal-ipam
  version: 1.0.0
  owner: network-platform

connection:
  protocol: http
  credential_profile: ipam-readonly

schedule:
  mode: poll
  interval: 300s

input_schema: {}
output_contract:
  - Entity
  - Relationship
  - Observation

normalization: {}
health_checks: {}
rate_limits: {}
test_fixtures: {}
permissions: {}
```

The in-product AI Collector Designer should accept an API description, sample
payload, MIB, command output, or plain-language requirement and generate the
collector definition, parser, mappings, tests, and preview.

Collectors must run in a distributed collector plane:

- Assign targets by site, tenant, protocol, or consistent shard.
- Use leases and heartbeats so failed work can be reassigned.
- Apply per-target concurrency, timeout, retry, jitter, and backpressure.
- Buffer transient failures without writing directly to core database tables.
- Report collector version, health, lag, and coverage to the control plane.
- Support systemd/VM deployment as the production baseline; containers remain
  an optional packaging choice.

---

# 7. Monitoring Categories

Initial resource categories:

```text
Network
  - Wired
  - Wireless
  - Firewall
  - Load balancer
  - OOBM

Compute
  - Linux
  - Windows

Virtualization
  - VMware
  - Hyper-V

Storage
  - SAN
  - NAS
  - Storage arrays

Application
  - Services
  - APIs
  - Middleware

Database
  - MySQL
  - PostgreSQL
  - SQL Server
  - Oracle

Container
  - Kubernetes
  - Docker

Cloud
  - AWS
  - Azure
  - GCP
```

Internally these should not be rigid categories.

Use:

```text
resource_type
+
capabilities
```

Example:

```yaml
resource_type: network.switch

capabilities:
  - snmp
  - ssh
  - lldp
  - interfaces
  - bgp
  - ospf
  - configuration
```

---

# 8. SNMP Collection Platform

SNMP support is an initial built-in collector pack implemented on the generalized
collector runtime. It must not introduce SNMP-specific assumptions into the
entity, observation, scheduling, or artifact models.

Recommended design:

```text
Device
  ↓
SNMP
  ↓
SNMP Exporter / custom collector
  ↓
Prometheus-compatible ingestion
  ↓
Time-Series Database
```

Recommended components:

```text
Prometheus SNMP Exporter
Prometheus
VictoriaMetrics / Mimir / Thanos for larger deployments
```

---

# 9. AI-Generated SNMP Templates

Users should not need to manually write SNMP monitoring profiles.

Target workflow:

```text
User uploads MIB
        ↓
AI parses MIB
        ↓
AI identifies useful OIDs
        ↓
AI classifies:
- counter
- gauge
- status
- table
        ↓
AI generates SNMP profile
        ↓
Static validation
        ↓
Test walk against device
        ↓
Cardinality validation
        ↓
Preview
        ↓
Deploy
```

"No human interference" should mean:

> No manual template authoring is necessary.

However automated validation must always be retained.

---

# 10. Time-Series Metrics

Recommended architecture:

```text
Collectors
    ↓
Prometheus protocol
    ↓
Prometheus / vmagent
    ↓
Remote Write
    ↓
VictoriaMetrics / Mimir / Thanos
```

PromQL should become an AI-callable query capability.

Example:

```text
User:
"Show interfaces over 80% utilization during the last 30 minutes."

AI:
1. determines appropriate metric
2. builds PromQL
3. executes query
4. interprets result
5. renders chart
```

---

# 11. Event and Log Platform

Metrics are insufficient for root-cause analysis.

The platform should collect:

```text
SNMP traps
Syslog
Windows Event Logs
Kubernetes Events
VMware events
Application logs
Cloud events
Configuration-change events
Security events
```

Potential components:

```text
OpenTelemetry Collector
Loki
OpenSearch
ClickHouse
Kafka / Redpanda if event volume requires it
```

---

# 12. Tool / Capability Platform

This is a core differentiator of iCheck.

The AI should not directly control infrastructure.

It should call structured tools.

Example:

```python
get_bgp_neighbors(device_id)

get_interface_status(
    device_id,
    interface
)

query_windows_cim(
    server,
    namespace,
    class_name
)

ping(
    source,
    destination
)

configure_vlan(
    device,
    vlan_id,
    name
)
```

---

# 13. Tool Definition

Every tool should include metadata.

Example:

```yaml
name: get_bgp_neighbors

category: diagnose

risk: low

permission: read_only

input_schema:
  device_id: string

output_schema:
  neighbors: array

timeout: 10

credential_profile:
  network_readonly

audit: true
```

Write tool:

```yaml
name: configure_vlan

category: change

risk: medium

permission: write

peer_review_required: true

rollback_supported: true

audit: true
```

---

# 14. User-Customizable AI Tools

The system should allow users to create new tools using AI.

Supported tool types:

```text
HTTP / REST
Python
SQL
Shell
SNMP
SSH
WMI / CIM
PowerShell
NETCONF
gNMI
Kubernetes API
MCP
```

Example request:

```text
"Create a tool that queries our IPAM API
and returns the owner, VLAN and site for an IP."
```

AI generates:

```text
lookup_ip_owner(ip)
```

The generated tool must pass:

```text
schema validation
security validation
permission validation
sandbox testing
test execution
approval before publishing
```

---

# 15. Execution Framework Strategy

iCheck should support several execution engines.

They serve different purposes.

## 15.1 Ansible

**Primary management and change automation framework.**

Best use cases:

```text
Multi-vendor configuration
Server management
Windows management
Linux management
VMware
Kubernetes
Cloud
Storage
Deployment workflows
Idempotent configuration
Rollback workflows
```

Ansible should be the default engine for controlled infrastructure changes.

---

## 15.2 Nornir

Nornir should remain available for Python-native network workflows.

Good use cases:

```text
Fast ad-hoc diagnostics
Parallel network queries
Custom Python workflows
Agent-created diagnostic tools
Complex result processing
```

Nornir is not required for every operation but should be supported as a first-class execution backend.

---

## 15.3 Netmiko

Netmiko should provide direct CLI access where structured APIs are unavailable.

Examples:

```text
show ip bgp summary
show interface counters
show mac address-table
show ip route
show environment
```

Use Netmiko primarily as a driver behind tools.

The AI should normally not directly construct arbitrary CLI commands.

---

## 15.4 Paramiko

Paramiko should normally remain below the platform abstraction.

Direct Paramiko use should be minimized.

Preferred hierarchy:

```text
Structured API
   ↓
gNMI / REST / NETCONF
   ↓
Ansible / Nornir
   ↓
Netmiko
   ↓
SSH
```

---

# 16. Execution Router

A central capability engine should decide how to execute a tool.

Example:

```text
get_bgp_neighbors(LEAF01)
        ↓
Capability Engine
        ↓
Device supports eAPI?
   YES → eAPI
   NO
        ↓
NETCONF?
   YES → NETCONF
   NO
        ↓
Nornir + Netmiko
```

For a configuration change:

```text
configure_vlan()
        ↓
Capability Engine
        ↓
Ansible resource module
        ↓
vendor collection
```

---

# 17. Windows / WMI / CIM Support

Windows is a first-class platform.

Preferred mechanisms:

```text
PSRP
WinRM
PowerShell
CIM
WMI
Windows Event Log
windows_exporter
```

Modern queries should prefer CIM.

Examples:

```powershell
Get-CimInstance Win32_Processor

Get-CimInstance Win32_LogicalDisk

Get-CimInstance Win32_OperatingSystem
```

Hyper-V example:

```powershell
Get-CimInstance `
  -Namespace root\virtualization\v2 `
  -ClassName Msvm_ComputerSystem
```

AI tool:

```text
get_hyperv_vm_cpu(vm_name)
```

Possible implementation:

```text
AI
 ↓
Tool Registry
 ↓
Ansible
 ↓
win_powershell
 ↓
PowerShell
 ↓
CIM
 ↓
Hyper-V
```

---

# 18. Capability Model

Every resource should expose four groups of capabilities.

```text
RESOURCE
  │
  ├─ Observe
  ├─ Diagnose
  ├─ Manage
  └─ Change
```

Example: Network Switch

```text
Observe
- CPU
- memory
- interfaces
- environmental state
- BGP

Diagnose
- ping
- traceroute
- route lookup
- BGP lookup
- MAC lookup
- ARP lookup

Manage
- backup config
- save config
- reboot
- software upgrade

Change
- VLAN
- interface
- ACL
- BGP
- routing policy
```

Example: Windows Server

```text
Observe
- CPU
- memory
- disk
- services

Diagnose
- CIM/WMI query
- Event Log
- process inspection
- connectivity test

Manage
- start service
- stop service
- restart service
- reboot
- Windows Update

Change
- registry
- firewall
- software installation
- system configuration
```

---

# 19. Tool Risk Classification

Tools must be classified according to operational risk.

## Level 0 — Observe

Examples:

```text
get_cpu()
get_interface()
get_route()
get_metric()
```

Approval:

```text
No peer review required
```

---

## Level 1 — Diagnose

Examples:

```text
ping()
traceroute()
WMI query
show commands
log query
```

Approval:

```text
No peer review required
```

---

## Level 2 — Operational Management

Examples:

```text
restart_service()
clear_bgp_session()
reboot_server()
```

Approval:

```text
Change Request
Peer Review
```

---

## Level 3 — Configuration Change

Examples:

```text
configure_vlan()
modify_acl()
change_bgp_policy()
modify_firewall_policy()
```

Approval:

```text
Change Request
Peer Review
```

---

## Level 4 — High-Risk Change

Examples:

```text
upgrade_core_switch()
delete_vm()
change_core_firewall_policy()
database schema modification
```

Approval:

```text
Change Request
Peer Review
Privileged Reviewer
Maintenance Window
Additional policy checks
```

---

# 20. Change Governance

Any state-changing action must create a Change Request.

The AI must never directly perform a production state change.

Workflow:

```text
AI Recommendation
      ↓
Proposed Change
      ↓
Pre-check
      ↓
Impact Analysis
      ↓
Risk Analysis
      ↓
Generate Diff
      ↓
Rollback Plan
      ↓
Peer Review
      ↓
Approval
      ↓
Maintenance Window
      ↓
Execution
      ↓
Post-check
      ↓
Success?
   /       \
 Yes       No
  │         │
Close     Rollback
```

---

# 21. Peer Review / Four-Eyes Principle

The system must enforce:

```text
Requester != Reviewer
```

Example:

```text
Alice creates change
Bob reviews change
Bob approves
```

Alice cannot approve her own change.

The rule must be backend enforced.

---

# 22. Change Object

Example:

```json
{
  "change_id": "CHG-20260914-001",
  "requested_by": "AI-Agent",
  "requested_for": "Incident-4832",

  "targets": [
    "CORE-HK-01",
    "CORE-HK-02"
  ],

  "change_type": "network.bgp.policy",

  "reason": "Move traffic away from degraded ISP-A",

  "risk": "medium",

  "current_state": {
    "local_preference": 100
  },

  "desired_state": {
    "local_preference": 200
  },

  "affected_services": [
    "internet",
    "payment-service"
  ],

  "peer_review_required": true,

  "rollback_supported": true
}
```

---

# 23. Change Review GUI

The reviewer should see business and operational meaning, not only YAML.

Example:

```text
CHANGE CHG-20260914-001

AI Proposed

Increase BGP Local Preference
ISP-B: 100 → 200

Targets
CORE-HK-01
CORE-HK-02

Reason
ISP-A packet loss = 14.7%

Expected Result
Approx. 65% outbound traffic moves to ISP-B

Risk
MEDIUM

CONFIG DIFF
- local-preference 100
+ local-preference 200

PRE-CHECK
✓ ISP-B healthy
✓ capacity sufficient
✓ BGP established
✓ rollback available

[Reject] [Request Modification] [Approve]
```

---

# 24. Incident Model

iCheck should separate:

```text
Event
Alert
Incident
```

## Event

Something happened.

```text
Ethernet1 changed state to DOWN
```

## Alert

A monitoring condition was violated.

```text
BGP neighbor unavailable
```

## Incident

Multiple events and alerts describe one operational failure.

Example:

```text
Ethernet1 down
BGP down
packet loss high
application unreachable

        ↓

AI Correlation

        ↓

Incident:
HK WAN connectivity degradation caused by
PE01 Ethernet1 physical failure
```

---

# 25. Alert / Incident Center

The primary operational screen should show incidents instead of thousands of individual alerts.

Example:

```text
CRITICAL INCIDENT #4832

HK Edge Connectivity Degradation

Started:
14:31:06

Affected services:
23

Likely root cause:
PE01 Ethernet1 physical-layer failure

Confidence:
96%

Correlated:
1 physical alarm
1 BGP alarm
3 route changes
11 service alarms
17 application symptoms
```

---

# 26. External Integration

The platform should expose APIs and webhooks for:

```text
ServiceNow
Jira
PagerDuty
Teams
Slack
Email
OA platforms
ITSM systems
CMDB systems
IPAM systems
custom ticket systems
```

Integration should be bidirectional.

Example:

```text
iCheck detects incident
      ↓
creates ServiceNow ticket
      ↓
adds AI RCA
      ↓
updates investigation progress
      ↓
records remediation
      ↓
verifies recovery
      ↓
closes ticket
```

---

# 27. Topology

Topology is one of the GUIs that should definitely remain.

However, it should represent infrastructure relationships rather than only physical links.

Example:

```text
Application
     ↓
Kubernetes Service
     ↓
Pod
     ↓
Node
     ↓
VM
     ↓
Hypervisor
     ↓
NIC
     ↓
Switch Interface
     ↓
Leaf
     ↓
Firewall
     ↓
WAN
```

The AI should dynamically filter topology according to the investigation.

Example question:

```text
"Why can't 10.20.17.21 reach 10.50.8.33?"
```

UI:

```text
10.20.17.21
     ↓
Leaf12
     ↓
Spine02
     ↓
FW03  ← DENY
     ↓
Leaf21
     ↓
10.50.8.33
```

---

# 28. AI Investigation Workspace

This should be the primary UI.

Example:

```text
Investigating:
HK office packet loss

✓ Checked WAN health
✓ Checked firewall status
✓ Checked router interfaces
✓ Checked historical baseline
● Checking BGP changes
○ Checking recent configuration changes
○ Testing hypothesis
```

The system should expose what the AI is doing instead of displaying a generic "Thinking..." indicator.

---

# 29. Evidence Model

Every AI conclusion must expose supporting evidence.

Example:

```text
Conclusion:

BGP instability caused by physical interface degradation.

Confidence:
93%

Evidence:

Ethernet4 CRC:
14:00      3
14:20      3
14:31  14839

Optical RX:
-18.2 dBm

Normal range:
-4.3 to -5.1 dBm

BGP:
Established → Idle at 14:31:05
```

The AI provides abstraction.

The GUI provides proof.

---

# 30. Configuration & Change Intelligence

The platform should collect and correlate:

```text
running configuration
configuration versions
configuration diffs
who changed it
when it changed
source of change
Git history
automation deployment
firmware upgrade
policy change
```

AI should be able to answer:

```text
"Did anything change before the outage?"
```

Example:

```text
14:59:47 ACL WAN_OUT modified
15:00:12 BGP began resetting
15:01:04 Application latency alarm

Correlation confidence: 97%
```

---

# 31. Dynamic UI Philosophy

Avoid large amounts of static dashboards.

The default home screen is the AI L1 operator workspace, not an inventory or
metric dashboard. It should show only information that requires attention:

```text
AI shift summary
Prioritized situations and their business impact
Investigations currently being performed by AI
Pending human approvals
Collection gaps and uncertainty that block reasoning
```

Raw endpoint tables, device inventories, full alert lists, and protocol-specific
details belong in contextual drill-down pages. The AI may bring them into an
investigation when they are evidence, but they should not dominate the home
screen.

Users should be able to request:

```text
"Show WAN utilization for all Hong Kong sites
during the last seven days."
```

AI generates the visualization dynamically.

Users can then say:

```text
"Split by ISP."

"Compare with last week."

"Highlight anomalies."

"Save this view."
```

Only saved views become persistent dashboards.

---

# 32. Main Navigation

Recommended navigation:

```text
iCheck

AI Operations
Situations
Incidents
Changes
Generated Views
Assets
Capability Studio
  - Collectors
  - Topology
  - Tools
  - Skills
  - Workflows
Settings
  - AI Providers and Models
  - Tools and MCP
  - Collectors
  - Credentials
  - Policy and Audit
```

Avoid traditional navigation such as:

```text
Network
Server
Storage
Database
Virtualization
Application
Metrics
Logs
Reports
```

The AI should find the data.

Implementation status on 2026-09-18: `Assets → Devices` is implemented as a
dedicated drill-down and onboarding route at `/assets/devices`. It supports
device identity, site and labels, protocol-neutral connection intents, and
scoped external credential references. It is intentionally separate from the
AI Operations home. Connection creation produces `pending` verification state.
Authenticated site workers now claim leased preflight jobs and return bounded
evidence for ICMP, TCP transport, or SNMP Exporter protocol queries; the Assets
page exposes the latest result and audited retry. Verified connections can now
be rendered through versioned, published activation policies into deterministic
collector-deployment plans. The Assets page exposes the plan and warnings; an
operator must approve its hash and reason before atomic activation, and can
later deactivate it without deleting history. This state is
`monitoring_configured`, not `active`. Runtime reconciliation now promotes only
fresh successful scheduled collection to `active`, degrades failed or stale
collection, fingerprints approved deployment content, detects drift, and
requires a new exact-plan approval to repair it. Live lab and scale acceptance
remain open, so neither transport verification nor saved configuration alone is
presented as proof of continuous monitoring.

---

# 33. Credential and Security Model

Credentials must never be directly exposed to the LLM.

Architecture:

```text
AI
 ↓
Tool Call
 ↓
Policy Engine
 ↓
Credential Broker
 ↓
Execution Engine
```

Credential types:

```text
SNMP community / SNMPv3
SSH credentials
API tokens
Windows credentials
Cloud credentials
Kubernetes credentials
Database credentials
```

Requirements:

```text
encrypted at rest
RBAC
secret rotation
audit
least privilege
credential scopes
```

## 33.1 AI Provider and Model Configuration

The platform must be provider-neutral and allow administrators to configure AI
without changing application code.

Configuration objects:

```text
AIProvider
  type
  base_url
  authentication_type
  secret_reference
  network and data-residency policy

AIModel
  provider
  model_name
  capabilities
  context limit
  cost and latency class

ModelRoutingPolicy
  task class
  primary model
  fallback models
  privacy boundary

AgentProfile
  role and instructions
  model policy
  tool policy
  maximum iterations
  wall-clock and cost budget
  approval and escalation policy
```

Tokens and infrastructure credentials must never be stored as plaintext model
configuration or returned to the browser. The database stores an opaque secret
reference; a credential broker resolves it only at execution time. The settings
page must support a redacted connection test and must prevent secrets from
entering prompts, traces, tool outputs, or logs.

Implementation status on 2026-09-19: `AIProvider`, `AIModel`, and bounded
`ModelRoutingPolicy` foundations are implemented with outbound host allowlists,
environment secret references, redacted model-list tests, audit, API, and a
dedicated settings page. The first OpenAI-compatible inference adapter and
bounded LangGraph investigation kernel are also implemented: structured model
decisions, typed read-only tools, immutable product checkpoints, evidence and
tool-call persistence, budget/duplicate guards, and deterministic escalation.
`AgentProfile`, external Vault/KMS providers, data-residency and permission
policy, live-provider fallback acceptance, live PostgreSQL resume acceptance,
and governed action approval remain future work. Ordered, snapshotted, audited
model fallback, durable asynchronous execution, and the initial AI operator
workspace are implemented. This is a working kernel and first product surface,
not a completed AI operator product.

---

# 34. Audit

Every AI tool invocation should generate an audit record.

Example:

```text
timestamp
user
agent
tool
target
parameters
execution engine
result
duration
risk level
change_id
reviewer
approval status
```

This is mandatory for commercial production environments.

---

# 35. Suggested Technology Stack

## Backend

```text
Python
FastAPI
Pydantic
SQLAlchemy
Celery / Temporal / task engine
```

## AI / Agent

```text
LangGraph as the initial stateful orchestration runtime
provider-neutral model adapters
MCP client and gateways at extension boundaries
typed Python tools and internal capability APIs
```

## CMDB / Knowledge

```text
PostgreSQL
```

Possible future addition:

```text
Graph database if relationship traversal becomes difficult
```

Do not add a graph database prematurely.

---

## Metrics

```text
Prometheus
SNMP Exporter
VictoriaMetrics / Mimir / Thanos
```

## Logs / Events

```text
OpenTelemetry Collector
Loki / OpenSearch / ClickHouse
```

## Management

```text
Ansible
Ansible Runner
Nornir
Netmiko
NETCONF
gNMI
REST APIs
PowerShell
PSRP / WinRM
WMI / CIM
```

## Cache / Queue

```text
Redis
Kafka / Redpanda if required by scale
```

## Frontend

```text
React
TypeScript
WebSocket / SSE
Topology visualization library
```

## Production Deployment

```text
Development/demo:
  Docker Compose may package PostgreSQL, API, and frontend.

Production baseline:
  HA control-plane services on VMs or bare metal
  systemd-managed regional/site collectors and execution workers
  PostgreSQL HA for knowledge, configuration, audit, and workflow state
  Prometheus-compatible regional collection with federation or remote write
  external secret management
  queue-backed scheduling, leases, rate limits, and backpressure

Optional:
  Containers or Kubernetes where the operator already standardizes on them
```

Containers are a deployment choice, not a scalability strategy or a requirement.
Collector and execution processes must remain independently deployable and
horizontally scalable.

---

# 36. Recommended Execution Strategy

Use a preference model.

## Read / Diagnostic Operations

```text
Native structured API
      ↓
gNMI / REST / NETCONF
      ↓
Nornir
      ↓
Netmiko
      ↓
raw SSH CLI
```

## State-Changing Operations

```text
AI
 ↓
Change Request
 ↓
Peer Review
 ↓
Approval
 ↓
Ansible
 ↓
Structured vendor module / API
 ↓
Infrastructure
```

Exceptions are allowed when a vendor has a better native API.

---

# 37. AI Capability Studio and Artifact Architecture

The Capability Studio is a primary product surface, not an administrator-only
code generator. It allows a user to create and iterate operational capabilities
through the same AI conversation used for investigation.

```text
User Requirement
      ↓
AI determines artifact type and asks only for missing operational facts
      ↓
Generate:
- typed contract and metadata
- implementation or declarative definition
- entity / relationship / observation mappings
- permissions and risk classification
- dependencies and secret references
- tests, fixtures, health checks, and documentation
      ↓
Deterministic Validation
      ↓
Isolated Sandbox Test
      ↓
Interactive Preview
      ↓
Policy / Security / Human Approval
      ↓
Publish Immutable Version to Artifact Registry
      ↓
Canary or Scoped Deployment
      ↓
Runtime Health, Audit, Rollback, and Conversational Iteration
```

The same lifecycle applies to collectors, parsers, topology definitions, tools,
skills, workflows, visualizations, and reports. Published artifacts become
discoverable capabilities available to authorized agents.

The UI must expose:

- A conversational authoring workspace with the proposed specification beside it.
- Test fixtures, sandbox results, generated evidence, and errors.
- Semantic diffs between artifact versions.
- Dependency and permission impact.
- Draft, test, review, published, deprecated, and rolled-back states.
- A one-click path from a failed runtime execution back into an AI-assisted edit.

Generated artifacts must be portable and exportable. iCheck must not lock the
user's operational knowledge inside an opaque conversation history.

---

# 38. Agent Runtime and Orchestration

LangGraph is the recommended stateful orchestration runtime for the first
implementation. Model providers, tool implementations, and artifact formats must
remain replaceable behind iCheck-owned interfaces.

## 38.1 Hybrid Workflow Model

Known runbooks should use deterministic graphs. Open-ended troubleshooting
should use a bounded agent loop. A single investigation may combine both:

```text
Purpose / Alert
      ↓
Scope and impact
      ↓
Load entity, topology, history, and current evidence
      ↓
Plan next diagnostic step
      ↓
Policy and tool eligibility check
      ↓
Execute tool(s)
      ↓
Normalize and persist evidence
      ↓
Evaluate hypotheses
      ├── evidence sufficient ──────────────→ explain / recommend
      ├── more evidence needed + budget ───→ plan next step
      ├── risky action required ────────────→ human interrupt
      └── budget exhausted / low confidence → escalate to L2
                                              ↓
                                  approved action / validation / rollback
```

The persisted investigation state should include:

```text
purpose and initiating event
entity and service scope
observations and evidence references
hypotheses and confidence
tool calls and normalized results
iteration, time, token, and tool-cost budgets
pending approval
conclusion, recommendation, and escalation reason
```

Every loop is bounded by maximum iterations, wall time, tool cost, duplicate-call
detection, target rate limits, tool allowlists, and evidence-based stop rules.
Checkpointing must allow investigations to survive process restarts. Human
approval must pause and resume the same durable investigation.

## 38.2 Tool and MCP Strategy

Not every tool should be a separate MCP server.

```text
Core low-latency capability       → typed in-process tool or internal API
Distributed collection/execution → HTTP or gRPC worker contract
High-frequency telemetry         → exporter / collector / remote-write protocol
External or user plug-in boundary→ MCP server or gateway
```

MCP is an interoperability boundary for focused capability packs, third-party
integrations, and user extensions. Tools should be grouped by security and
operational domain rather than creating one server per function. The iCheck host
retains model context, policy, consent, credentials, audit, and cross-tool
orchestration.

## 38.3 Initial Agents

```text
Supervisor Agent
Network Agent
Systems Agent
Application / Kubernetes Agent
```

Start with these roles and split into Windows, Linux, virtualization, storage,
database, or vendor specialists only when evidence shows that separate context,
permissions, or tools are necessary. Specialized agents are subgraphs or tools
under the supervisor, not independent opaque control planes.

## 38.4 Current Kernel Contract

Implementation status on 2026-09-19:

- LangGraph owns the executable reason → tools → reason state machine and may
  use its PostgreSQL saver for thread-level restart recovery.
- iCheck separately persists immutable, hash-addressed product checkpoints,
  evidence references, tool calls, conclusions, confidence, uncertainty, and
  escalation. LangGraph storage is not exposed as the product audit model.
- The OpenAI-compatible reasoner reads only the configured provider, model, and
  server-side credential reference. Provider tokens, infrastructure credential
  references, and device connection configuration are excluded from prompts.
- Each investigation snapshots its authenticated principal, permissions, and
  authorization scope. The model receives only currently executable internal
  tools allowed by that immutable snapshot. Persistence and execution enforce
  the permission again; tool results remain untrusted evidence.
- Core low-latency tools remain typed internal handlers. MCP execution is
  intentionally fail-closed until the gateway, identity, permission, and
  capability-pack policies exist.
- A state-changing tool creates an exact-plan proposal and durably interrupts
  the same LangGraph thread before execution. A different principal with
  `changes.approve` must decide the matching plan hash. The existing execution
  is requeued and resumes the same checkpoint; an ambiguous `executing` action
  after worker loss is never automatically replayed.

The direct graph service entry point runs only a fresh investigation and rejects
partially consumed state. The leased agent worker chooses fresh execution or
resumes the existing LangGraph thread, renews ownership per node, observes
cancellation, emits ordered/SSE progress, and reconciles a terminal graph commit
after worker loss. The AI L1 home creates these durable investigations and shows
their trace, evidence, conclusion, confidence, uncertainty, and real collection
gaps without moving terminal inventory onto home. Controlled tests cover graph
reconstruction and resume with an in-memory saver; frontend lint and production
build cover the workspace. Live PostgreSQL process-kill acceptance, browser
OIDC/session integration, and per-target scope enforcement remain next. The detailed contracts and
verified boundaries are maintained in `docs/agent-runtime.md` and
`docs/operator-workspace.md`.

---

# 39. Typical Investigation Example

User:

```text
"Why is payment-api latency high?"
```

Workflow:

```text
Supervisor Agent
        ↓
Application telemetry
        ↓
Kubernetes health
        ↓
Node health
        ↓
VM / Hypervisor
        ↓
Network path
        ↓
Interface telemetry
        ↓
Recent config changes
        ↓
Historical comparison
        ↓
Root Cause Analysis
```

Output:

```text
Root Cause

Leaf03 Ethernet12 physical-layer degradation.

Evidence

CRC errors increased from 0 to 18,423.
Optical RX dropped to -18.2 dBm.
Packet loss began at 14:32:08.
Payment API P99 increased 34 seconds later.

Affected Resources

K8s-node17
K8s-node18
payment-api

Recommended Action

Move traffic to redundant link.

Confidence

94%
```

---

# 40. Development Phases

The detailed, status-bearing plan is maintained in
`docs/development-plan.md`. The sequence below captures product dependencies.
The Capability Studio is deliberately early: self-extension cannot be postponed
until after a conventional monitoring platform has already been built.

## Phase 0 — Runnable Vertical Slice

Current foundation:

```text
PostgreSQL-ready entity model
IP / MAC / wired attachment / Wi-Fi terminal history
alert rules, deduplication, acknowledgement, and resolution
collector-facing ingestion contracts
initial operations UI
versioned collector artifacts, deployments, workers, leases, and run history
bootstrap-authenticated worker enrollment and rotating worker credentials
credential-reference profiles and a fail-closed broker boundary
bounded JSON Schema validation and collector lifecycle audit events
Prometheus-compatible backend registry and bounded PromQL query boundary
versioned SNMP Exporter collector pack and non-container deployment templates
web device onboarding with protocol-neutral, credential-referenced connection intents
leased worker preflight, bounded evidence, retry, and readiness aggregation
versioned activation policies, immutable plan preview, approval, and deactivation
run-health promotion, failure/staleness degradation, and deployment-drift repair
provider/model routing and secret-reference configuration
persistent investigation, evidence, Tool Registry, and tool-call contracts
bounded LangGraph reason/tool/evidence kernel with structured model inference
```

This phase proves durable identity and alert state but is not yet the AI-native
product runtime.

---

## Phase 1 — Distributed Collection and Data Foundation

Build:

```text
generic CollectorDefinition and artifact schema
collector scheduler, leases, heartbeats, rate limits, and health
systemd/VM production packages; Compose remains development-only
Prometheus-compatible metrics plane and SNMP exporter pack
Windows metrics plus on-demand PSRP/CIM adapter
controller/API collector SDK
entity, relationship, observation, and event normalization
artifact registry foundations
```

Target:

> Multiple collector workers can safely collect hundreds to thousands of
> heterogeneous targets without protocol-specific logic entering the core model.

---

## Phase 2 — AI Operator Kernel

Build:

```text
AI provider, URL, model, secret-reference, and routing configuration
LangGraph durable investigation state
typed Tool Registry and execution policy
bounded planner/tool/evidence loop
read-only network, Windows, PromQL, log, and topology tools
checkpointing, streaming, budget limits, and L2 escalation
AI L1 home screen and situation workspace
```

Target:

> AI can autonomously perform a bounded, read-only investigation and expose every
> conclusion, tool call, evidence item, uncertainty, and escalation reason.

---

## Phase 3 — In-Product Capability Studio

Build:

```text
conversational Collector Designer
Tool and Skill Designer
workflow template editor for deterministic and agentic graphs
AI-generated topology and visualization definitions
schema/security validation
sandbox, fixtures, replay, and preview
versioned publish, canary rollout, health, export, and rollback
MCP gateway for external and user capability packs
```

Target:

> A user creates a new API collector, topology view, diagnostic skill, or workflow
> inside iCheck without an IDE or a product release.

---

## Phase 4 — Situation and Incident Intelligence

Build:

```text
event correlation and Situation model
service impact and topology reasoning
incident lifecycle and root-cause analysis
historical and change timelines
dynamic views generated from investigation context
external ticket and collaboration integrations
```

Target:

> The primary UI is an AI-operated situation queue, while inventory and raw
> telemetry remain contextual evidence in dedicated subpages.

---

## Phase 5 — Governed Action

Build:

```text
Ansible Runner and replaceable execution backends
change objects, pre-checks, post-checks, and rollback
RBAC and scoped credential broker
peer review and four-eyes approval
maintenance windows and risk policies
complete AI/tool/artifact audit trail
```

Target:

> AI can propose changes and execute approved actions without receiving
> infrastructure credentials or bypassing policy.

---

## Phase 6 — Scale and Ecosystem

Build:

```text
collector and agent-worker horizontal scaling
multi-tenant isolation and regional control
artifact dependency and compatibility management
signed capability packs and organization catalogs
additional network, cloud, virtualization, storage, and application packs
capacity, reliability, security, and upgrade testing
```

---

## Phase 7 — Governed Autonomous Operations

Only after evidence quality, rollback, and governance are mature:

```text
automatic remediation for pre-approved low-risk operations
automatic incident verification
automatic rollback
closed-loop operations
```

Example:

```text
Alert
 ↓
AI diagnoses
 ↓
known low-risk remediation
 ↓
policy permits automation
 ↓
execute
 ↓
verify
 ↓
close incident
```

High-risk changes should continue to require human approval.

---

# 41. MVP Recommendation

Do not try to build every category initially.

The first AI-native MVP must prove three product loops:

```text
Observe:
  a generated or built-in collector produces normalized evidence

Investigate:
  a durable, bounded agent loop uses tools and explains its conclusion

Extend:
  a user creates, tests, publishes, and revises one capability inside iCheck
```

Keep the infrastructure scope focused on:

```text
Network
Linux
Windows
```

Technology:

```text
FastAPI
PostgreSQL
Prometheus
SNMP Exporter
generic HTTP collector
Netmiko
Nornir
PowerShell/CIM
LangGraph
Artifact Registry and sandbox
React
```

Initial AI capabilities:

```text
find_device()

get_interface_status()

get_interface_metrics()

get_bgp_neighbors()

get_route()

get_mac_entry()

get_arp_entry()

ping()

traceroute()

get_windows_cpu()

get_windows_disk()

query_windows_event()

query_metrics()

query_logs()
```

Initially keep all tools read-only.

---

# 42. Architectural Rules

## Rule 1

AI must never receive infrastructure passwords.

## Rule 2

AI should call typed tools, not arbitrary SSH commands.

## Rule 3

Structured APIs are preferred over CLI.

## Rule 4

Every state-changing action creates a Change Request.

## Rule 5

Every Change Request requires peer review according to policy.

## Rule 6

Requester cannot approve their own change.

## Rule 7

All actions are audited.

## Rule 8

Every AI conclusion should expose evidence.

## Rule 9

CMDB represents infrastructure knowledge; TSDB stores time-series telemetry.

## Rule 10

Dynamic infrastructure state should retain history.

## Rule 11

Execution technology must remain replaceable behind the Tool Platform.

## Rule 12

Monitoring templates and tools may be AI-generated, but must be deterministically validated.

## Rule 13

The AI Agent Runtime is the product kernel; monitoring screens and chat are
projections of its state, not separate products connected by an AI add-on.

## Rule 14

Collectors are protocol-neutral, versioned artifacts. SNMP, APIs, WMI/CIM,
streaming, and future protocols use the same lifecycle and normalized contracts.

## Rule 15

Collectors, topology views, tools, skills, workflows, and visualizations must be
creatable and iterable through conversation inside iCheck.

## Rule 16

Generated capabilities never silently modify the production runtime. They pass
typed validation, sandbox tests, policy checks, versioned publishing, scoped
rollout, health observation, and rollback.

## Rule 17

AI providers, models, execution engines, collectors, and tool transports must be
replaceable behind iCheck-owned contracts. MCP is supported at integration
boundaries but is not mandatory for every internal tool.

## Rule 18

Docker Compose is for development and demonstration. Production components must
support independent VM/bare-metal deployment and horizontal scaling; containers
remain optional.

---

# 43. Product Definition

iCheck should ultimately be described as:

> **An AI-native, self-extensible IT operations agent platform that continuously
> discovers, observes, understands, diagnoses, and manages heterogeneous
> infrastructure, while allowing users to create and evolve its collectors,
> topology, skills, tools, and workflows through conversation.**

A shorter product description:

> **iCheck is an extensible AI infrastructure engineer with observability,
> capability creation, automation, and governance built in.**

---

# 44. Final Technology Position

### Monitoring

```text
Prometheus ecosystem
SNMP Exporter
OpenTelemetry
VictoriaMetrics
```

### Infrastructure knowledge

```text
PostgreSQL
```

### AI

```text
LangGraph orchestration
provider-neutral model adapters
typed tools and MCP gateways
```

### Network diagnostics

```text
Native API
gNMI
NETCONF
Nornir
Netmiko
```

### Infrastructure management

```text
Ansible
Ansible Runner
```

### Windows

```text
PowerShell
CIM/WMI
PSRP / WinRM
windows_exporter
```

### Governance

```text
Change Request
Peer Review
Four-Eyes Approval
RBAC
Audit
Rollback
```

### Core principle

```text
AI decides WHAT it needs.

The Capability Platform decides HOW to do it.

Humans decide WHETHER risky changes are allowed.
```

---

# 45. Long-Term Goal

The long-term vision is a closed-loop AI operations system:

```text
                 Infrastructure

                       ↓

            Continuous Observability

                       ↓

               Infrastructure Model

                       ↓

                 AI Reasoning

                       ↓

             Incident Understanding

                       ↓

             Recommended Remediation

                       ↓

                 Policy Engine

                       ↓

                  Peer Review
             (when risk requires)

                       ↓

                 Automation

                       ↓

                  Validation

                       ↓

                  Learning
```

Learning includes two distinct loops:

```text
Operational loop:
observe → investigate → act → verify

Capability loop:
identify missing capability → generate artifact → test → publish
→ observe runtime quality → revise or roll back through conversation
```

iCheck must learn by producing explicit, reviewable, versioned artifacts. It
must not rely on invisible prompt drift or uncontrolled self-modification.

The system should evolve from:

```text
Monitoring
```

to:

```text
Understanding
```

to:

```text
Assisted Operations
```

and finally:

```text
Governed Autonomous Operations
```

without sacrificing auditability, explainability, or human control.
