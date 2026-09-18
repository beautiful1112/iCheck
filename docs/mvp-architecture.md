# MVP architecture

## Product boundary

The current vertical slice proves endpoint identity, alert state, and normalized
ingestion. It must not grow into a conventional fixed monitoring product before
the agent kernel is introduced.

The target MVP is an AI L1 operator with an in-product capability studio:

```text
Conversation / operational purpose
        ↓
Durable Agent Runtime
        ├── investigates with typed tools
        └── designs a missing versioned capability
                    ↓
      validate → sandbox → preview → approve → publish
                    ↓
Collector / Topology / Tool / Skill / Workflow / View
```

The AI is the primary operator and capability authoring interface. Asset,
endpoint, alert, metric, and protocol pages are supporting evidence surfaces.

## Endpoint identity model

A MAC address identifies an endpoint record. Mutable facts are stored as
time-bounded observations rather than overwritten fields.

```text
Endpoint (normalized MAC)
  ├── IP address observations
  │     source, collector, VLAN, first_seen, last_seen, active
  ├── wired attachments
  │     switch, interface, VLAN, first_seen, last_seen, active
  └── wireless sessions
        controller, AP, SSID, IP, radio, signal, connected/disconnected
```

This supports current-state and historical questions:

- Which MAC currently owns an IP?
- Which IP addresses has this endpoint used?
- Which switch port or AP last observed it?
- When did a wireless client roam or disconnect?
- Did an IP change occur near an incident?

The `raw_data` JSON fields retain unmodeled vendor fields while stable fields remain
indexed and queryable. Vendor adapters should not place credentials in raw data.

## Alert lifecycle

```text
Observation or external event
        ↓
Enabled matching rule
        ↓
Deterministic condition check
        ↓
Deduplication key
        ↓
OPEN → ACKNOWLEDGED → RESOLVED
```

Repeated matching observations update `last_seen` and `occurrence_count` on the
same active alert. A later recovery observation may resolve it automatically.
Manual acknowledgement and resolution always record the actor and timestamp.

Initial built-in rule types:

- `wireless.rssi.low` — threshold defaults to `-75 dBm`.
- `endpoint.ip.changed` — emitted when an active address changes for the same
  endpoint, source, collector, and IP family.
- `endpoint.new` — available but disabled by default to avoid initial discovery
  noise.

## Service boundaries

```text
Distributed collectors / vendor adapters
        ↓
Normalized ingestion contracts
        ↓
Inventory + alert domain services
        ↓
PostgreSQL
        ↓
Typed capability APIs
        ↓
LangGraph Agent Runtime
        ↓
AI L1 workspace / Capability Studio / supporting subpages
```

SNMP, WLC, arbitrary APIs, Prometheus, and WMI/CIM collectors must translate
source data into the same ingestion contracts. They must not write directly to
database tables or cause source-specific fields to spread through the core
domain model.

The Agent Runtime uses typed capability APIs over these services. It does not
receive database, model-provider, or infrastructure credentials.

## Generic collector contract

A collector is a versioned artifact with connection metadata, schedule or event
mode, normalized outputs, rate limits, health checks, permissions, test
fixtures, and a credential reference.

Collection workers register with the control plane and use leases and
heartbeats. Target ownership can be reassigned without duplicate uncontrolled
polling. Workers apply retry budgets, jitter, timeouts, per-target concurrency,
and backpressure.

SNMP Exporter, controller APIs, HTTP APIs, windows_exporter, and on-demand
PSRP/CIM are initial collector or diagnostic packs, not hard-coded platform
boundaries.

## AI and workflow runtime

LangGraph is the initial orchestration choice. Known runbooks use deterministic
graphs; uncertain troubleshooting uses a bounded plan → tool → evidence →
evaluate loop. Both persist the same investigation state and can pause for
human approval.

Every run records its purpose, entity scope, evidence, hypotheses, tool results,
budget, approval state, conclusion, and escalation reason. Loops have explicit
iteration, duration, cost, duplicate-call, and target-rate limits.

MCP is used for focused external or user capability packs. Core typed tools may
run in process, while distributed collectors and action workers use internal
HTTP/gRPC contracts. MCP is not required for every function.

## Generated artifact lifecycle

```text
draft → validate → sandbox test → preview → review → publish
      → scoped deploy → observe → revise or roll back
```

Published artifact versions are immutable and exportable. Conversation history
alone is not an executable specification. Collectors, mappings, tools, skills,
workflows, topology definitions, and generated views must carry their schemas,
tests, dependencies, permissions, and version history.

## Deployment boundary

Docker Compose is only a local development convenience. The production baseline
uses independently deployable control-plane services, site or regional
collector workers, and execution workers on VMs or bare metal under systemd.
Containers remain optional.

PostgreSQL stores knowledge, configuration, alert/incident state, artifact
metadata, workflow checkpoints, and audit records. Metrics belong in a
Prometheus-compatible time-series plane; logs and large artifacts use their
appropriate stores.

## Next architectural slice

The accepted order is:

1. Artifact and generic collector contracts.
2. Distributed collector registration, authenticated worker identity, leases,
   schema validation, audit, health, and a reference API collector.
3. Prometheus, SNMP, windows_exporter, and governed PSRP/CIM boundaries are
   implemented; representative non-container deployment and credential-backed
   execution validation are next.
4. AI provider/model configuration, secret references, and Tool Registry
   contracts.
5. Durable LangGraph investigation state and a read-only agent loop.
6. AI L1 information architecture and conversational Capability Studio.

See [the development plan](./development-plan.md) for status and exit criteria.
