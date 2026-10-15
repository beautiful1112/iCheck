# Regional worker capacity recommendations

iCheck evaluates Collector and Agent worker capacity without requiring Docker
or Kubernetes. Policies and decisions are scoped to one tenant and region;
worker processes may run under systemd on VMs or bare metal.

## Deliberate control boundary

The iCheck scaling controller remains recommendation-only. It observes work and
worker leases, records an immutable desired replica count, and stops there. It
does not execute a shell, call systemd, provision a VM, or terminate a host.
An independently deployed, opt-in systemd capacity provider can now apply
those decisions on a single VM/bare-metal worker host. Cloud, hypervisor, and
host lifecycle remain outside the controller.

A capacity provider may consume the latest decision and reconcile a site's
chosen runtime:

```text
regional queue + heartbeats
          ↓
iCheck scaling controller
          ↓
immutable desired replica decision
          ↓
separately privileged capacity provider
          ↓
systemd / VM API / bare metal / optional orchestrator
```

This separation keeps process control, cloud, hypervisor, bare-metal, and
orchestration APIs out of the Agent and scaling-controller trust boundaries.

## Policies

A policy belongs to either `collector` or `agent` and defines:

- an optional Collector label/site selector;
- required adapter or model-provider capabilities;
- minimum and maximum replicas;
- target queued work per replica;
- bounded scale-out and scale-in steps;
- oldest-queue age target;
- heartbeat timeout; and
- cooldown.

Agent pools use capabilities rather than label selectors. A policy should
normally describe one homogeneous capacity pool. Required capabilities are an
all-of match for workers; queued jobs match the corresponding adapter or model
provider type.

Collector backlog uses basic due/lease/version eligibility checks: the
deployment is enabled and due, its lease is absent/expired, its Artifact is
published/deprecated or is the validated candidate of an active canary, and
its adapter and worker selector match the pool. It is a demand estimate, not
execution admission: current identity, credential, revocation and supervised-I/O
checks still belong to the Collector admission path. Agent backlog contains queued
or expired-running executions for still-running Investigations, excluding
cancel requests, and matches model-provider capability.

Fresh workers are those with a heartbeat inside the policy timeout and a
non-offline state. Stale workers are counted as evidence but excluded from
current/ready capacity. Active leases determine busy replicas.

## Recommendation algorithm

The deterministic evaluator:

1. computes `ceil(queue_depth / target_queue_per_replica)`;
2. never recommends below busy replicas or `min_replicas`;
3. adds bounded scale-out pressure when oldest work exceeds the age target;
4. clamps the result to min/max;
5. limits movement by the scale-out or scale-in step; and
6. holds the previous bounded recommendation during cooldown.

Every evaluation stores observed queue age, current/ready/busy/stale counts,
desired replicas, direction, policy revision, reason codes, actor, and
timestamp. Updating a policy uses an expected revision and requires an audit
reason.

## Controller and high availability

`icheck-scaling-worker` is a PostgreSQL-only regional process. Every polling
transaction binds its fixed tenant/region and tries a transaction-level
PostgreSQL advisory lock derived from that namespace. Multiple replicas are
safe: only the lock holder records decisions while holding that transaction's
namespace lock. It does not deduplicate successive polling cycles into one
wall-clock interval. Every cycle appends a recommendation, never a capacity action.
Policy evaluation and edits take the same fresh row mutex; multi-policy callers
lock in immutable ID order. READ COMMITTED with DBAPI autocommit disabled is
mandatory, and the leader namespace must match the bound Session.

Install the supplied unit and configure:

```text
/etc/icheck/scaling-worker.env
ICHECK_DATABASE_URL=postgresql+psycopg://icheck_scaling@127.0.0.1:5432/icheck?sslmode=require
ICHECK_TENANT_ID=<tenant UUID>
ICHECK_REGION_ID=<region UUID>
ICHECK_SCALING_WORKER_POLL_SECONDS=15
```

Reference files:

- `deploy/systemd/icheck-scaling-worker.service`
- `deploy/systemd/scaling-worker.env.example`

The reviewed `scaling-worker` database profile names 16 relations. Only
recommendations and audit are insertable; only `worker_scaling_policies.updated_at`
is writable, genuinely, to permit PostgreSQL row locking. Policies, bounds,
revision/enablement, worker/queue/provider configuration and existing decisions
cannot be changed. Capacity receipts, credentials, access/session tokens,
deletion and DDL are inaccessible. Whole ORM worker/provider metadata reads
include token hashes and external provider references, not usable raw tokens
or secrets; the controller never resolves credentials. These are trusted core
service credentials, not tenant or remote-Worker credentials. Namespace RLS
uses the configured session, not a per-login namespace restriction.

The post-r31 source check (private development evidence; not distributed)
passes 18 exact-role PostgreSQL cases across corrected segments, including
real subprocess SIGKILL before/after recommendation commit and a policy-edit
wait. Queues/heartbeats are synthetic; no installed scaling service, actual
fleet load or capacity application/convergence/scale-in is accepted. The source
is not yet packaged and native provisioning still requires approval.

Run one logical controller set per region. The controller itself can have
multiple replicas for availability because the advisory lock prevents duplicate
leaders.

## API, UI, and Agent access

The regional API is:

```text
GET  /api/v1/scaling/policies
POST /api/v1/scaling/policies
PUT  /api/v1/scaling/policies/{id}
POST /api/v1/scaling/policies/{id}/evaluate
POST /api/v1/scaling/evaluate
GET  /api/v1/scaling/decisions
POST /api/v1/scaling/decisions/{id}/application-events
GET  /api/v1/scaling/application-events
```

`scaling.read` can view policies and history. `scaling.manage` with global
scope inside the active namespace is required to create, revise, or manually
evaluate policies. `scaling.apply` with the same namespace-global requirement
is reserved for the external capacity-provider identity. The dedicated UI is
`/settings/scaling`, keeping capacity details off the AI L1 home.

The built-in read-only Tool `capacity.get_worker_scaling` exposes the latest
regional decisions as cited Investigation evidence. It lets the L1 Agent
explain backlog, stale workers, and recommended capacity, but cannot mutate
policy or infrastructure.

## Capacity-provider integration contract

An external reconciler can poll `GET /api/v1/scaling/decisions?limit=...` using
a namespace-bound, least-privilege identity. It should:

- select the newest decision per policy;
- treat `decision.id` as its idempotency key;
- reconcile to `desired_replicas`, never apply the value as a delta;
- re-read policy and decision state before destructive scale-in;
- start Workers with the policy's tenant/region and capabilities;
- wait for registered healthy heartbeats before considering scale-out ready;
- drain or honor active leases before stopping a Worker; and
- retain provider-side apply/error evidence without writing credentials or raw
  provider errors into iCheck.

The reconciler reports progress to the decision-specific application-event
endpoint. The server derives `provider_subject` from the authenticated
principal, requires a provider-scoped idempotency key, and accepts only:

```text
new → accepted → applying → applied
               ↘ failed
new → rejected
```

`accepted`, `applying`, and `applied` are rejected for any decision that is no
longer the latest for its policy. Terminal events cannot be reopened. Failure
reports require only a SHA-256 error fingerprint; raw provider errors are not
persisted. Exact idempotent replay returns the existing immutable event, while
key reuse with different content fails closed. The settings page joins the
latest receipt to each recommendation.

This receipt contract proves what the provider reported, not that iCheck
independently verified a VM or process change.

## Allowlisted systemd provider

`icheck-systemd-capacity-provider` is the concrete VM/bare-metal adapter. It is
not part of the AI Agent process and is not started by default. It runs once
per tenant/region worker host, retains a dedicated PostgreSQL leader transaction
to prevent two provider processes from reconciling the same namespace across
business commits, and accepts only a
root-owned, non-writable JSON mapping.

The native provider runs as the isolated `icheck-capacity` account, never root.
The config and its complete ancestry must be root-owned, non-linked and not
group/world writable. Its current default location is
`/etc/icheck-workers/capacity/systemd-capacity.json`, readable only to the
provider's group. Its source-reviewed `systemd-capacity-provider` PostgreSQL
profile names 12 relations and five UPDATE columns: policy `updated_at` for its
mutex, and each Worker registry's `state`/`updated_at`. It appends immutable
capacity receipts and audit, but cannot recommend, configure policy, register/
retoken Workers, edit capabilities, claim or renew leases, rewrite history,
read credential/provider/MCP/identity tables or perform DDL/DELETE/TEMP.
Worker ORM reads include token hashes, not usable bearer/registration tokens;
deployment/lease metadata is private core-service data, not tenant access.
All business relations retain namespace RLS. This is a fixed-namespace trusted
core role, not a login-level namespace or mapped-instance SQL restriction.
Neither the native DB profile nor provider service has been provisioned yet.

READ COMMITTED with DBAPI autocommit disabled is required before leadership or
decision processing. The namespace must match the bound Session. The dedicated
leader transaction holds an xact advisory lock on one retained connection;
business commits cannot release it or leave a session lock in a shared pool.
Normal/error exit rolls it back. Each operation checks that connection before
continuing; loss stops further actions and leaves committed progress recoverable.

Before each bounded start/stop, after every commit and before a convergence
receipt, the provider takes the same fresh policy mutex used by editors and
scaling evaluators. It requires enabled current revision, latest decision,
current replica bounds, a non-future observation and the exact mapping binding.
The process reloads the protected mapping before each phase; missing/unreadable/
changed configuration fails closed. An existing `applying` receipt is not
authorization to continue obsolete inputs. The deadline is checked throughout,
and expired applications cannot actuate or report late convergence. Root-owned
file changes are re-read, not transactionally locked against an arbitrary root
writer; coordinated mapping/Polkit updates remain an operator requirement.

The mapping binds an exact `(pool, policy_name)` to an ordered list of instance
IDs. IDs are converted only into these unit templates:

```text
icheck-collector-capacity@<instance>.service
icheck-agent-capacity@<instance>.service
```

Path characters, shell fragments, arbitrary unit names, duplicate instance
ownership, and desired counts beyond the configured list are rejected. The
adapter invokes `/usr/bin/systemctl` with an argument vector and never invokes
a shell or sudo, and disables interactive password requests. A decision is reconciled to an absolute target set (the first N
allowlisted instances), never treated as a delta.

Scale-out is complete only after the unit is active and the deterministic
worker identity (`capacity-<pool>-<instance>`) has a fresh, online heartbeat
with the policy's required capabilities and Collector selector. Scale-in sets
the Worker to `draining` first. Heartbeats and re-registration cannot clear that state,
both worker types stop claiming new leases and exit successfully after current
work, and the provider refuses to stop a unit while it owns an unexpired
Collector deployment, device preflight, or Agent execution lease. The Worker
is marked offline only after inactive state is confirmed. Registry admission,
heartbeat, registration and Collector/Agent renewal share a fresh row mutex.
The provider holds that mutex while checking leases/stopping, so cached online
state or a renewal that waited past expiry cannot bypass the drain barrier.
Recovery after a committed drain and completed stop can finalize the offline
state without issuing stop again. These API admission changes must be deployed
with the new provider; installed r30 alone does not implement this fence.

Every decision progresses through the existing immutable
`accepted → applying → applied/failed` receipt contract. Exact retries are
idempotent. Only a SHA-256 failure fingerprint and stable detail code are
stored; raw `systemctl` diagnostics remain provider-local. Convergence must
also occur before the configured timeout.

PostgreSQL and external systemd are not one atomic transaction. A source-process
crash after a completed host action is recovered from absolute unit state and
committed receipts, not by replaying a delta or assuming exactly-once I/O.
Failed/superseded applications can leave partial host state or sticky drain;
an operator/new current decision must reconcile it, not silently roll it back.

Reference deployment files:

- `deploy/systemd/icheck-systemd-capacity-provider.service`;
- `deploy/systemd/systemd-capacity-provider.env.example`;
- `deploy/systemd/systemd-capacity.json.example`;
- `deploy/systemd/icheck-collector-capacity@.service`; and
- `deploy/systemd/icheck-agent-capacity@.service`.

The instance templates read a common pool environment plus an optional
per-instance override under `/etc/icheck/capacity/`. Operators pre-provision
the maximum allowed instance set; the provider can start and stop only those
instances. Its database role should be limited to scaling decisions/receipts,
the two Worker registries, and active lease evidence.

As the deployment operator, render and review the exact-instance permission rule:

```bash
/opt/icheck/.venv/bin/icheck-systemd-capacity-provider \
  --config /etc/icheck-workers/capacity/systemd-capacity.json --render-polkit
```

Rendering performs no controller cycle, service action or database transaction.
After explicit review, install the output root-owned mode 0644 in
`/etc/polkit-1/rules.d/00-icheck-capacity.rules`. Audit both local and vendor rule
directories: an earlier broad allow rule can override a later denial. Regenerate
after reviewed config changes; do not authorize every capacity template instance
with a regex. The rule permits only start/stop of exact configured unit names and
denies other systemd manager actions for this account. There is no root fallback.
Generic manager operations, including transient creation, supply no exact
unit/verb details in the tested systemd 255 contract and therefore fail closed.
See the [systemd manager implementation](https://github.com/systemd/systemd/blob/v255/src/core/dbus-manager.c)
and [Polkit rule ordering](https://polkit.pages.freedesktop.org/polkit/polkit.8.html).

The actual r29 permission drill passes allowed start/stop and denies an unlisted
instance, API start, restart, enable and transient creation under the non-root
account. Temporary fixtures only ran sleep and were removed, including their
rule. This does not accept real Worker registration, DB receipts, convergence,
lease-aware scale-in, process-loss or load. No production capacity rule is
installed on the host yet.

## Current limits

- The opt-in local systemd process adapter is implemented. VM provisioning,
  cloud/hypervisor APIs, Kubernetes, and automatic host termination are not.
- No automatic host termination is permitted.
- The representative 1,000-target PostgreSQL scale run and process-kill
  acceptance remain open.
- Policies cover Collector and Agent pools; other worker classes can be added
  only after workload-specific queue and lease semantics are defined.
