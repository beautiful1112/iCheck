# Agent runtime HTTPS protocol

## Boundary

`icheck.agent-runtime/v1` removes the remote Agent Worker's direct database
dependency. PostgreSQL and model credentials remain inside the regional control
plane. The Worker needs only:

- an HTTPS control-plane URL;
- its tenant and region IDs;
- a bootstrap token, rotating Worker bearer token, and production mTLS identity;
- Worker-local MCP credential resolution and an exact MCP host allowlist.

Workflow schedule, Alert-trigger, and Situation-integration outboxes are not
Agent duties. The region-pinned `icheck-workflow-dispatch-worker` owns those
PostgreSQL queues.

## Execution sequence

After registration and claim, active runtime requests carry the protocol
version, execution ID, bearer identity, mTLS identity when enabled, and the
unexpired execution lease token. The completion endpoint may accept an exact
retry after that lease is cleared, using its committed receipt as proof.

```text
claim
  -> runtime/bootstrap
  -> checkpoint get/list/put/writes
  -> runtime/reason
  -> runtime/tool
       -> optional MCP invocation interrupt -> Worker-local credential use
       -> optional action approval interrupt -> human decision and re-claim
  -> progress with complete bounded graph state
  -> completion
```

The endpoints are rooted at
`/api/v1/agent/executions/{execution_id}/runtime`. Checkpoint configuration is
limited to `thread_id`, `checkpoint_ns`, and `checkpoint_id`; the thread must
equal the Investigation ID. LangGraph values use its typed serializer and
Base64 transport with a 10 MB decoded-value ceiling. Arbitrary thread deletion
is not exposed to Workers. Aggregate checkpoint requests are capped at 15
million Base64 characters, and the shared HTTPS client rejects request or
response bodies over 32 MB.

Reason and Tool calls have canonical SHA-256 operation IDs over the protocol
version, operation type, execution ID, and complete typed input. The control
plane independently recomputes the ID, binds an input hash to a dedicated
durable LangGraph operation thread, and rejects drift. An exact retry returns or
continues the same operation instead of invoking a provider or Tool twice.

Completion is a separate Worker-authenticated endpoint. In the same
transaction as the terminal event and audit, the control plane stores the
Worker ID, lease token hash, and exact completion-request digest. Once
committed, only the same Worker, token and request can replay that receipt;
the replay adds no event or audit. A new approval attempt clears the previous
receipt. The Worker retries completion at most twice after a transport error
or upstream 5xx, and does not apply that retry policy to other operations.

## Interrupts and credentials

Action approval and MCP execution are nested, durable Tool interrupts. A
state-changing action waits for the existing four-eyes decision and resumes the
same checkpoint after a new claim. An action already persisted as running after
an unknown crash remains outcome-unknown by default; only an exact interruption
owned by the current remote operation may continue.

For MCP, the control plane validates publication, activation, schemas, Worker
selector, endpoint allowlist, and active lease. It returns a short-lived
credential *reference*, never a secret. The Worker resolves the reference from
its local Vault/environment broker, invokes the allowlisted HTTPS endpoint,
validates and redacts the result, closes or revokes the resolved lease, and
returns a correlation-bound result. The control plane validates it again before
persisting evidence.

## Failure and security rules

The outer investigation now checkpoints each sequential request in its own
`icheck-tool-request` Task. Completed requests retain their primitive results
and citations; the next request owns a different exact human interrupt. A
Task has no retry policy for unknown infrastructure writes. A refused governed
action can have real completed read-only prerequisites without an action call.
The Tool response therefore additionally supports `status: failed` with
`failure: {error_type: ActionRejected, tool_call_ids, evidence_ids}`. Both ID
lists are unique, bounded to 100 and contain only actual scoped ledger IDs.
That response has neither a result nor an interrupt. The Worker raises a typed
failure and preserves the completed prerequisite and prior-request trace as
the graph escalates. It never invents a primary call ID or treats refusal as
success. Exact operation retries reuse the recorded refusal without I/O.

Successful Tool completion can atomically seal a minimized exact-call citation
binding. Internal and MCP recovery use that binding before returning citations;
unbound older/manual internal completions do not acquire guessed references.
Result/source identity drift denies recovery. Migration `v0x2z4b6d8f1` adds the
namespace-isolated immutable receipt table and bounded JSON guards. Drain active
investigations and deploy the API/Worker pair after migration: old Workers and
pending outer-node checkpoint layouts are not accepted mixed-version rollout.
See batch/citation evidence (private development evidence; not distributed)
for the controlled acceptance boundary; deployed identity/transport remains a
separate gate.

- Bearer identity, mTLS identity, execution owner, tenant/region, and active
  lease must all agree; unauthorized or stale requests fail closed, apart from
  the exact committed completion receipt described above.
- Graph state has an exact shape, immutable Investigation identity/scope/budgets,
  monotonic bounded counters, a 2 MB encoded ceiling, and inline-secret checks.
- Progress persists the user-facing Investigation checkpoint but never copies a
  lease token or full state into ordered event payloads.
- A claim that says resume while the server has no executable checkpoint fails.
  Persisted counters without a checkpoint also fail rather than restarting.
- The client serializes synchronous checkpoint RPCs for deterministic ordering.
- Errors returned to the Worker are type-bounded; model content, Tool result
  bodies, credential values, and raw provider errors are absent from audit.

## Deployment and acceptance

Use `deploy/systemd/icheck-agent-worker.service` with
`agent-worker.env.example` on remote Worker hosts. It deliberately has no
`ICHECK_DATABASE_URL`. Run `icheck-workflow-dispatch-worker` from the regional
control-plane tier with PostgreSQL and a fixed tenant/region namespace.

Automated acceptance covers unauthorized and stale lease denial, cross-thread
checkpoint denial, operation-ID tampering, complete HTTP-only reasoning and
internal Tool loops, delegated MCP with secret redaction, and four-eyes action
resume on a second claim. A private PostgreSQL process-loss probe now also
passes with two real database-free Agent Workers, natural lease expiry, one
persisted Tool result, and product checkpoint continuity; see the
saved report (private development evidence; not distributed).
It uses development authentication and loopback HTTP with a controlled model.
Remaining environment acceptance is production Worker-CA/proxy rollout,
HTTPS/mTLS process-kill and cancellation drills, and representative multi-worker
concurrency/latency testing.
The completion replay has controlled timeout and upstream-502-after-commit
tests plus a non-owner PostgreSQL concurrent request test. A separate
loopback TCP response-loss report (private development evidence; not distributed)
records a real Worker retry after a fault proxy consumed the committed success
response and closed its socket. Production proxy/Worker-CA/mTLS fault acceptance
remains open.
An additional local mTLS report (private development evidence; not distributed)
uses an ephemeral CA, requires a verified Worker certificate, rejects a
certificate-free connection, strips spoofed identity/address headers at the
TLS proxy, and repeats the completion-loss drill. This checks the implemented
HTTPS client and Worker identity binding, not the deployed CA or ingress.

Production checkpoint storage is separately provisioned by the database owner
with `icheck-checkpoint-schema-prepare`. The runtime's `verify` mode checks
the installed saver version, required tables and indexes, and least-privilege
grants, namespace defaults and forced RLS before serving graph traffic; it
cannot create tables or write saver migration history. The owner command
backfills known historical graph threads and rejects orphaned ones. Every
runtime request binds the Investigation tenant and region on its dedicated
PostgresSaver connection. A restricted-role Worker report (private development evidence; not distributed)
passes local mTLS and response-loss flow with this boundary; native PostgreSQL
tests prove no-context, cross-region and cross-tenant checkpoint denial. The
deployed CA/proxy, role grants and production-scale populated-store backfill
are not accepted.
