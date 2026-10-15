# Governed Ansible action adapter

## Boundary

The first replaceable Phase 5 execution backend is a focused Ansible Runner
MCP service. It is separate from the API and Agent Worker and runs as the
`icheck-actions` operating-system principal. It does not accept an inline
playbook, arbitrary playbook path, arbitrary CLI command, shell fragment, raw
inventory, or model-created target pattern.

Each reviewed catalog operation exposes five stage MCP Tools:

```text
ansible.<operation>.precheck
ansible.<operation>.dry_run
ansible.<operation>.apply
ansible.<operation>.postcheck
ansible.<operation>.rollback
```

The adapter also exposes one global, read-only
`ansible.action_outcome.lookup` Tool. It accepts the original iCheck Tool-call
ID and reads the local write ledger; it does not run Ansible or depend on the
current project file contents. Approved apply and rollback calls require that
ID in the `icheck/toolCallId` MCP metadata before execution. The ledger binds
it to the operation, stage, idempotency key and action fingerprint before
dispatch.

Pre-check, dry-run, and post-check execute with Ansible check mode. Dry-run
uses the pinned apply playbook. Apply is the only Tool that accepts an
`idempotency_key`; its local durable ledger returns the stored result for an
exact duplicate and fails closed if the key is reused with different
arguments or a previous process lost the outcome. Rollback remains a separate
state-changing Tool and is executed only through the parent change plan's
frozen rollback request and a second four-eyes decision. It uses the same
ledger with a stage-specific identity and its Tool-call ID as the provider-side
idempotency key, without adding an argument to the frozen rollback mapping.

The lookup reports `applied` with the retained Runner run ID only after a
successful terminal apply or rollback result is saved. Missing, interrupted,
failed and timed-out writes report `unknown`, never `not_applied`. Its
observation time is the lookup time, not a claim about when target state
changed. The correlation index
and terminal ledger records use atomic replacement and file plus directory
sync; a new runtime instance reads them. A provider report is still not an
independent target check, recipient receipt or final disposition.

The systemd unit explicitly uses `KillMode=control-group`, a ten-second stop
limit and final SIGKILL so a stop or restart targets the Runner child as well
as the adapter process. A local process-kill test terminates the ledger owner
after dispatch and confirms that a new process reports `unknown` and refuses
to re-execute the same call. This does not prove the effect of a real Runner
process on a network device; that requires the live lab drill.

## Catalog and execution safety

`icheck.ansible-catalog/v1` pins:

- the deterministic hash of every regular file in the project tree;
- one inventory file and its SHA-256;
- an explicit list of individual inventory host aliases per operation;
- four relative playbook paths;
- a closed, fully required, scalar-only parameter schema; and
- a bounded per-operation timeout.

Project symbolic links, path traversal, drift, inventory drift, secret-like
parameter names, reserved `ansible_*`/`icheck_*` parameters, target patterns,
unbounded strings/numbers, and undeclared Tools fail closed. The runner
executable is absolute and SHA-256 pinned in production. It is launched as an
argument array without a shell, with stdin/stdout/stderr disconnected, a
minimal environment, a new process group, a timeout, and an ephemeral mode
`0700` private-data directory. Event count and event-file bytes are bounded;
raw events and stdout never enter Agent evidence.

The structured result contains only status, changed-task/failed/event counts,
duration, opaque run ID, operation/stage, catalog hash, and replay state. A
failed apply returns an MCP error. Because the write was dispatched, iCheck
keeps the original Tool call running and its outcome unknown; it does not
automatically authorize or start rollback. The provider lookup also remains
`unknown`, since a failed Runner run may have changed the device partially.
A failed pre-check, dry-run, post-check, or rollback is returned as boolean
evidence so the deterministic state machine can stop or mark verification or
rollback failure accurately.

For approval preview, the apply contract should declare dry-run
`summary_paths` such as `changed`, `changed_tasks`, `failed_tasks`, and
`catalog_sha256`. The Tool-call result hash supplies the exact preview
fingerprint. Raw Ansible diff text is deliberately neither returned nor stored.

In a scoped deployment, each inventory host alias and `allowed_targets` value
must be the corresponding iCheck Device UUID. The apply contract declares
`"authorization_target_paths": {"target": "device_id"}`. Plan creation and
approval/execution then resolve that UUID against the Investigation's frozen
device/site scope. A scoped change with no binding, an unknown Device, a moved
Device, or an out-of-scope Device fails before Ansible runs. Global platform
administrators remain compatible without a redundant binding.

## Credentials

The MCP server uses a bearer token and binds to loopback in production. The
existing lease-bound Worker credential profile may also supply these
allowlisted headers:

```text
X-Icheck-Ansible-User             -> ansible_user
X-Icheck-Ansible-Password         -> ansible_password
X-Icheck-Ansible-Become-Password  -> ansible_become_password
X-Icheck-Ansible-Network-OS       -> ansible_network_os
```

They are written only to the job's mode `0600` `env/extravars`, are never
placed on the process command line, are not returned in MCP content, and are
deleted with the private-data directory. Use a site-specific MCP server,
credential profile, Worker selector, and catalog so one credential grant does
not span unrelated sites. Private-key and multiline secret transport is not
enabled in this slice.

## Tool publication and change contract

Starting the adapter does not activate an action. An administrator still must:

1. create and validate the five stage Tool Artifacts and the read-only outcome
   lookup Artifact, each matching live `tools/list`;
2. publish the immutable versions;
3. register this MCP server and attest each Tool;
4. activate the exact versions; and
5. grant the Agent and peer approver the required permissions.

To qualify a later unknown-write lookup, the published apply Artifact must
freeze `outcome_lookup_tool_name` and an `outcome_lookup_correlation` contract
pointing to the lookup Artifact's registry name. Both activations must remain
pinned to this same MCP server. Existing published Artifacts are not silently
upgraded. Local adapter tests cover apply and rollback correlation, runtime
re-instantiation, failed and interrupted runs, and catalog drift; live Runner
and target-state conformance remain separate release gates.

The apply Tool uses `icheck.change-tool/v1`. Its target paths contain `target`
and every operation parameter; its idempotency path is `idempotency_key`; its
four stages name the corresponding advertised Tools and use `success` as the
boolean result path. `authorization_target_paths` binds `target` to
`device_id` for scoped execution. The rollback Tool deliberately has no recursive change
contract. Production strict admission permits it only when it exactly matches
a rollback already frozen by a failed parent plan. It cannot be proposed as a
standalone legacy action.

## Non-container deployment

The repository provides:

- `deploy/systemd/icheck-ansible-adapter.service`;
- `deploy/systemd/ansible-adapter.env.example`; and
- `deploy/ansible/catalog.json.example`.

Install the optional dependency into the application virtual environment only
when the reviewed action host is ready:

```bash
.venv/bin/pip install -e '.[action]'
```

Calculate the pins after installing the final files:

```bash
sha256sum /opt/icheck/.venv/bin/ansible-runner
sha256sum /etc/icheck/ansible/inventory/hosts.yml
.venv/bin/python -c 'from pathlib import Path; from icheck.action_adapters.ansible_runner_mcp import project_tree_sha256; print(project_tree_sha256(Path("/etc/icheck/ansible/project")))'
```

Create `/var/lib/icheck/ansible-adapter` for `icheck-actions`, keep the bearer
token mode `0600`, copy the reviewed catalog and pack under
`/etc/icheck/ansible`, then start the unit. Register the local endpoint as
`http://127.0.0.1:8766/rpc`; loopback HTTP is allowed by the MCP gateway.

This repository currently contains the adapter code and deployment templates,
but this workstation has no `ansible-runner` executable and no approved live
write pack. Nothing is installed, activated, or executed against a device in
this slice. Live lab acceptance follows only after the user provides the test
inventory and maintenance window.
