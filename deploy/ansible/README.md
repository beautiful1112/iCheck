# Ansible action pack layout

This directory contains deployment templates, not an enabled write pack. Copy
`catalog.json.example` to `/etc/icheck/ansible/catalog.json` only after the
inventory and every referenced playbook/role/collection have been reviewed.
Replace the zero hashes with the deterministic project-tree hash documented in
`docs/ansible-action-adapter.md` and the ordinary SHA-256 of the inventory.

The service rejects absolute paths, traversal, symbolic links, project or
inventory drift, arbitrary Ansible limit expressions, secret-like tool
arguments, and tools not declared by the catalog. It does not accept inline
playbooks or arbitrary shell/CLI commands.

For scoped production changes, use the iCheck Device UUID as the Ansible
inventory host alias and catalog target. Declare the apply contract binding as
`"authorization_target_paths": {"target": "device_id"}`. The platform then
resolves the target through the Investigation's frozen device/site scope both
when the plan is created and before approval/execution.
