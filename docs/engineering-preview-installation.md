# Native installation and upgrade

For a new dedicated Ubuntu 24.04 x86_64 server, use the
[r19.27 one-command installer](native-one-command-installer.md). It automates
prerequisite installation and the first-install steps below. This manual remains
the administrator reference for the r19.26 application payload and guarded
upgrades; the new installer does not overwrite an existing installation.

## Scope and prerequisites

Engineering Preview 0.1.0-preview.r19.26 is a native single-node evaluation
distribution. Docker is not required. This guide is for a Linux administrator;
the archive is not an unattended appliance installer. Start on a dedicated
evaluation host, validate its setup, and only then consider controlled exposure.

The archive includes the backend wheel, 86 pinned binary dependency wheels,
standalone Next.js GUI, systemd templates and operator helpers. It does **not**
include a database, device enrollment, saved credentials, AI keys, lab networks,
existing dashboards or notification destinations. Third-party service binaries
and their installation are separate prerequisites.

Prepare Linux x86_64 with systemd, CPython matching `backend-runtime.json`
(the supplied wheelhouse is qualified for CPython 3.12.3), PostgreSQL, Node.js
22.13 or newer, nginx, Prometheus, SNMP Exporter, Grafana and Alertmanager as
needed. Match the package's runtime manifest; do not assume another architecture
or Python patch level passes the native verifier. Reserve space for retained
releases, SQL backups, monitoring data and Grafana storage. No fleet-size claim
is made by this preview.

The database head is `a4g6i8k0m2p5`. Always deploy a matching backend and GUI.
Published source retains synthetic tests and examples, not the private
development host's saved state. See [qualification](../acceptance/public-preview-qualification.json).

## 1. Verify and trust the package

Download the native archive and `SHA256SUMS` from the same GitHub release.
Check the selected file before extraction:

```bash
sha256sum --check --ignore-missing SHA256SUMS
tar -tzf icheck-engineering-preview-0-1-0-r19-26-public-linux-amd64.tar.gz
```

A checksum detects mismatch; it is not a cryptographic publisher signature.
Review the archive, then extract it under a root-owned deployment directory.
Keep all installer path ancestors root-owned and not group/other writable.
Never run installer code as root directly from a user-writable Git checkout.
Set `BUNDLE` to the extracted absolute trusted bundle path. Replace every
`YOUR_SERVER`, local operator name, network and example value in this guide.

## 2. Stage inactive application releases

Create the isolated installer environment and its pinned verifier dependency:

```bash
python3.12 -m venv /opt/icheck/backend-installer-venv
/opt/icheck/backend-installer-venv/bin/pip install --no-index --only-binary=:all: \
  --find-links "$BUNDLE/backend-wheelhouse" 'packaging==26.3'
/opt/icheck/backend-installer-venv/bin/python \
  "$BUNDLE/operator/deploy/stage_native_backend.py" \
  --service-accounts prepare --acknowledge-accounts
/opt/icheck/backend-installer-venv/bin/python \
  "$BUNDLE/operator/deploy/verify_native_backend_bundle.py" \
  "$BUNDLE" "$BUNDLE/operator/deploy/systemd"
/opt/icheck/backend-installer-venv/bin/python \
  "$BUNDLE/operator/deploy/stage_native_backend.py" \
  "$BUNDLE" --units "$BUNDLE/operator/deploy/systemd"
/opt/icheck/node/bin/node "$BUNDLE/operator/deploy/stage_native_frontend.mjs" \
  "$BUNDLE/frontend"
```

Provision a trusted Node runtime at `/opt/icheck/node/bin/node` or adapt the
reviewed native unit consistently. Staging verifies files and creates inactive
release directories; it does not migrate SQL, switch active pointers or start
services. See [native release contracts](native-release.md) for ownership,
service-account preparation and guarded first-install/switch prerequisites.

## 3. Prepare PostgreSQL and private service configuration

Create a dedicated database owner/migration identity and separate non-owner
runtime roles without superuser/BYPASSRLS. Keep connection URLs in protected
environment files, never public examples or command arguments. Do not reuse a
developer database. Copy the appropriate files from `operator/deploy/systemd`
to `/etc/systemd/system` and create protected environment files from examples.
Examples contain placeholders that **must** be replaced, not reusable credentials.

Set `RELEASE` to the staged backend virtualenv. Load the migration URL through
your protected deployment session, keep the backend fleet stopped, then run:

```bash
"$RELEASE/bin/icheck-db" heads
"$RELEASE/bin/icheck-db" upgrade --acknowledge-drained
"$RELEASE/bin/icheck-db" current
"$RELEASE/bin/icheck-checkpoint-schema-prepare" \
  --runtime-role icheck_api --acknowledge-database-ddl
```

Checkpoint preparation needs a separate `ICHECK_CHECKPOINT_SCHEMA_OWNER_URL`.
Grant API/runtime DML, not schema ownership. Provision restricted SQL profiles
with `icheck-db worker-grants`; see [namespace isolation](tenant-region-isolation.md)
and [native release](native-release.md). Revoke PostgreSQL's default `PUBLIC TEMP`
grant where required by the internal-worker inspector. Agent/Collector workers
use the authenticated API and must not receive database URLs.

Required deployment settings include `ICHECK_AUTO_CREATE_SCHEMA=false`,
`ICHECK_CHECKPOINT_SETUP_MODE=verify`, required control-plane authentication,
secure session cookies, password login and reviewed worker identity. Keep
infrastructure write features disabled. The Agent capability list must contain
`openai_compatible,mcp,anthropic`. Do not overwrite an existing list during upgrade.

Provision managed AI key custody from the trusted bundle after the service
account and API environment exist:

```bash
/opt/icheck/backend-installer-venv/bin/python -I -B \
  "$BUNDLE/tools/preview_managed_ai.py" --acknowledge-key-provisioning
```

This creates server-local encryption-key custody, not a provider API key. Back
it up securely. Provision managed device credential custody according to
[device onboarding](device-onboarding.md); it is separate from AI key custody.

## 4. Switch the paired release and configure HTTPS

Use the guarded `switch_native_backend.py` and `switch_native_frontend.mjs`
commands documented in [native release](native-release.md). They require exact
old/new release IDs, the installed migration head and a confirmed stopped fleet.
For first installation, use the documented `none` previous-release value. Do
not replace the guarded switch with an unverified symlink operation.

Configure nginx, worker mTLS and the HTTPS origin before remote access. The
`preview_native_ingress.py` helper is for a locally issued evaluation CA; verify
its explicit address/identity inputs with `--help`. A public deployment needs
an appropriate trusted certificate and firewall policy, not a copied lab CA.
Keep API/frontend listeners private behind the ingress. See
[worker identity](worker-mtls.md) and [authentication](control-plane-auth.md).

## 5. Create the admin account and choose its password

**Username: `admin`. Password: the unique passphrase you choose below. There is
no preset/shared password, and bootstrap alone does not enable password login.**

The helper needs a reviewed, protected API environment with the prerequisites
above and configured preview CA custody. In a protected administrator session:

```bash
"$RELEASE/bin/python" -I -B "$BUNDLE/tools/preview_native_access.py" prepare-api \
  --listen-ip YOUR_SERVER_IPV4 --acknowledge-preview-access
systemctl restart icheck-control-plane
"$RELEASE/bin/python" -I -B "$BUNDLE/tools/preview_native_access.py" bootstrap-admin \
  --operator-user YOUR_LOCAL_LINUX_USER --admin-username admin \
  --acknowledge-preview-access
systemctl restart icheck-control-plane
```

It creates a single human administrator, saves the expiring administrator API
token privately in `/var/lib/icheck-preview-access/admin-access-token`, and
removes bootstrap authority from the API environment. Restart removes the old
bootstrap value from process memory. It refuses unsafe/replayed provisioning.

Now run the following as the local Linux operator owning that private token,
using a protected interactive terminal:

```bash
python3 "$BUNDLE/tools/preview_operator_password.py" \
  --api https://YOUR_SERVER:8443/api/v1 \
  --token-file /var/lib/icheck-preview-access/admin-access-token \
  --ca-file /var/lib/icheck-preview-access/preview-ca.pem
```

Enter and confirm a unique **15–256-character** password/passphrase at the hidden
prompts. The tool displays the web username, never the password. Store it in your
password manager. Sign in at `https://YOUR_SERVER:8443/login` with `admin` and
that passphrase. Do not use `admin/admin`. No real password is published in this
manual. See [account access](engineering-preview-server-access.md) for recovery.

## 6. Start monitoring integrations and workers

Install the separate service binaries and configure persistent storage. Follow
[Prometheus/SNMP](prometheus-snmp-rollout.md), [Grafana](grafana-access.md) and
[metric alerts](metric-alerts.md). Provision your own Grafana administrator and
service-account token; they are not the iCheck admin password.

Create finite, explicitly approved collector/gateway profiles. No lab CIDRs are
preapproved. `preview_native_access.py prepare-workers` takes your explicit
`--lab-cidr` values; inspect its help and review generated configuration.
When using optional native plugin profiles, pass approved CIDRs to
`preview_native_monitoring.py --add-preview-plugin-profiles --allowed-cidr ...`
with `--acknowledge-local-monitoring`. Its preview profile site is `LAB`; for a
different site use reviewed custom gateway configuration. Do not copy benchmark
examples as a real authorization policy.

Enable only the required API, frontend, Collector, Agent, Projection, Indicator,
lease reconciler and monitoring gateway units. Optional workflow dispatch,
SNMP module installation and Alertmanager units need their separately documented
accounts, grants and configuration before being enabled. Merely installing a
unit template is not permission to activate it. Automatic AI investigation
remains disabled until its owner approves a standing policy in the GUI.

## 7. Verify your installation

Check service states and API readiness. Confirm unauthenticated inventory access
is rejected and admin password login succeeds. Run the read-only smoke helper
with your protected admin token/CA. Add devices **through the GUI** and explicitly
approve any target test; the package never enrolls test devices automatically.
Configure providers and search in AI Settings using your own credentials. Model
or search tests may incur provider charges and require explicit approval.

Verify fresh target measurements, dashboard data, actual notification delivery
and backup restoration in your own environment. Package checks and synthetic
tests do not establish these outcomes. Record any remaining acceptance gaps.

## Upgrade, backup and recovery

Before upgrading, record active backend/frontend IDs, migration head and worker
capabilities. Back up PostgreSQL, `/etc/icheck`, `/etc/icheck-workers`, ingress,
systemd overrides, encryption custody, Grafana storage and monitoring data.
Validate logical archives and practice restoration on a separate host. Never
upload backups or passwords to this repository.

Stage and verify the new pair offline. Stop API/frontend and **all** relevant
workers, including workflow dispatch and SNMP module installation, before
migrating. Preserve existing keys, routes, credentials and approved networks.
Add capabilities without replacing unrelated settings. Switch the paired release,
restart the previously active services, then repeat health/login/read-only checks.

Do not automatically downgrade a migrated database. In particular, the provider
preset migration refuses a lossy downgrade when non-OpenRouter custody exists.
Use reviewed fix-forward or a coordinated full restore of application/schema/key
state. Preserve the old release and backups until acceptance is complete.
