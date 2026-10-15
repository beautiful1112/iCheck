# Native monitoring prerequisites

The r19 application candidate needs a protected SNMP generator and Alertmanager
in addition to the existing Prometheus, SNMP Exporter and Grafana installation.
The separate native-prerequisite supplement contains the qualified Linux x86_64
generator, Alertmanager and amtool binaries with their licenses, notices and
provenance. It does not install services, configure credentials, enable monitoring
or alter the frozen application archive.

The running server now has the approved r19.1 application and native integrations;
see the deployment receipt (private development evidence; not distributed).
For a new host, deploy the matching application and database,
provision the integrations below, and verify their GUI journeys before reporting
them as usable on the server. Back up configuration, application SQL, keys and
relevant native state before a coordinated cutover. Do not mix source scripts
with a privileged installed runtime.

## Binary custody and host requirements

Verify the supplement's distributed checksum once when receiving it. Transfer it
to root-owned, non-writable path ancestry before using it for privileged deployment.
Its `manifest.json` identifies the exact binaries and source versions. Preserve
the included `licenses/` files with the installation's third-party notices.

The generator is built from SNMP Exporter 0.30.1 commit
`48b810afbd9222b74439ad1cf7d0d7b7c0cf4290`, matching this server's exporter. It is
dynamically linked to Net-SNMP and the host C/OpenSSL libraries; this server resolves
`libnetsnmp.so.40`, `libc.so.6`, `libssl.so.3` and `libcrypto.so.3`. These libraries
are not bundled. This check is not portability qualification for another Linux
distribution. The generator has no supported `--version` flag: its protected
runtime manifest binds the source version to the executable digest instead.

Alertmanager and amtool are upstream Linux/amd64 0.34.1 binaries, revision
`73c6bfe7393929211294c1954f30d8ed78e4d0ad`. Their original download checksum was
verified before the private notification pipeline test. They are not running
services merely because the supplement contains them.

## SNMP runtime preparation

After deployment approval, place `bin/generator` at `/opt/icheck/bin/generator`
under the existing root-owned binary custody rules. Review
`config/generator.json` against the installed exporter and place it at
`/etc/icheck-workers/snmp-runtime/generator.json`. Do not replace the exporter,
existing authentication custody or assigned module catalog.

Provision the real standard MIB dependencies at `/opt/icheck/snmp-mibs` or the
protected configured `ICHECK_SNMP_GENERATOR_MIB_DIRECTORY`. MIB source files are
not included in this supplement. Vendor MIBs require the appropriate permissions
and complete imports; Studio accepts them in an immutable authoring recipe.
Missing dependencies must remain a compilation error, not a fabricated metric.

Configure the reviewed root-owned module catalog and the broker template from
the paired application's `operator/deploy/systemd/`. The broker runs only
`/opt/icheck/.venv/bin/python -I -m icheck.snmp_install_broker`, with a protected
Unix socket and the fixed local API UID. It accepts neither commands nor paths
from a browser. Check that the installed application contains that module before
starting it. Do not grant a general sudo command to the API.

Only the selected gateway profile may opt into
`allow_installed_snmp_templates=true`. Preserve its existing sites, CIDRs, ports,
managed credential scope and finite approval bounds. Profile permission does not
approve any target. Validate native generation and parser behavior without a
device first; actual target testing and monitoring need separate approval.
See [SNMP module generation](snmp-exporter-attestation.md).

## Alertmanager and metric rules

Place the reviewed Alertmanager and amtool binaries under `/opt/icheck/bin/`.
Provision the dedicated unprivileged account, private configuration and durable
state directory. Use the paired application's optional Alertmanager unit with
listener `127.0.0.1:9093` and clustering disabled. The loopback lifecycle endpoint
and Alertmanager must not be exposed through the public proxy.

Use the native examples in the application bundle's `config/alertmanager/`.
Create a scoped service receiver identity, put its token in the protected bearer
file, and bind its exact subject/namespace in the control-plane configuration.
The token is not a web password and must not enter chat, URLs or browser storage.

Provision `/var/lib/icheck-metric-rules` and its managed catalog with the ownership
and set-group-ID mode described in [metric alerts](metric-alerts.md). Merge only
the managed rule-file entry and Alertmanager destination into the existing
Prometheus configuration. Preserve scrape jobs, TSDB, retention and existing
inventory-event evaluation. Validate with the installed promtool and amtool
before activating the reviewed services.

## Verification and removal boundaries

After the paired cutover, confirm the exact SQL head and healthy API/worker
heartbeats. In Studio, describe a template, test an explicitly selected target,
enable its reviewed enrollment and verify every requested fresh measurement in
Prometheus. Confirm and open its real Grafana dashboard. A published draft,
successful ping, exporter `up` or configured receiver is not an acceptance result.

Test a metric rule against actual samples, confirm it, induce a safe controlled
threshold breach and inspect its delivered inbox receipt. Acknowledge it, clear
the lab condition and inspect the later cleared receipt separately. Retain the
investigation evidence; acknowledgement and clearance do not prove recovery.
The [GUI quick start](engineering-preview-quick-start.md) contains the full demo.

Remove integrations only through their documented withdrawal and consumer checks.
Do not delete an installed SNMP module still used by an enrollment, wipe alert
history, remove existing scrape jobs or erase native state/backups simply to
uninstall the supplement. Keep application rollback releases and protected keys.
