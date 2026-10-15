# Prometheus and SNMP Exporter reference deployment

Current plan, 12 October 2026: add a separate native Grafana instance to visualize
the existing Prometheus data. Preserve the current TSDB, exporter custody and
approved discovery/gateway path. See [Grafana integration](../../docs/grafana-monitoring-design.md)
and [current rollout status](../../docs/prometheus-snmp-rollout.md). Older r30/r34
installation statements below are historical; the r16/r17 preview records now
include live switch collection and the gateway-backed Assets status. They are
not evidence that Grafana or additional exporters are installed.

These files are a VM/bare-metal reference, not an automatic production
installer. Pin and verify the Prometheus and SNMP Exporter binaries for the
target operating system, place them under `/opt/icheck/bin`, and copy the
systemd units from `deploy/systemd`.

The reference was installed and verified on host `zhao` on 2026-09-18 with
Prometheus 3.13.3 LTS and SNMP Exporter 0.30.1. Both endpoints are deliberately
loopback-only. The reproducible runtime inputs used for that installation are
under `deploy/runtime`; see `docs/prometheus-snmp-rollout.md` for evidence and
remaining production gates.

Configuration layout:

```text
/etc/icheck-workers/prometheus/prometheus.yml
/etc/icheck-workers/prometheus/snmp-targets.json
/etc/icheck-workers/prometheus/windows-targets.json
/etc/icheck-workers/snmp-exporter/snmp.yml
/etc/icheck/secrets/snmp-exporter.env
/var/lib/icheck-prometheus/
```

The current r29 units use separate `icheck-prometheus` and `icheck-snmp-exporter`
accounts, not the API account. The parent `/etc/icheck-workers` is root-owned
0711; each component config directory is root:component 0750 with config files
0640. Prometheus' private StateDirectory is 0700. All target-list paths must use
this layout too. PID 1 reads the optional exporter environment; do not add a
monitoring account to the API's `icheck` group. The actual 9 October migration
retains TSDB and target-list data and passes both local readiness checks; see
[r29 evidence](../../acceptance/native-test-release-r29-2026-10-09.json).

`snmp.yml` is the generated combined module and authentication configuration.
Do not hand-edit it; keep the matching generator input with the capability
pack. Authentication fields may reference environment variables for SNMPv3
username, password, and privacy password. Keep those values in the optional
external environment or secret-provider file and protect it with mode `0600`.

The existing operator-provisioned continuous path is:

```text
Prometheus -> SNMP Exporter -> device
Prometheus -> remote_write -> scalable metrics backend
iCheck -> bounded PromQL API -> metrics backend
Prometheus -> windows_exporter -> Windows host metrics
```

Current unbundled source adds a GUI-approved path through a database-free,
current-authority gateway, not API ownership of these files or exporter secrets.
The [HTTP SD job example](gui-continuous.yml.example) is syntax-checked but not
installed. Cached discovery cannot authorize a scrape: gateway approval,
withdrawal, expiry and custody are rechecked per attempt. See the
[continuous monitoring contract](../../docs/continuous-monitoring.md) for the
coordinated h5 migration/native cutover and real exporter/load/series-scope gates.
Do not enable it against installed r30 or duplicate devices in both this job
and the retained manual target lists. The integrated demo remains deferred.

The iCheck `snmp_exporter` worker adapter is intended for bounded previews,
validation, and normalized observation workflows. It is not a replacement for
Prometheus scraping and must not be used to store high-cardinality continuous
time series in PostgreSQL.

Host-local installation and self-scrape acceptance are complete. Real-device,
remote-write, cardinality, rollback, and scale acceptance remain open. See
`docs/prometheus-snmp-rollout.md` for the exact boundary and evidence.
