# Prometheus and SNMP Exporter reference deployment

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
/etc/icheck/prometheus/prometheus.yml
/etc/icheck/prometheus/snmp-targets.json
/etc/icheck/prometheus/windows-targets.json
/etc/icheck/snmp/snmp.yml
/etc/icheck/secrets/snmp-exporter.env
/var/lib/icheck/prometheus/
```

`snmp.yml` is the generated combined module and authentication configuration.
Do not hand-edit it; keep the matching generator input with the capability
pack. Authentication fields may reference environment variables for SNMPv3
username, password, and privacy password. Keep those values in the optional
external environment or secret-provider file and protect it with mode `0600`.

The continuous production path is:

```text
Prometheus -> SNMP Exporter -> device
Prometheus -> remote_write -> scalable metrics backend
iCheck -> bounded PromQL API -> metrics backend
Prometheus -> windows_exporter -> Windows host metrics
```

The iCheck `snmp_exporter` worker adapter is intended for bounded previews,
validation, and normalized observation workflows. It is not a replacement for
Prometheus scraping and must not be used to store high-cardinality continuous
time series in PostgreSQL.

Host-local installation and self-scrape acceptance are complete. Real-device,
remote-write, cardinality, rollback, and scale acceptance remain open. See
`docs/prometheus-snmp-rollout.md` for the exact boundary and evidence.
