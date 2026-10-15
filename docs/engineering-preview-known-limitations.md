# Engineering Preview limitations

This release is an engineering preview, not a claim of production readiness,
fleet scalability, universal device support or unattended remediation.

- The one-command installer supports fresh Ubuntu 24.04 x86_64 hosts only.
  Other Linux distributions, ARM, offline installation and automatic upgrades
  are not qualified by this installer.
- No devices, existing credentials, provider keys, private dashboards or lab
  permissions are shipped. Setup creates fresh custody, two reusable Grafana
  dashboards and a local Alertmanager receiver; monitoring networks must be
  chosen explicitly. Examples do not authorize access.
- Evaluation server/worker certificates expire after 90 days; integration tokens
  expire after 30 days. Automatic renewal is not implemented in this prerelease.
- Synthetic tests do not replace device interoperability, load, backup/restore
  or end-to-end notification tests on the installation owner's environment.
- Model catalogs and successful probes do not guarantee reasoning quality,
  support for every artifact schema or accurate results. Paid tests are opt-in.
- Internet research requires a configured provider. Retrieved content is
  untrusted evidence, never permission to execute instructions or install code.
- MCP generation/installation is constrained by supported adapters and runtime
  contracts. One package can expose several tools. A generated tool is not
  automatically authorized for every target or capable of arbitrary remediation.
- Legacy SSH compatibility is a device-specific exception requiring explicit
  approval; it does not disable host identity verification or relax the fleet.
- Monitoring health requires fresh expected measurements, not merely `up=1`,
  a successful connection or a retained verification record.
- Grafana has separate browser authentication. A shared Prometheus data source
  is not protected by dashboard variables as though they were tenant isolation.
- Alert investigation is disabled by default. Authorized policies are bounded
  and read-only; in-flight calls may finish after silence/closure. Remote
  Alertmanager federation and unrestricted nested automation are not claimed.
- Full automatic research-to-monitoring-to-dashboard acceptance remains open.
- Expanded Advanced AI settings may overflow a narrow phone viewport when
  retained configuration values are long; the default guided setup fits.
- No shared admin password, email password recovery or bundled identity provider
  is supplied. Preserve administrative recovery and custody securely.
- Release checksums are integrity checks, not cryptographic publisher signatures.

See [native installer acceptance](../acceptance/native-installer-r19-27.json),
[application publication checks](../acceptance/public-preview-qualification.json)
and [installation](native-one-command-installer.md) before deploying.
