# Windows collection reference

This directory contains reviewed configuration inputs, not evidence of a live
installation.

Use the signed `windows_exporter` MSI from the official project release and pin
the approved version and SHA-256 in the environment deployment repository. The
recommended baseline enables only CPU, disk, memory, network, OS, selected
service, and system collectors. Restrict TCP/9182 at the Windows Firewall to the
site Prometheus addresses.

Continuous path:

```text
Prometheus -> windows_exporter:9182/metrics -> Windows performance data
Prometheus -> remote_write -> scalable metrics backend
```

On-demand diagnostics use the versioned `builtin-psrp-cim-diagnostics`
artifact. Create an `on_demand` deployment with a deployment-scoped credential
profile reference, then call its trigger endpoint. The adapter accepts only the
fixed read-only operations published in that artifact, requires WinRM TLS, and
uses the built-in credential-brokered PSRP transport. Install the Worker with
the `windows` extra, add `psrp_cim` to its capabilities, configure target and
port allowlists, and provide either a trusted WinRM certificate chain or
`ICHECK_COLLECTOR_PSRP_CA_FILE`. Arbitrary PowerShell and insecure certificate
verification are not accepted. `ICHECK_COLLECTOR_PSRP_CONFIGURATION_NAME` can
select a constrained JEA endpoint.
