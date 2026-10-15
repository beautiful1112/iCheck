# VMware monitoring

The VMware source plugin uses the shared Studio monitoring-template workflow:
describe measurements, review the template, test a selected exporter endpoint,
enable the exact tested version and confirm its native Grafana proposal.
Host, VM and datastore fixtures passed the source path; a temporary native
Prometheus stored a host fixture. The implementation is deployed in r19.2 and its
approved LAB gateway profile and online Collector metric-test capability are
configured. This does not qualify a real vSphere environment.

## Select the endpoint and object

Register an existing **VMware exporter** connection in Assets. Its address is
the exporter endpoint, normally port 9272, not the vCenter SDK address. The first
wire profile follows
[vmware_exporter 0.18.4 source](https://github.com/pryorda/vmware_exporter/blob/9f9bfaf0b96cdaeb3ff293c1d489f9f3c716097f/vmware_exporter/vmware_exporter.py).
The [upstream project](https://github.com/pryorda/vmware_exporter) states that it
needs a new maintainer; this compatibility profile is not a maintenance or
fleet-scale certification.

The exporter must already have a read-only vSphere account and verify its
vCenter/ESXi TLS certificate. An iCheck account/token credential protects the
exporter's HTTPS listener or reverse proxy, not its SDK login. Do not paste either
secret into Studio chat. HTTP requires an explicit protected gateway exception.

Choose **VMware** in Studio, select ESXi host, virtual machine or datastore,
and enter the exact observed object name. An optional datacenter disambiguates
names. The adapter rejects multiple matching identities, even when the name is
the same. The exporter does not expose a managed-object ID in this profile;
duplicate VM names may need renaming or a different exporter profile.

| Object | Supported groups | Important prerequisite |
| --- | --- | --- |
| ESXi host | CPU, memory, disk I/O, network, uptime | Host and performance metrics enabled |
| Virtual machine | CPU, memory, guest disks, network, uptime | VM performance enabled; guest disks need VMware Tools and guest collection |
| Datastore | Capacity and free bytes | Datastore collection enabled |

The model uses only the selected object's catalog and reports unsupported
requests. No target is contacted by previewing a draft. Test every requested
measurement before enabling it; exporter `up`, object power or accessibility
alone is insufficient. Missing powered-off VM measurements are not fabricated.

## Metric and health meaning

The adapter calls `/metrics` without arbitrary target, SDK URL or section
overrides. Only selected-object measurements and its power/accessibility state
are forwarded. Tags, custom attributes and other objects are filtered. Guest
disk capacity/free series must cover the same partitions, bounded to 128.
Known credential echoes, duplicate projected series, nonfinite values and
oversized responses fail closed.

The upstream emits gauges without original performance timestamps. The proof
therefore explicitly records `sample_freshness_scope=gateway_receipt` and
`source_timestamp_available=false`. Prometheus verifies current enrollment and
fresh scrape samples, not the age of an omitted vSphere performance timestamp.
Collection does not prove workload readiness, object health or fault resolution.
Power/accessibility zero is observed state, not a reason to turn a complete
measurement receipt into a healthy-object claim.

Grafana treats performance averages as gauges, not counters. Host reported
memory MiB is converted to bytes; VM memory percentages are divided by 100,
following [vSphere percentage units](https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/PerformanceManagerUnit_enum/).
Ratios use a positive measured denominator. CPU raw values are MHz; disk/network
performance averages retain their vSphere reported units rather than receiving
an invented counter rate. Dashboard creation still needs a separate confirmation
and retains its previous version and real saved URL.

## Deployment and qualification

The Collector needs the `vmware_exporter` capability and a reviewed gateway
profile such as `preview-vmware`, with explicit endpoint CIDRs, ports, TLS names,
credential references and object scopes (`hosts`, `vms`, `datastores`). Existing
credential adapter scopes are preserved during rotation. The approved LAB gateway
profile and Collector test capability are now deployed without widening the
existing CIDRs. No vSphere account, lab enrollment or SQL metric store was created.

The exporter may read more objects upstream than the gateway forwards. Its
account/configuration must enforce any required upstream boundary; output filters
and Grafana variables are not device-level isolation. Repeated per-object scrapes
also need capacity evaluation before fleet use.

See the shared qualification record (private development evidence; not distributed)
and [plugin acceptance path](../tests/test_vmware_monitoring.py). Remaining gates
are a real vSphere endpoint, live model-backed authoring and fresh target-dashboard
acceptance. The paired application/profile provisioning is deployed. No VMware
exporter was remotely installed and no monitored infrastructure was changed.
