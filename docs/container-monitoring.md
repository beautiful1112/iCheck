# Container monitoring with cAdvisor

The container plugin extends the shared Studio monitoring-template contract.
Source and private fixture checks cover authoring, selected-host metric testing,
reviewed activation, gateway projection, fresh Prometheus evidence and a native
Grafana proposal. A real cAdvisor/container runtime has not been qualified, and
the implementation is deployed in r19.2. Its approved LAB gateway profile and
online Collector metric-test capability are configured for explicit GUI testing.
The GUI's source-preview label does not claim real-container qualification.

## Engineer workflow

Use an existing cAdvisor endpoint on the monitored container host. Add that host
in Assets with a **Container exporter (cAdvisor)** connection, then describe the
desired measurements in Studio's **Monitor a device or API** builder. Choose
Containers if the inferred technology needs correction. The default port is
8080; HTTPS is preferred. An unauthenticated HTTP endpoint requires an explicit
protected gateway exception. Select a protected account/token reference for
HTTPS authentication rather than pasting credentials into the conversation.

Choose an exact container name or cgroup/container ID, or leave both blank for
all matching runtime containers. The selector is platform-owned, not a field the
model may invent or change. The first profile requires non-root IDs and nonempty
image labels; host/raw cgroups do not count as a container. A template supports
at most 32 matching runtime containers; use an exact selector for a larger host.

Review the measurement groups, explicitly select a registered host and click
**Test selected target**. Each matching container must expose every requested
measurement with its declared type and current source timestamps. Only then
review the collection interval and **Enable tested template**. Publication and
enrollment use the same reviewed transaction as the other exporter plugins.
No device is contacted simply by opening Studio or generating a proposal.

Prometheus must receive fresh samples for every requested metric on the same
container IDs, plus cAdvisor health evidence. Exporter `up`, a fresh
`container_last_seen` value or CPU on one ID and memory on a different ID is
insufficient. Fresh metric proof unlocks a native Grafana proposal; confirmation
saves it and returns its URL. Template edits/rollback retain prior versions and
require a new binding test when the configuration changes. Metric collection
does not prove workload readiness or fault resolution.

## Measurements and timestamps

The catalog follows the [cAdvisor Prometheus metrics documentation](https://github.com/google/cadvisor/blob/v0.60.6/docs/storage/prometheus.md):

| Group | Measurements | Grafana presentation |
| --- | --- | --- |
| CPU | CPU usage seconds counter | Rate in CPU cores, not an invented busy percentage |
| Memory | Working-set and reported memory-limit bytes | Bytes; ratio only for a positive reported limit |
| Disk | Filesystem usage and limit bytes | Filesystem bytes by device |
| Network | Received/transmitted byte counters | Rates by interface |
| Uptime | Container start timestamp | Container age |

cAdvisor attaches source timestamps to measured statistics; the gateway preserves
them instead of stamping cached data as newly measured. The selected statistic
timestamps must be within 60 seconds, with at most five seconds of future skew.
Static specification/start-time gauges can be scrape-timestamped normally.
The [upstream collector implementation](https://github.com/google/cadvisor/blob/v0.60.6/lib/metrics/prometheus.go)
also explains why `container_last_seen` is not enough to prove cached statistics
are current. New activation may wait for the next cAdvisor housekeeping sample.

The platform reads `/metrics`; it does not invent a per-request `collect[]`
cAdvisor API or alter the host's enabled metric flags. Gateway `allowed_collectors`
entries are the approved measurement groups (`cpu`, `memory`, `disk`, `network`,
`metadata`), not a claim that those flags were installed on the remote host.
Missing runtime/kernel metrics cause an explicit test failure. Network metrics
can vary with shared namespaces; CPU percentage needs an appropriate quota
denominator, and zero/unlimited memory limits are not fabricated percentages.

## Security and deployment boundaries

The existing leased Collector and gateway retain literal-IP target pinning,
certificate verification, protected credential revision checks and before/after
I/O authority checks. Provision a reviewed native `cadvisor` gateway profile such
as `preview-containers`, with explicit sites, target CIDRs, ports, measurement
groups and TLS names. The worker needs the `cadvisor` preflight capability.
No profile or network approval was broadened by this source work.

Only declared measurements, health indicators and the bounded labels `id`,
`name`, `image`, `cpu`, `device` and `interface` are forwarded. Environment and
arbitrary container labels are filtered; known credential echoes, nonfinite
values, duplicate projected series and oversized responses fail closed. Bodies
remain limited to 2 MB and 20,000 samples. Protected credential references retain
their previous adapter scope during rotation; older HTTP/Linux/Windows profiles
are not silently expanded to cAdvisor. Metrics stay in Prometheus, not a second
SQL metric store or a custom iCheck chart renderer.

iCheck itself stays native. This plugin does not install Docker, start containers,
mount host filesystems, grant a privileged cAdvisor deployment or manage Kubernetes.
Those are separate host-administration decisions. Filters and Grafana variables
are not container-level access isolation over a shared Prometheus data source.

## Qualification and remaining work

The [container acceptance path](../tests/test_container_monitoring.py) and shared
private exporter/Prometheus test cover wire projection, preserved timestamps,
target activation, field/credential handling, per-ID metric completeness and
confirmed native Grafana proposals. The private Prometheus run uses timestamped
cAdvisor-shaped fixture data, not a real container. See the
qualification record (private development evidence; not distributed).

The paired application cutover and approved LAB worker/gateway profiles are
deployed. Still required: a real runtime/cAdvisor host check, live model-backed
authoring and fresh target-dashboard acceptance. The shared VMware source slice is
documented in [VMware monitoring](vmware-monitoring.md); real-vSphere qualification
and actual metric notification delivery remain outstanding.
