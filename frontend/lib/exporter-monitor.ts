export type ExporterPlugin = "linux" | "windows" | "containers" | "vmware";
export type ExporterGroup = "cpu" | "memory" | "disk" | "network" | "uptime";
export type ExporterMonitorSpec = {contract: "icheck.exporter-monitor/v1"; plugin: ExporterPlugin;
  groups: ExporterGroup[]; scheme: "http" | "https"; server_name: string | null; auth_mode: "none" | "basic" | "bearer";
  container_id?: string | null; container_name?: string | null;
  vmware_scope?: "hosts" | "vms" | "datastores" | null; vmware_name?: string | null; vmware_datacenter?: string | null};
const gatewayProfiles = {snmp: "preview-snmp", https_api: "preview-http", node_exporter: "preview-linux",
  windows_exporter: "preview-windows", cadvisor: "preview-containers", vmware_exporter: "preview-vmware"} as const;
export type MonitoringProtocol = keyof typeof gatewayProfiles;
export function defaultMonitoringProfile(protocol: MonitoringProtocol) {return gatewayProfiles[protocol];}
// Request selection only; authoritative metric names and validation come from the server.
const collectors: Record<Exclude<ExporterPlugin, "vmware">, Record<ExporterGroup, string[]>> = {
  linux: {cpu: ["cpu"], memory: ["meminfo"], disk: ["filesystem"], network: ["netdev"], uptime: ["stat", "time"]},
  windows: {cpu: ["cpu"], memory: ["memory"], disk: ["logical_disk"], network: ["net"], uptime: ["system"]},
  containers: {cpu: ["cpu"], memory: ["memory"], disk: ["disk"], network: ["network"], uptime: ["metadata"]},
};
export function exporterProtocol(plugin: ExporterPlugin) {return ({linux:"node_exporter",windows:"windows_exporter",containers:"cadvisor",vmware:"vmware_exporter"} as const)[plugin];}
export function exporterCollectors(spec: ExporterMonitorSpec) {
  if (spec.plugin === "vmware") return spec.vmware_scope ? [spec.vmware_scope] : [];
  const plugin = spec.plugin;
  return [...new Set(spec.groups.flatMap(group => collectors[plugin][group]))];
}
