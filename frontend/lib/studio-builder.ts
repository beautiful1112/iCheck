/** Task-facing Studio semantics. Publishing is never proof of enabled monitoring. */
export type StudioTask = "monitor" | "dashboard" | "automate" | "extension";
export type StudioKind = "collector" | "workflow" | "skill" | "tool" | "topology" | "visualization" | "report";
export type StudioSession = {
  id: string; title: string; brief: string; artifact_kind: StudioKind; status: string;
  target_url: string; current_spec: Record<string, unknown>; artifact_id: string | null;
  artifact_version_id: string | null; generation_attempt_id: string | null; tokens_used: number;
  updated_at: string; messages: {id: string; role: string; content: string; structured_content: Record<string, unknown>}[];
};
export type Capability = {id: string; name: string; kind: string; description: string; labels?: Record<string, unknown>;
  versions: {id: string; version: number; status: string; validation_report: Record<string, unknown>;
    definition?: Record<string, unknown>; collector_definition?: {adapter_type: string} | null}[]};
export type StudioPrincipal = {subject: string; permissions: string[]; authorization_scope: {all?: boolean}};
export const tasks: {id: StudioTask; label: string; hint: string}[] = [
  {id: "monitor", label: "Monitor a device or API", hint: "Describe the target and measurements."},
  {id: "dashboard", label: "Build a dashboard", hint: "Discover real metrics and propose Grafana panels."},
  {id: "automate", label: "Automate a check", hint: "Create a reusable workflow or diagnostic Skill."},
  {id: "extension", label: "Create a plugin or MCP server", hint: "Generate executable tools, dependencies and checks."},
];
export function permits(principal: StudioPrincipal | null, permission: string) {
  return Boolean(principal && (principal.permissions.includes("*") || principal.permissions.includes(permission)));
}
export function validReference(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}
export function inferTask(brief: string, chosen: StudioTask | null): StudioTask {
  if (chosen) return chosen;
  if (/\b(mcp|netmiko)\b/i.test(brief) && /\b(create|build|generate|plugin)\b|\u521b\u5efa|\u751f\u6210/i.test(brief)) return "extension";
  if (/\b(grafana|dashboard|chart|panels?)\b|\u4eea\u8868\u76d8|\u56fe\u8868/i.test(brief)) return "dashboard";
  if (/\b(workflow|automat\w*|skill|runbook|diagnos\w*|check)\b|\u5de5\u4f5c\u6d41|\u81ea\u52a8\u5316|\u6392\u9519/i.test(brief)) return "automate";
  return "monitor";
}
export function authoringKind(brief: string): "workflow" | "skill" | "tool" {
  if (/\bworkflow\b|\u5de5\u4f5c\u6d41/i.test(brief)) return "workflow";
  if (/\bmcp\b.*\btool\b|\btool\b.*\bmcp\b/i.test(brief)) return "tool";
  return /\b(skill|runbook|diagnos\w*|troubleshoot\w*)\b|\u6392\u9519|\u6280\u80fd/i.test(brief) ? "skill" : "workflow";
}
export function legacyKind(kind: string) {return kind === "visualization" || kind === "report";}
export function publishedVersion(capability: Capability) {
  return capability.versions.filter(version => version.status === "published").sort((a, b) => b.version - a.version)[0] || null;
}
export function runtimeLink(capability: Capability) {
  const version = publishedVersion(capability);
  if (!version || !validReference(version.id) || legacyKind(capability.kind)) return null;
  if (capability.kind === "workflow" || capability.kind === "skill") return `/?${capability.kind}_version=${encodeURIComponent(version.id)}`;
  if (capability.kind === "collector") {
    if (["snmp", "linux", "windows", "containers", "vmware"].includes(String(version.validation_report?.plugin)) || version.collector_definition?.adapter_type === "http_metrics") return validReference(capability.id) ?
      `/studio?artifact=${encodeURIComponent(capability.id)}&template_version=${encodeURIComponent(version.id)}` : null;
    return "/assets/devices";
  }
  return null;
}
export function validationFor(session: StudioSession | null) {
  if (!session) return null;
  const message = [...session.messages].reverse().find(item => item.structured_content.artifact_version_id === session.artifact_version_id && item.structured_content.validation_report);
  const report = message?.structured_content.validation_report;
  return report && typeof report === "object" ? report as Record<string, unknown> : null;
}
export function canPublish(session: StudioSession | null, principal: StudioPrincipal | null) {
  return Boolean(session && !isExtension(session) && !legacyKind(session.artifact_kind) && session.status === "validated" &&
    session.artifact_version_id && validationFor(session) && validationFor(session)?.publication_blocked !== true &&
    permits(principal, "capabilities.manage") && principal?.authorization_scope.all === true);
}
export function previewFacts(session: StudioSession) {
  const spec = session.current_spec;
  if (isExtension(session)) return {target: `Authorized ${String(spec.device_type)} inventory device, chosen at test/install`,
    interval: null, credential: "Protected SSH reference, resolved outside generated code",
    outcomes: Array.isArray(spec.tools) ? spec.tools.map(tool => {const row = tool as Record<string, unknown>;
      return `${String(row.name)} · ${row.operation === "backup" ? "protected configuration backup receipt" : "read-only device result"}`;}) : [],
    result: session.status === "validated" ? "Executable draft fixture checks passed; installation is managed separately" : session.status};
  const mapping = isHTTPMonitoring(session) && Array.isArray(spec.metrics) ? spec.metrics : Array.isArray(spec.field_mappings) ? spec.field_mappings : [];
  const nodes = Array.isArray(spec.nodes) ? spec.nodes : [];
  const outcomes = (session.artifact_kind === "collector" ? mapping : nodes).slice(0, 20).map(input => {
    const row = input && typeof input === "object" ? input as Record<string, unknown> : {};
    return row.name && typeof row.value_pointer === "string" ? `${row.name}: ${row.value_pointer || "JSON root"}` : String(row.destination_field || row.title || row.tool_name || "Declared output");
  });
  return {target: session.target_url || "Selected when the capability is used",
    interval: session.brief.match(/Requested interval:\s*(\d+)\s*seconds/i)?.[1] || null,
    credential: session.brief.match(/Credential reference:\s*([^\n]+)/i)?.[1] || null,
    outcomes: session.artifact_kind==="skill"&&Array.isArray(spec.allowed_tools)?spec.allowed_tools.map(tool=>`Read-only tool: ${String(tool)}`):isExporterMonitoring(session) && Array.isArray(spec.groups) ? spec.groups.map(group => `${group} (native exporter; actual samples required)`) :
      isSNMPMonitoring(session) && Array.isArray(spec.symbols) ? spec.symbols.map(String) : outcomes, result: session.status === "published" ?
      ["workflow","skill"].includes(session.artifact_kind)?"Reusable check saved; explicit launch and trigger activation are separate":"Template saved; target activation is separate" :
      validationFor(session)?.publication_blocked === true ? "External validation required; cannot enable" :
      session.status === "validated" ? ["workflow","skill"].includes(session.artifact_kind)?"Draft contract validation passed; no check was executed":"Draft validation passed; no live collection proof" : session.status};
}
export function isExtension(session: StudioSession) {return session.current_spec.format_version === "icheck.mcp-extension/v1";}
export function isHTTPMonitoring(session: StudioSession) {
  return session.current_spec.contract === "icheck.http-monitoring-authoring/v1" || session.messages.some(message =>
    message.role === "system" && message.structured_content.http_monitoring_input);
}
export function isSNMPMonitoring(session: StudioSession) {
  return session.current_spec.contract === "icheck.snmp-monitoring-authoring/v1" || session.messages.some(message =>
    message.role === "system" && message.structured_content.snmp_monitoring_input);
}
export function isExporterMonitoring(session: StudioSession) {
  return session.current_spec.contract === "icheck.exporter-monitoring-authoring/v1" || session.messages.some(message =>
    message.role === "system" && message.structured_content.exporter_monitoring_input);
}
export function monitoringPlugin(session: StudioSession): "http" | "snmp" | "linux" | "windows" | "containers" | "vmware" {
  if (isSNMPMonitoring(session)) return "snmp";
  const input = session.messages.find(message => message.role === "system" && message.structured_content.exporter_monitoring_input)?.structured_content.exporter_monitoring_input;
  if (isExporterMonitoring(session) && input && typeof input === "object" && "plugin" in input && input.plugin === "vmware") return "vmware";
  if (isExporterMonitoring(session) && input && typeof input === "object" && "plugin" in input && input.plugin === "containers") return "containers";
  return isExporterMonitoring(session) && input && typeof input === "object" && "plugin" in input && input.plugin === "windows" ? "windows" : isExporterMonitoring(session) ? "linux" : "http";
}
export function inferMonitoringSource(brief: string): "metrics" | "snmp" | "linux" | "windows" | "containers" | "vmware" | "sample" {
  if (/\bsnmp\b/i.test(brief)) return "snmp";
  if (/\b(vmware|vsphere|vcenter|esxi)\b/i.test(brief)) return "vmware";
  if (/\b(containers?|docker|cadvisor|kubernetes|k8s)\b|\u5bb9\u5668/i.test(brief)) return "containers";
  if (/\bwindows(?:_exporter)?\b/i.test(brief)) return "windows";
  if (/\blinux\b|\bnode_exporter\b/i.test(brief)) return "linux";
  return /\binventory\b|IP.?MAC|\u7ec8\u7aef|\u8d44\u4ea7|wifi/i.test(brief) ? "sample" : "metrics";
}
export function isMonitoring(session: StudioSession) {return isHTTPMonitoring(session) || isSNMPMonitoring(session) || isExporterMonitoring(session);}
export function credentialFreeTarget(value: string) {
  const parsed = new URL(value);
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash ||
      [...parsed.searchParams.keys()].some(name => /token|password|secret|api[_-]?key|authorization/i.test(name))) {
    throw new Error("Use a credential-free HTTP(S) URL. Select a protected credential reference separately.");
  }
  return parsed.href;
}
