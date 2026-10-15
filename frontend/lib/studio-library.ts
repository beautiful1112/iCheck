import {publishedVersion, validReference, type Capability} from "./studio-builder.ts";

export const categories = [
  {id: "collectors", label: "Data collectors", hint: "Collection templates for devices, exporters and APIs. Target activation is separate."},
  {id: "mcp", label: "MCP servers", hint: "One server package contains one or more tools. Installation applies to the whole package, not each tool."},
  {id: "tools", label: "Function tools", hint: "Registered AI tools and tool contracts. Agent permissions still control execution."},
  {id: "automation", label: "Workflows & skills", hint: "Reusable checks and automation definitions. Publishing does not start a run."},
  {id: "other", label: "Other capabilities", hint: "Topology, visualization and historical artifacts."},
] as const;
export type Category = typeof categories[number]["id"];
export type ExtensionInstallation = {id: string; artifact_id: string; active_version_id: string; enabled: boolean; last_health_status: string};
export type RegisteredTool = {id: string; name: string; description: string; transport: string; enabled: boolean; read_only: boolean};
export type ExternalServer = {id: string; name: string; enabled: boolean; last_health_status: string | null; last_tool_count: number | null};
export function categoryOf(row: Capability): Category {
  if (row.labels?.format === "icheck.mcp-extension/v1" || row.versions.some(v => v.definition?.format_version === "icheck.mcp-extension/v1")) return "mcp";
  if (row.kind === "collector") return "collectors";
  if (row.kind === "tool") return "tools";
  return ["workflow", "skill"].includes(row.kind) ? "automation" : "other";
}
export function latestVersion(row: Capability) {return [...row.versions].sort((a,b) => b.version-a.version)[0];}
export function partitionMCPDrafts(rows: Capability[], installations: ExtensionInstallation[] | null) {
  const drafts: Capability[] = [], capabilities: Capability[] = [];
  for (const row of rows) {
    // Only never-validated drafts move to history. Installed/deprecated packages
    // and a server with an older validated version must remain manageable.
    const draftOnly = categoryOf(row) === "mcp" && row.versions.every(v => v.status === "draft")
      && !installations?.some(item => item.artifact_id === row.id);
    (draftOnly ? drafts : capabilities).push(row);
  }
  return {capabilities, drafts};
}
export type MCPToolSummary = {name: string; operation: string; commands: string[]};
export function mcpTools(version: Capability["versions"][number] | undefined): MCPToolSummary[] | null {
  const spec = version?.definition?.spec;
  if (version?.definition?.format_version !== "icheck.mcp-extension/v1" || !spec || typeof spec !== "object" || !("tools" in spec) || !Array.isArray(spec.tools)) return null;
  const tools: MCPToolSummary[] = [];
  for (const item of spec.tools) {
    if (!item || typeof item !== "object" || typeof item.name !== "string" || typeof item.operation !== "string"
      || !Array.isArray(item.commands) || !item.commands.every((command: unknown) => typeof command === "string")) return null;
    tools.push({name: item.name, operation: item.operation, commands: item.commands});
  }
  return tools;
}
export function capabilityState(row: Capability, installations: ExtensionInstallation[] | null) {
  if (categoryOf(row) !== "mcp") return publishedVersion(row) ? "Published template" : "Draft only";
  if (installations === null) return "Installation status unavailable";
  const installed = installations.find(item => item.artifact_id === row.id);
  return installed ? installed.enabled ? "Installed · Enabled" : "Installed · Disabled" : "Not installed";
}
export function conversationLink(row: Capability) {
  const id = row.labels?.studio_session_id;
  return validReference(id) ? `/studio/builder?session=${id}` : null;
}
/** Preserve previously shared Studio URLs without retaining the old crowded landing. */
export function legacyStudioDestination(params: URLSearchParams) {
  const kept = new URLSearchParams();
  for (const key of ["session", "artifact", "investigation", "template_version"]) {
    const value = params.get(key);
    if (validReference(value)) kept.set(key, value);
  }
  const create = params.get("create");
  if (create && ["workflow", "monitor", "dashboard", "automate", "extension"].includes(create)) kept.set("create", create);
  return kept.size ? `/studio/builder?${kept}` : null;
}
