import type {GrafanaPrincipal} from "./grafana-plugin";

export type DashboardTarget = {uid: string; title: string};
export function canAuthorDashboard(principal: GrafanaPrincipal | null) {
  return principal?.authorization_scope.all === true &&
    ["investigations.create", "investigations.read", "metrics.read"].every(permission =>
      principal.permissions.includes("*") || principal.permissions.includes(permission));
}

export function dashboardAuthoringRequest(connectionId: string, brief: string, target: DashboardTarget | null,
  changeId?: string) {
  const context = changeId
    ? `Read previous proposal ${changeId} using grafana.changes.get. Preserve its requested changes, inspect the current remote dashboard when present, then produce a new revision.`
    : target ? `Revise existing dashboard UID ${target.uid}. Read its current definition and resource version first; preserve panels, variables and settings unless the user asks to change them.`
      : "Create a new dashboard proposal.";
  return {
    title: `${changeId || target ? "Revise" : "Create"} dashboard: ${brief.trim()}`.slice(0, 255),
    objective: `${brief.trim()}\n\nUse Grafana connection ${connectionId}. ${context}\nDiscover actual metrics and sample relevant queries. Use native Grafana tools to produce a validated proposal and return its review link. Report missing data explicitly. Do not apply changes, enroll devices, run device probes or enable collection.`,
    execution_mode: "diagnose", scope: {capability_task: "grafana-dashboard", grafana_connection_id: connectionId, authoring_brief: brief.trim(),
      ...(target ? {grafana_resource_uid: target.uid} : {})},
    route_purpose: "investigation", created_by: "web.dashboards",
  };
}
