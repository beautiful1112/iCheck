/** Metadata only. Service tokens belong in protected API inputs, never these types. */
export type GrafanaConnection = {
  id: string; name: string; api_url: string; public_url: string; datasource_uid: string;
  folder_uid: string; revision: number; enabled: boolean; token_configured: boolean;
};
export type GrafanaChange = {
  id: string; connection_id: string; resource_kind: "dashboard" | "folder"; resource_uid: string;
  folder_uid: string; definition: Record<string, unknown>; previous_resource: Record<string, unknown> | null;
  expected_resource_version: string | null; plan_hash: string; status: string; approved_by: string | null;
  error_code: string | null; review_url: string; resource_url: string; restore_of_id: string | null;
};
export type GrafanaPrincipal = { permissions: string[]; authorization_scope: {all?: boolean} };
export function canManageGrafana(principal: GrafanaPrincipal | null) {
  return principal?.authorization_scope.all === true &&
    (principal.permissions.includes("*") || principal.permissions.includes("metrics.manage"));
}
export function proposalReference(value: unknown): {id: string; title: string; status: string} | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  if (typeof row.id !== "string" || !/^[0-9a-f-]{36}$/.test(row.id) ||
      row.review_url !== `/dashboards?change=${row.id}` ||
      !["dashboard", "folder"].includes(String(row.resource_kind)) ||
      !["proposed", "applying", "applied", "conflict", "unknown", "rejected"].includes(String(row.status))) return null;
  const definition = row.definition as Record<string, unknown> | undefined;
  return {id: row.id, title: typeof definition?.title === "string" ? definition.title : "Grafana change", status: String(row.status)};
}

/** Full-page native tool URLs only; never render arbitrary model markdown as a saved resource. */
export function grafanaResourceLinks(value: unknown, toolName?: string): {title:string; url:string}[] {
  if (!value || typeof value !== "object") return [];
  const row = value as Record<string, unknown>;
  const safeUrl = (input: unknown): string | null => {
    if (typeof input !== "string" || input.length > 2048 || /[\s\\]/.test(input)) return null;
    try {
      const parsed = new URL(input);
      if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash ||
          !/\/(?:d|dashboards\/f)\/[A-Za-z0-9_-]{1,64}$/.test(parsed.pathname) ||
          [...parsed.searchParams.keys()].some(key => !["from", "to", "var-device"].includes(key))) return null;
      return parsed.href;
    } catch { return null; }
  };
  const proposal = proposalReference(row);
  if (proposal?.status === "applied") {
    const url = safeUrl(row.resource_url);
    return url ? [{title:proposal.title, url}] : [];
  }
  if (!["grafana.dashboard.get", "grafana.dashboard.link", "grafana.folder.get",
        "grafana.dashboards.search", "grafana.folders.search"].includes(toolName || "")) return [];
  const items = Array.isArray(row.dashboards) ? row.dashboards : Array.isArray(row.folders) ? row.folders : [row];
  return items.slice(0, 20).flatMap(input => {
    if (!input || typeof input !== "object") return [];
    const item = input as Record<string, unknown>;
    const resource = item.resource as {spec?:{title?:unknown}} | undefined;
    const url = safeUrl(item.url);
    const title = item.title ?? resource?.spec?.title;
    return url ? [{title:typeof title === "string" ? title : "Open Grafana dashboard", url}] : [];
  });
}

export function readableDefinition(value: Record<string, unknown>) {
  const object = (input: unknown): Record<string, unknown> => input && typeof input === "object" ? input as Record<string, unknown> : {};
  const panels = (Array.isArray(value.panels) ? value.panels : []).slice(0, 20).map(input => {
    const panel = object(input);
    return {title: String(panel.title || `Panel ${panel.id}`), type: String(panel.type || ""),
      queries: (Array.isArray(panel.targets) ? panel.targets : []).slice(0, 8).map(target => String(object(target).expr || ""))};
  });
  const list = object(value.templating).list;
  const variables = (Array.isArray(list) ? list : []).slice(0, 12).map(input => {
    const variable = object(input);
    return {name: String(variable.name || ""), type: String(variable.type || ""),
      query: typeof variable.query === "string" ? variable.query : String(object(variable.query).query || "")};
  });
  const range = object(value.time);
  const validRange = typeof range.from === "string" && range.from.length > 0 && range.from.length <= 128 &&
    typeof range.to === "string" && range.to.length > 0 && range.to.length <= 128;
  const timeRange = value.time === undefined ? "Not specified — Grafana may use its default; this proposal does not preserve a custom range."
    : validRange ? `${range.from} → ${range.to}` : "Invalid time range — review Advanced details.";
  const refresh = value.refresh === undefined ? "Not specified — not an explicit off setting."
    : value.refresh === "" ? "Off"
    : typeof value.refresh === "string" && value.refresh.length <= 32 ? value.refresh
    : "Invalid refresh setting — review Advanced details.";
  const timezone = value.timezone === undefined || value.timezone === "" ? "Grafana default"
    : typeof value.timezone === "string" && value.timezone.length <= 128 ? value.timezone : "Invalid timezone";
  return {panels, variables, timeRange, refresh, timezone,
    description: typeof value.description === "string" ? value.description.slice(0, 4000) : ""};
}
