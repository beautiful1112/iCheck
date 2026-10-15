export const assetCategories = [
  ["", "All devices"], ["wired", "Wired devices"], ["wireless", "Wireless devices"],
  ["firewalls", "Firewalls"], ["servers", "Physical servers / hosts"], ["storage", "Storage"], ["other", "Other"],
] as const;

export type DeviceHealth = {
  device_id: string;
  state: "up" | "poll_failed" | "degraded" | "stale" | "unknown" | "disabled" | "pending" | "not_monitored";
  reason: string;
  checked_at: string;
  backend_id: string | null;
  connections: Array<{connection_id: string; protocol: string; state: string; reason: string;
    observed_at: string | null; sample_age_seconds: number | null; freshness_limit_seconds: number; source: string}>;
};

export function healthLabel(state?: string): string {
  return ({up: "Up · collecting", poll_failed: "Poll failed", degraded: "Degraded", stale: "Stale",
    unknown: "Unknown", disabled: "Disabled", pending: "Setup pending", not_monitored: "Not monitoring"} as Record<string, string>)[state || "unknown"] || "Unknown";
}

export function healthEvidenceKey(connection: Pick<DeviceHealth["connections"][number], "connection_id" | "source">, index: number): string {
  return JSON.stringify([connection.connection_id, connection.source, index]);
}

export function inventoryPagePath(search: string, category: string, cursor?: string): string {
  const params = new URLSearchParams({limit:"50", search});
  if (category) params.set("category", category);
  if (cursor) params.set("cursor", cursor);
  return `/assets/devices/page?${params}`;
}
