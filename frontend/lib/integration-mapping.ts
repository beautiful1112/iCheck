export type MappingAsset = {id: string; name: string; management_ip: string | null; site: string | null;
  enabled: boolean; revision: number; identity_revision: number};
export type MappingRow = {resource_id: string; remote_id: string; name: string; current: boolean;
  binding_revision: number; state: "linked" | "unlinked" | "needs_review"; reason: string | null;
  device: MappingAsset | null; suggestion: MappingAsset | null; match: string};
export type MappingView = {items: MappingRow[]; total: number; offset: number; limit: number;
  connection_revision: number; scan_id: string | null; can_link: boolean};
export type MappingChoices = Record<string, MappingAsset>;

export function mappingLabel(row: MappingRow) {
  if (row.state === "linked") return "Linked";
  const reasons: Record<string, string> = {
    connection_disabled: "Connection disabled",
    connection_changed: "Connection changed; review the link",
    source_scope_unconfirmed: "Source scope needs a new sync",
    complete_inventory_sync_required: "Waiting for a completed sync",
    not_seen_in_latest_scan: "Not seen in the latest scan",
    source_name_changed: "Source name changed; review the link",
    asset_unavailable: "Asset unavailable or disabled",
    asset_identity_changed: "Asset identity changed; review the link",
    ambiguous: "Ambiguous name; choose an asset",
    no_match: "No exact-name match",
    not_current: "Waiting for a completed, current observation",
    asset_already_linked: "Matching asset is already linked",
    exact_name: "Suggested exact-name match",
  };
  return reasons[row.reason || row.match] || "Not linked";
}

export function suggestedChoices(view: MappingView): MappingChoices {
  if (!view.can_link) return {};
  return Object.fromEntries(view.items.filter(row => row.current && row.state === "unlinked" && row.suggestion)
    .map(row => [row.resource_id, row.suggestion!]));
}

export function mappingApproval(view: MappingView, choices: MappingChoices) {
  if (!view.can_link || !view.scan_id) throw new Error("Refresh after a completed inventory sync.");
  const entries = Object.entries(choices);
  if (!entries.length || entries.length > 1000) throw new Error("Choose between 1 and 1,000 links.");
  if (new Set(entries.map(([, device]) => device.id)).size !== entries.length)
    throw new Error("Each asset can be linked only once in this connection.");
  const items = entries.map(([id, device]) => {
    const row = view.items.find(item => item.resource_id === id);
    if (!row?.current || !device.enabled) throw new Error("A selected resource or asset is no longer available.");
    return {resource_id: id, source_name: row.name, expected_binding_revision: row.binding_revision,
      device_id: device.id, expected_device_revision: device.revision,
      expected_device_identity_revision: device.identity_revision};
  });
  return {expected_revision: view.connection_revision, expected_scan_id: view.scan_id, confirm: true, items};
}
