/** Metadata only. Raw configurations are never tool results or chat content. */
export type BackupReceipt = {backup_id: string; created_at: string; sha256: string; bytes: number};
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;

export function backupReceipt(value: unknown): BackupReceipt | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (Object.keys(row).length !== 4 || typeof row.backup_id !== "string" || !uuid.test(row.backup_id) ||
    typeof row.created_at !== "string" || !timestamp.test(row.created_at) || !Number.isFinite(Date.parse(row.created_at)) ||
    typeof row.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(row.sha256) ||
    typeof row.bytes !== "number" || !Number.isInteger(row.bytes) || row.bytes < 1 || row.bytes > 1_000_000) return null;
  return {backup_id: row.backup_id, created_at: row.created_at, sha256: row.sha256, bytes: row.bytes};
}

export function backupDownloadPath(receipt: BackupReceipt): string {
  if (!backupReceipt(receipt)) throw new Error("Invalid configuration backup receipt");
  return `/capability-studio/configuration-backups/${receipt.backup_id}/download`;
}

type Call = {id: string; investigation_id: string; tool_name?: string; status: string; result: unknown;
  arguments: Record<string, unknown>};
type Evidence = {investigation_id: string; evidence_type: string; evidence_id: string};

/** Display provenance, not download authority: the endpoint rechecks the current human/device scope. */
export function investigationBackups(id: string, calls: Call[], evidence: Evidence[]) {
  const seen = new Set<string>();
  return calls.flatMap(call => {
    if (!uuid.test(id) || !uuid.test(call.id) || call.investigation_id !== id || call.status !== "succeeded" ||
      !call.tool_name?.startsWith("extensions.") || call.tool_name.length > 255 ||
      typeof call.arguments.device_id !== "string" || !uuid.test(call.arguments.device_id)) return [];
    const native = evidence.some(item => {
      const parts = item.evidence_id.split(":");
      return item.investigation_id === id && item.evidence_type === "native_mcp_result" && parts.length === 4 &&
        parts[0] === "extension" && uuid.test(parts[1]) && uuid.test(parts[2]) && parts[3] === call.id;
    });
    const receipt = native ? backupReceipt(call.result) : null;
    if (!receipt || seen.has(receipt.backup_id)) return [];
    seen.add(receipt.backup_id);
    return [{receipt, deviceId: call.arguments.device_id, toolName: call.tool_name, callId: call.id}];
  });
}
