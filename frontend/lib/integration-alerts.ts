export type AlertFeed = {
  connection_id: string; connection_revision: number; revision: number; enabled: boolean;
  interval_seconds: number; phase: string; failures: number; last_error: string | null;
  last_attempt_at: string | null; last_success_at: string | null; next_run_at: string | null;
};
export type ExternalAlert = {
  id: string; source_event_id: string; title: string; source_state: "open" | "resolved";
  suppressed: boolean; acknowledged: boolean; native_severity: string; available: boolean;
  checked_at: string; occurred_at: string; alert_id: string | null; stopped_at: string | null;
  stop_reason: string | null; mapping: string; connection_revision: number;
};
export type ExternalAlerts = {items: ExternalAlert[]; total: number; offset: number; limit: number};
export function externalAlertLabel(row: ExternalAlert) {
  if (!row.available) return "Source status unavailable";
  if (row.source_state === "resolved") return "Resolved at source";
  if (row.suppressed) return "Suppressed at source";
  return row.acknowledged ? "Open · acknowledged" : "Open";
}
export function feedApproval(feed: AlertFeed, revision: number, enabled: boolean, seconds: number) {
  if (!Number.isInteger(seconds) || seconds < 60 || seconds > 3600) throw new Error("Choose an interval from 60 to 3600 seconds.");
  return {expected_revision: revision, expected_feed_revision: feed.revision, confirm: true, enabled, interval_seconds: seconds};
}
