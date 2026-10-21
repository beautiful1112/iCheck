export type Integration = {id: string; name: string; provider: string; api_url: string; group_ids: string[];
  enabled: boolean; revision: number; token_configured: boolean; last_test_status: string | null};
export type IntegrationSync = {id: string; connection_id: string; connection_revision: number; status: string;
  cursor: number; total: number; observed: number; error_code: string | null; can_resume: boolean;
  started_at: string; updated_at: string; finished_at: string | null};
export type ImportedResources = {items: {id: string; remote_id: string; name: string; monitoring_enabled: boolean;
  observed_at: string; last_run_id: string; health: "unknown"}[]; total: number; offset: number; limit: number};

export type IntegrationSchedule = {connection_id: string; revision: number; connection_revision: number;
  enabled: boolean; interval_seconds: number; retention_days: number; next_run_at: string | null;
  active_run_id: string | null; lease_expires_at: string | null; failures: number;
  last_attempt_at: string | null; last_success_at: string | null; last_error: string | null};

export function scheduleLabel(schedule: IntegrationSchedule, now = Date.now()) {
  if (!schedule.enabled) return "Automatic sync is off";
  if (schedule.lease_expires_at && Date.parse(schedule.lease_expires_at) > now) return "Processing a batch";
  if (schedule.next_run_at && Date.parse(schedule.next_run_at) < now - 120_000) return "Overdue · check the synchronization worker";
  if (schedule.last_error) return `Waiting to retry · ${schedule.last_error}`;
  if (schedule.active_run_id) return "Scan in progress · waiting for the next batch";
  return "Automatic sync enabled";
}

export function resumable(run: IntegrationSync | null, connection: Integration | null) {
  return !!run && !!connection && connection.enabled && run.can_resume && run.connection_revision === connection.revision;
}

export function syncLabel(run: IntegrationSync | null) {
  if (!run) return "Not synchronized";
  if (run.status === "completed") return `Scan complete · ${run.observed} observed / ${run.total} source IDs`;
  if (run.status === "superseded") return "Configuration changed · start a new sync";
  if (run.status === "failed") return `Sync stopped · ${run.error_code || "source unavailable"}`;
  return `Sync paused or in progress · ${run.cursor} / ${run.total} source IDs processed`;
}

// One click handles up to 2,500 hosts. More work remains resumable without a
// long-running browser request, unbounded retries or an implicit schedule.
export async function advanceSync(run: IntegrationSync, step: (run: IntegrationSync) => Promise<IntegrationSync>,
  stopped: () => boolean, observed: (run: IntegrationSync) => void): Promise<IntegrationSync> {
  for (let batch = 0; batch < 10 && run.can_resume && !stopped(); batch++) {
    const next = await step(run);
    if (stopped()) return next;
    if (next.id !== run.id || next.connection_revision !== run.connection_revision || next.cursor < run.cursor
      || (next.status === "in_progress" && next.cursor === run.cursor)) throw new Error("Unexpected sync progress; refresh before resuming");
    run = next; observed(run);
    if (run.status === "failed") break;
  }
  return run;
}
