"use client";

import {useState} from "react";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {scheduleLabel, type IntegrationSchedule} from "@/lib/monitoring-integrations";

// Parent keys this form by saved schedule revision, not status refreshes.
export function IntegrationScheduleForm({schedule, busy, canEnable, onSave}: {
  schedule: IntegrationSchedule; busy: boolean; canEnable: boolean;
  onSave: (enabled: boolean, interval: number, retention: number) => void;
}) {
  const [minutes, setMinutes] = useState(schedule.interval_seconds / 60);
  const [retention, setRetention] = useState(schedule.retention_days);
  const date = (value: string | null) => value ? new Date(value).toLocaleString() : "Not yet";
  return <section className="rounded-xl border border-slate-200 bg-white p-5 sm:p-6">
    <h2 className="font-semibold">Automatic synchronization</h2>
    <p role="status" className="mt-2 text-sm">{scheduleLabel(schedule)}</p>
    <p className="mt-2 text-sm text-slate-600">Keep the saved groups synchronized while your browser is closed. This reads source inventory only, not device metrics or alerts.</p>
    <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
      <div><dt className="text-slate-500">Last successful scan</dt><dd>{date(schedule.last_success_at)}</dd></div>
      <div><dt className="text-slate-500">Next batch or scan</dt><dd>{schedule.enabled ? date(schedule.next_run_at) : "Paused"}</dd></div>
      <div><dt className="text-slate-500">Last worker attempt</dt><dd>{date(schedule.last_attempt_at)}</dd></div>
    </dl>
    {schedule.last_error && <p className="mt-3 text-sm text-amber-800">Last error: {schedule.last_error}. Previously imported inventory is retained.</p>}
    <form className="mt-4 space-y-4" onSubmit={event => {event.preventDefault(); onSave(true, minutes * 60, retention);}}>
      <fieldset disabled={busy} className="space-y-4">
        <label className="block max-w-xs text-sm">Sync interval (minutes)
          <Input type="number" min={5} max={1440} step={1} required value={minutes} onChange={event => setMinutes(Number(event.target.value))} /></label>
        <details><summary className="cursor-pointer text-sm">History retention</summary>
          <label className="mt-3 block max-w-xs text-sm">Completed scan manifest retention (days)
            <Input type="number" min={7} max={365} step={1} required value={retention} onChange={event => setRetention(Number(event.target.value))} /></label>
          <p className="mt-2 text-xs text-slate-500">Only old completed/superseded host-ID manifests are compacted. Scan summaries, resumable progress, audits and imported resources remain.</p>
        </details>
        <div className="flex flex-wrap gap-3"><Button type="submit" disabled={!canEnable}>{schedule.enabled ? "Save automatic sync" : "Enable automatic sync"}</Button>
          {schedule.enabled && <Button type="button" variant="outline" onClick={() => onSave(false, schedule.interval_seconds, schedule.retention_days)}>Pause automatic sync</Button>}</div>
      </fieldset>
    </form>
    <p className="mt-3 text-xs text-slate-500">Enabling approves recurring reads of the saved group scope. Transient failures get at most two quick retries, then wait until the next interval. Pausing waits for any in-flight batch to finish. Connection changes pause this schedule.</p>
    {!canEnable && <p className="mt-2 text-sm text-slate-600">Save a nonempty group selection before enabling.</p>}
  </section>;
}
