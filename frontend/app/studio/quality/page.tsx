"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";

type Settings = { enabled: boolean; evidence_mode: "execution_health" | "remediation_outcome"; window_minutes: number; min_samples: number; max_failure_ppm: number; max_p95_ms: number; max_sample_age_seconds: number; evaluation_interval_seconds: number; min_records_per_run: number; alert_on_degradation: boolean };
type Policy = Settings & { id: string; artifact_version_id: string; content_hash: string; revision: number };
type Assessment = { id: string; evidence_scope: string; status: string; reasons: string[]; policy_revision: number; sample_count: number; failed_count: number; failure_ppm: number | null; p95_ms: number | null; evaluated_at: string; valid_until: string; assessment_sha256: string; scan_truncated: boolean };
type State = { as_of: string; policy: Policy; latest_assessment: Assessment | null; state: string; current: boolean; deadline_ms?: number };
type Version = { artifact_version_id: string; name: string; kind: string; version: number; content_hash: string };
const defaults: Settings = { enabled: true, evidence_mode: "execution_health", window_minutes: 60, min_samples: 5, max_failure_ppm: 100000, max_p95_ms: 30000, max_sample_age_seconds: 900, evaluation_interval_seconds: 60, min_records_per_run: 0, alert_on_degradation: true };
const numericFields: Array<{ key: keyof Settings; label: string; min: number; max: number }> = [
  { key: "window_minutes", label: "Evidence window (minutes)", min: 5, max: 10080 },
  { key: "min_samples", label: "Minimum evidence samples", min: 1, max: 2000 },
  { key: "max_failure_ppm", label: "Maximum failures per million samples", min: 0, max: 1000000 },
  { key: "max_p95_ms", label: "Maximum p95 duration (milliseconds)", min: 1, max: 3600000 },
  { key: "max_sample_age_seconds", label: "Maximum terminal-sample age (seconds)", min: 60, max: 604800 },
  { key: "evaluation_interval_seconds", label: "Continuous evaluation interval (seconds)", min: 60, max: 86400 },
  { key: "min_records_per_run", label: "Minimum records per Collector run", min: 0, max: 1000000 },
];

export default function CapabilityQualityPage() {
  const [states, setStates] = useState<State[]>([]);
  const [versions, setVersions] = useState<Version[]>([]);
  const [versionId, setVersionId] = useState("");
  const [settings, setSettings] = useState<Settings>({ ...defaults });
  const [editing, setEditing] = useState<Policy | null>(null);
  const [reason, setReason] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [history, setHistory] = useState<Assessment[]>([]);
  const [historyPolicy, setHistoryPolicy] = useState<string | null>(null);
  const [catalogTruncated, setCatalogTruncated] = useState(false);
  const [now, setNow] = useState(0);
  const generation = useRef(0);
  const mutation = useRef(0);
  const historyGeneration = useRef(0);

  const load = useCallback(async () => {
    const current = ++generation.current;
    const requestedAt = performance.now();
    setLoading(true); setError(null);
    try {
      const [policies, catalog] = await Promise.all([
        apiFetch<State[]>(`/capability-quality/policies?offset=${offset}&limit=50`),
        apiFetch<{ items: Version[]; truncated: boolean; scan_truncated: boolean }>("/capability-catalog?limit=500"),
      ]);
      if (current !== generation.current) return;
      const supported = catalog.items.filter((item) => ["collector", "tool", "skill", "workflow"].includes(item.kind));
      const receivedAt = performance.now();
      // Use request start conservatively: slow responses or Catalog loading
      // must never extend the server's validity window after receipt.
      setNow(receivedAt);
      setStates(policies.map((item) => ({ ...item, deadline_ms: item.latest_assessment ? requestedAt + Math.max(0, Date.parse(item.latest_assessment.valid_until) - Date.parse(item.as_of)) : 0 })));
      setVersions(supported); setCatalogTruncated(catalog.truncated || catalog.scan_truncated);
      setVersionId((prior) => supported.some((item) => item.artifact_version_id === prior) ? prior : supported[0]?.artifact_version_id ?? "");
    } catch (caught) {
      if (current === generation.current) { setStates([]); setVersions([]); setError(caught instanceof Error ? caught.message : "Unable to read capability quality."); }
    } finally { if (current === generation.current) setLoading(false); }
  }, [offset]);

  useEffect(() => {
    // Expire cached health using a server-relative monotonic deadline, even
    // without another fetch and without trusting the browser's wall clock.
    const timer = window.setInterval(() => setNow(performance.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => { void load(); }, 0);
    const currentGeneration = generation;
    const currentHistoryGeneration = historyGeneration;
    const onNamespace = () => {
      ++generation.current; ++mutation.current; ++historyGeneration.current;
      setStates([]); setVersions([]); setVersionId(""); setEditing(null); setSettings({ ...defaults });
      setReason(""); setHistory([]); setHistoryPolicy(null); setNotice(null); setBusy(false);
      if (offset) setOffset(0); else void load();
    };
    window.addEventListener("icheck:namespace-changed", onNamespace);
    return () => { ++currentGeneration.current; ++currentHistoryGeneration.current; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", onNamespace); };
  }, [load, offset]);

  function edit(policy: Policy) {
    setEditing(policy); setVersionId(policy.artifact_version_id);
    setSettings(Object.fromEntries(Object.keys(defaults).map((key) => [key, policy[key as keyof Settings]])) as Settings);
    setNotice(null);
  }

  async function run(path: string, method: string, body: Record<string, unknown>, label: string) {
    if (busy) return;
    if (reason.trim().length < 10 || reason.length > 512) { setError("Provide a reason of 10–512 characters."); return; }
    const current = generation.current; const action = ++mutation.current;
    setBusy(true); setError(null); setNotice(null);
    try {
      await apiFetch(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...body, reason: reason.trim() }) });
      if (current !== generation.current) return;
      setNotice(`${label} completed. No automation permission was granted.`);
      setReason(""); setEditing(null); setSettings({ ...defaults });
      ++historyGeneration.current; setHistory([]); setHistoryPolicy(null);
      await load();
    } catch (caught) { if (current === generation.current) setError(caught instanceof Error ? caught.message : `${label} failed.`); }
    finally { if (action === mutation.current) setBusy(false); }
  }

  async function readHistory(policyId: string) {
    const current = generation.current; const request = ++historyGeneration.current;
    setHistory([]); setHistoryPolicy(policyId); setError(null);
    try {
      const rows = await apiFetch<Assessment[]>(`/capability-quality/policies/${encodeURIComponent(policyId)}/assessments?limit=20`);
      if (current === generation.current && request === historyGeneration.current) setHistory(rows);
    } catch (caught) { if (current === generation.current && request === historyGeneration.current) setError(caught instanceof Error ? caught.message : "Unable to read assessments."); }
  }

  const selected = versions.find((item) => item.artifact_version_id === versionId);
  const title = (id: string) => { const version = versions.find((item) => item.artifact_version_id === id); return version ? `${version.name} · ${version.kind} v${version.version}` : id; };
  const scopeLabel = (scope: string) => scope === "remediation_outcome_not_authority" ? "Remediation outcome (Tool observations, no authority)" : scope === "execution_health_not_correctness" ? "Execution health (not correctness)" : "Evidence scope unavailable";
  return <main className="min-h-screen bg-[#f4f6f8] text-slate-900">
    <header className="flex items-center justify-between border-b border-slate-200 bg-white px-5 py-3"><div className="flex items-center gap-3"><Link href="/studio/catalog" aria-label="Back to capability catalog"><ArrowLeft className="size-4" /></Link><div><h1 className="text-sm font-semibold">Capability quality</h1><p className="text-xs text-muted-foreground">Execution health and causal remediation outcomes</p></div></div><Button variant="outline" size="sm" disabled={loading || busy} onClick={() => void load()}><RefreshCw className="size-4" />Refresh</Button></header>
    <div className="mx-auto max-w-5xl space-y-5 p-5 lg:p-8">
      <p className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">Healthy execution is not proof of correctness, successful remediation or permission for unattended changes. Quality policies never publish, activate, execute or approve an Artifact.</p>
      <p className="text-xs text-slate-600">Remediation outcomes verify causal post-checks after separately approved actions. Tool contracts may also require a typed before-and-after state transition; legacy Tools retain a boolean-only basis. A successful rollback is restoration, not success of the original purpose. These observations do not independently prove vendor truth or grant automation authority.</p>
      {error ? <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p> : null}
      {notice ? <p role="status" className="rounded-lg bg-emerald-50 p-3 text-sm text-emerald-700">{notice}</p> : null}
      <Card><CardHeader><CardTitle className="text-base">{editing ? "Revise quality policy" : "Configure continuous evaluation"}</CardTitle><CardDescription>Requires namespace-wide capabilities.manage. Version and content bindings are immutable; upgrades need their own policy and new evidence.</CardDescription></CardHeader><CardContent className="space-y-4 text-xs">
        {editing ? <p className="break-all font-mono">{title(editing.artifact_version_id)} · revision {editing.revision} · {editing.content_hash}</p> : <label className="block font-medium">Published capability version<select className="mt-1 block h-9 w-full rounded-md border border-slate-200 bg-white px-3" value={versionId} disabled={busy || loading} onChange={(event) => setVersionId(event.target.value)}><option value="">Select published version</option>{versions.map((item) => <option key={item.artifact_version_id} value={item.artifact_version_id}>{item.name} · {item.kind} v{item.version}</option>)}</select></label>}
        {catalogTruncated ? <p className="text-amber-800">The Catalog scan is truncated. This selector is not a complete fleet listing.</p> : null}
        <label className="block font-medium">Evidence basis<select className="mt-1 block h-9 w-full rounded-md border border-slate-200 bg-white px-3" value={settings.evidence_mode} disabled={busy} onChange={(event) => setSettings((prior) => ({ ...prior, evidence_mode: event.target.value as Settings["evidence_mode"], min_samples: event.target.value === "remediation_outcome" ? Math.min(prior.min_samples, 200) : prior.min_samples }))}><option value="execution_health">Execution health (not correctness)</option><option value="remediation_outcome">Remediation outcomes (governed change Tools only)</option></select></label>
        <p className="text-muted-foreground">One revisioned policy per version. Switching evidence basis invalidates current assessments; history keeps its original evidence scope. Outcome scans are bounded to 200 actions and include failed purpose and rollback outcomes.</p>
        <div className="grid gap-3 sm:grid-cols-2">{numericFields.map(({ key, label, min, max }) => <label key={key} className="block font-medium">{label}<Input className="mt-1" type="number" min={min} max={key === "min_samples" && settings.evidence_mode === "remediation_outcome" ? 200 : max} step={1} disabled={busy} value={String(settings[key])} onChange={(event) => setSettings((prior) => ({ ...prior, [key]: Number(event.target.value) }))} /></label>)}</div>
        <p className="text-muted-foreground">100,000 failures per million = 10%. p95 uses nearest-rank duration. Initial dispatch/approval waiting is excluded. Outcome duration includes verification, restoration and any rollback approval wait; overdue work fails the configured duration gate.</p>
        <div className="flex flex-wrap gap-5"><label className="flex items-center gap-2"><input type="checkbox" checked={settings.enabled} disabled={busy} onChange={(event) => setSettings((prior) => ({ ...prior, enabled: event.target.checked }))} />Evaluation enabled</label><label className="flex items-center gap-2"><input type="checkbox" checked={settings.alert_on_degradation} disabled={busy} onChange={(event) => setSettings((prior) => ({ ...prior, alert_on_degradation: event.target.checked }))} />Alert on degradation</label></div>
        <label className="block font-medium">Reason for the next action<Input className="mt-1" value={reason} maxLength={512} disabled={busy} onChange={(event) => setReason(event.target.value)} placeholder="10–512 characters" /></label>
        <div className="flex gap-3"><Button variant="outline" disabled={busy || loading || (!editing && !selected)} onClick={() => void run(editing ? `/capability-quality/policies/${editing.id}` : "/capability-quality/policies", editing ? "PUT" : "POST", editing ? { ...settings, expected_revision: editing.revision } : { ...settings, artifact_version_id: versionId, expected_content_hash: selected?.content_hash }, editing ? "Policy revision" : "Policy creation")}>{editing ? "Save revision" : "Create quality policy"}</Button>{editing ? <Button variant="ghost" disabled={busy} onClick={() => { setEditing(null); setSettings({ ...defaults }); }}>Cancel edit</Button> : null}</div>
      </CardContent></Card>
      <Card><CardHeader><CardTitle className="text-base">Current assessments</CardTitle><CardDescription>Expired, insufficient and revision-drifted assessments never claim current health. A stopped controller cannot keep assessments fresh.</CardDescription></CardHeader><CardContent className="space-y-3 text-xs">
        {loading ? <p>Loading quality policies…</p> : !states.length ? <p className="text-muted-foreground">No quality policies on this page.</p> : states.map(({ policy, latest_assessment: assessment, state, current, deadline_ms }) => {
          const fresh = current && !!assessment && Number.isFinite(deadline_ms) && now < (deadline_ms ?? 0);
          const displayState = state === "disabled" ? "disabled" : current && !fresh ? "expired" : state;
          return <section key={policy.id} className="space-y-2 rounded-lg border border-slate-200 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2"><p className="font-medium">{title(policy.artifact_version_id)}</p><span className={displayState === "healthy" && fresh ? "text-emerald-700" : "text-amber-800"}>{displayState.replaceAll("_", " ")}</span></div>
            <p>Policy revision {policy.revision} · {policy.enabled ? "evaluation enabled" : "evaluation disabled"} · {policy.evidence_mode === "remediation_outcome" ? "remediation outcomes" : "execution health"}</p>
            {assessment ? <><p>{scopeLabel(assessment.evidence_scope)}</p><p>{assessment.sample_count} samples · {assessment.failed_count} failed · p95 {assessment.p95_ms ?? "unknown"} ms · assessed {new Date(assessment.evaluated_at).toLocaleString()}</p><p>Reasons: {assessment.reasons.length ? assessment.reasons.join(", ") : "none at observation time"}</p><p className="break-all font-mono text-[10px]">{assessment.assessment_sha256}</p></> : <p>No assessment recorded. Configure the regional quality controller or evaluate manually.</p>}
            <div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" disabled={busy} onClick={() => edit(policy)}>Edit policy</Button><Button variant="outline" size="sm" disabled={busy} onClick={() => void run(`/capability-quality/policies/${policy.id}/evaluate`, "POST", {}, "Evidence evaluation")}>Evaluate now</Button><Button variant="ghost" size="sm" disabled={busy} onClick={() => void readHistory(policy.id)}>Assessment history</Button></div>
          </section>;
        })}
        <div className="flex items-center justify-between"><Button variant="outline" size="sm" disabled={busy || loading || offset === 0} onClick={() => { setOffset(Math.max(0, offset - 50)); setHistory([]); setHistoryPolicy(null); setEditing(null); }}>Previous</Button><span>{states.length ? `Policies ${offset + 1}–${offset + states.length}` : "No policies"}</span><Button variant="outline" size="sm" disabled={busy || loading || states.length < 50} onClick={() => { setOffset(offset + 50); setHistory([]); setHistoryPolicy(null); setEditing(null); }}>Next</Button></div>
      </CardContent></Card>
      {historyPolicy ? <Card><CardHeader><CardTitle className="text-base">Assessment history</CardTitle><CardDescription>{title(states.find((item) => item.policy.id === historyPolicy)?.policy.artifact_version_id ?? historyPolicy)} · latest 20 immutable observations</CardDescription></CardHeader><CardContent className="space-y-3 text-xs">{history.map((item) => <div key={item.id} className="space-y-1 rounded-lg border border-slate-200 p-3"><p>{item.status.replaceAll("_", " ")} · policy revision {item.policy_revision} · {new Date(item.evaluated_at).toLocaleString()}</p><p>{scopeLabel(item.evidence_scope)}</p><p>{item.sample_count} samples, {item.failed_count} failures. Valid until {new Date(item.valid_until).toLocaleString()}.</p><p>{item.reasons.join(", ") || "No failed gates at that observation time."}</p><p className="break-all font-mono text-[10px]">{item.assessment_sha256}</p></div>)}{!history.length ? <p>No assessment history loaded.</p> : null}</CardContent></Card> : null}
    </div>
  </main>;
}
