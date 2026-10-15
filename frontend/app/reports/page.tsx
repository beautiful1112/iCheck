"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Clock3,
  Download,
  FileText,
  Loader2,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { apiBlob, apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type ReportSummary = {
  artifact_id: string;
  name: string;
  description: string;
  version_id: string;
  version: number;
  published_at: string;
  content_hash: string;
  report_title: string;
  lookback_minutes: number;
  section_count: number;
};

type ReportSection = {
  section_key: string;
  title: string;
  service_key: string;
  service_name: string | null;
  indicator_key: string;
  indicator_name: string | null;
  kind: string | null;
  unit: string | null;
  state: "ready" | "no_data" | "drifted";
  drift_code: string | null;
  current_status: string;
  current_value: number | null;
  sample_count: number;
  minimum: number | null;
  maximum: number | null;
  average: number | null;
  first_observed_at: string | null;
  last_observed_at: string | null;
  trend: "improving" | "degrading" | "stable" | "insufficient_data";
  warning_threshold: number | null;
  critical_threshold: number | null;
  samples_truncated: boolean;
};

type GeneratedReport = ReportSummary & {
  generated_at: string;
  overall_status: string;
  sample_count: number;
  drifted_section_count: number;
  sections: ReportSection[];
  scope_applied: boolean;
  format_version?: "icheck.service-health-report-render/v2";
  retained_proofs?: Array<{ section_key: string; title: string; reference_kind: string; reference_id: string;
    recorded: Record<string, unknown>; historical: true; grants_future_authority: false }>;
};

type SavedSummary = {
  id: string; version_id: string; version: number; generated_at: string;
  content_sha256: string; snapshot_size_bytes?: number;
  overall_status: string; retention_state: "retained";
};
type SavedReport = SavedSummary & { snapshot: GeneratedReport };
type HistoryPage = { items: SavedSummary[]; next_after_id: string | null };
type ExportFormat = "pdf" | "html" | "csv" | "json";

function signalClass(status: string) {
  if (status === "critical") return "border-red-200 bg-red-50 text-red-700";
  if (status === "warning") return "border-amber-200 bg-amber-50 text-amber-700";
  if (status === "healthy") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  return "border-slate-200 bg-slate-50 text-muted-foreground";
}

function number(value: number | null, unit: string | null) {
  if (value === null) return "—";
  return `${value.toLocaleString(undefined, { maximumFractionDigits: 2 })}${unit ? ` ${unit}` : ""}`;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [generated, setGenerated] = useState<GeneratedReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<SavedReport | null>(null);
  const [history, setHistory] = useState<SavedSummary[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [downloading, setDownloading] = useState<ExportFormat | null>(null);
  const reportRequest = useRef(0);
  const listRequest = useRef(0);
  const historyRequest = useRef(0);
  const captureAttempt = useRef<{ versionId: string; key: string } | null>(null);
  const invalidateRequests = useCallback(() => {
    ++reportRequest.current;
    ++historyRequest.current;
  }, []);

  const selected = useMemo(
    () => reports.find((item) => item.version_id === selectedId) || null,
    [reports, selectedId],
  );

  const load = useCallback(async () => {
    const request = ++listRequest.current;
    setLoading(true);
    try {
      const data = await apiFetch<ReportSummary[]>("/reports");
      if (request !== listRequest.current) return;
      setReports(data);
      if (!data.length) setGenerated(null);
      setSelectedId((current) => data.some((item) => item.version_id === current) ? current : data[0]?.version_id || null);
      setError(null);
    } catch (cause) {
      if (request !== listRequest.current) return;
      setError(cause instanceof Error ? cause.message : "Unable to load reports");
    } finally {
      if (request === listRequest.current) setLoading(false);
    }
  }, []);

  const generate = useCallback(async (report: ReportSummary) => {
    const request = ++reportRequest.current;
    setSaved(null);
    setGenerated(null);
    setGenerating(true);
    try {
      const data = await apiFetch<GeneratedReport>(`/reports/${report.artifact_id}/generate?version=${report.version}`);
      if (request !== reportRequest.current) return;
      setGenerated(data);
      setError(null);
    } catch (cause) {
      if (request !== reportRequest.current) return;
      setGenerated(null);
      setError(cause instanceof Error ? cause.message : "Unable to generate report");
    } finally {
      if (request === reportRequest.current) setGenerating(false);
    }
  }, []);

  const loadHistory = useCallback(async (artifactId: string, afterId?: string) => {
    const request = ++historyRequest.current;
    setHistoryLoading(true);
    try {
      const data = await apiFetch<HistoryPage>(`/reports/${artifactId}/instances?limit=10${afterId ? `&after_id=${encodeURIComponent(afterId)}` : ""}`);
      if (request !== historyRequest.current) return;
      setHistory((current) => afterId ? [...current, ...data.items] : data.items);
      setNextAfter(data.next_after_id);
    } catch (cause) {
      if (request === historyRequest.current) setError(cause instanceof Error ? cause.message : "Unable to load saved reports");
    } finally {
      if (request === historyRequest.current) setHistoryLoading(false);
    }
  }, []);

  const capture = async () => {
    if (!selected) return;
    if (!crypto.randomUUID) {
      setError("Saved reports require HTTPS or localhost for secure request keys");
      return;
    }
    const request = ++reportRequest.current;
    if (captureAttempt.current?.versionId !== selected.version_id) {
      captureAttempt.current = { versionId: selected.version_id, key: crypto.randomUUID() };
    }
    setSaving(true);
    try {
      const data = await apiFetch<SavedReport>(`/reports/${selected.artifact_id}/instances`, {
        method: "POST", body: JSON.stringify({ version_id: selected.version_id, request_key: captureAttempt.current.key }),
      });
      if (request !== reportRequest.current) return;
      captureAttempt.current = null;
      setSaved(data);
      setGenerated(data.snapshot);
      setError(null);
      void loadHistory(selected.artifact_id);
    } catch (cause) {
      if (request === reportRequest.current) setError(cause instanceof Error ? cause.message : "Unable to capture report");
    } finally {
      if (request === reportRequest.current) setSaving(false);
    }
  };

  const openSaved = async (instance: SavedSummary) => {
    const request = ++reportRequest.current;
    setGenerated(null);
    setSaved(null);
    setGenerating(true);
    try {
      const data = await apiFetch<SavedReport>(`/reports/instances/${instance.id}`);
      if (request !== reportRequest.current) return;
      setGenerated(data.snapshot);
      setSaved(data);
      setError(null);
    } catch (cause) {
      if (request === reportRequest.current) setError(cause instanceof Error ? cause.message : "Unable to read saved report");
    } finally {
      if (request === reportRequest.current) setGenerating(false);
    }
  };

  const download = async (format: ExportFormat) => {
    if (!saved) return;
    const request = reportRequest.current;
    const instance = saved;
    setDownloading(format);
    try {
      const data = await apiBlob(`/reports/instances/${instance.id}/export?format=${format}`);
      if (data.snapshotSha256 !== instance.content_sha256) throw new Error("Downloaded snapshot identity does not match");
      if (!crypto.subtle) throw new Error("Verified downloads require HTTPS or localhost");
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", await data.blob.arrayBuffer())))
        .map((byte) => byte.toString(16).padStart(2, "0")).join("");
      if (digest !== data.contentSha256) throw new Error("Downloaded document integrity check failed");
      if (request !== reportRequest.current) return;
      const url = URL.createObjectURL(data.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `icheck-report-${instance.id}.${format}`;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setError(null);
    } catch (cause) {
      if (request === reportRequest.current) setError(cause instanceof Error ? cause.message : "Unable to export report");
    } finally {
      setDownloading(null);
    }
  };

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  useEffect(() => {
    const changed = () => {
      ++listRequest.current; invalidateRequests(); captureAttempt.current = null;
      setReports([]); setSelectedId(null); setGenerated(null); setSaved(null); setHistory([]);
      setNextAfter(null); setError(null); setGenerating(false); setSaving(false); setDownloading(null);
      void load();
    };
    window.addEventListener("icheck:namespace-changed", changed);
    return () => window.removeEventListener("icheck:namespace-changed", changed);
  }, [invalidateRequests, load]);

  useEffect(() => {
    if (!selected) return;
    const timer = window.setTimeout(() => {
      setHistory([]);
      setNextAfter(null);
      setSaving(false);
      void generate(selected);
      void loadHistory(selected.artifact_id);
    }, 0);
    return () => {
      window.clearTimeout(timer);
      invalidateRequests();
    };
  }, [generate, invalidateRequests, loadHistory, selected]);

  return (
    <main className="min-h-screen bg-[#f4f6f8] text-slate-900">
      <header className="flex min-h-16 flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-white px-4 py-3">
        <div className="flex items-center gap-3"><Link href="/" className="rounded-md p-2 text-muted-foreground hover:bg-slate-100" aria-label="Back to AI operator"><ArrowLeft className="size-4" /></Link><span className="grid size-9 place-items-center rounded-xl bg-indigo-600 text-white"><FileText className="size-4" /></span><div><h1 className="text-sm font-semibold">Service health reports</h1><p className="text-xs text-muted-foreground">Governed metrics and retained historical proof · scoped evidence</p></div></div>
        <div className="flex items-center gap-2"><Button asChild variant="outline" size="sm"><Link href="/settings/report-storage">Storage policy</Link></Button><Button asChild variant="outline" size="sm"><Link href="/studio">Author report</Link></Button><Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}><RefreshCw className={cn("size-3.5", loading && "animate-spin")} /> Refresh</Button></div>
      </header>
      {error ? <div className="flex items-center gap-2 border-b border-red-200 bg-red-50 px-5 py-2 text-xs text-red-700"><TriangleAlert className="size-4" />{error}</div> : null}

      <div className="grid min-h-[calc(100vh-64px)] grid-cols-1 md:grid-cols-[280px_minmax(0,1fr)] lg:grid-cols-[320px_minmax(0,1fr)]">
        <aside className="border-r border-slate-200 bg-white p-3">
          <div className="space-y-2">{reports.map((item) => <button key={item.version_id} onClick={() => {
            if (selectedId === item.version_id) return;
            ++reportRequest.current;
            ++historyRequest.current;
            setGenerated(null);
            setSaved(null);
            setHistory([]);
            setNextAfter(null);
            setSelectedId(item.version_id);
          }} className={cn("w-full rounded-xl border p-3 text-left", selectedId === item.version_id ? "border-indigo-300 bg-indigo-50" : "border-slate-100 hover:bg-slate-50")}>
            <div className="flex items-start justify-between gap-2"><p className="text-xs font-semibold">{item.report_title}</p><Badge variant="outline" className="text-[9px]">v{item.version}</Badge></div>
            <p className="mt-2 line-clamp-2 text-[10px] leading-4 text-muted-foreground">{item.description}</p>
            <p className="mt-2 text-[9px] text-muted-foreground">{item.section_count} sections · {item.lookback_minutes}m</p>
          </button>)}</div>
          {!loading && !reports.length ? <div className="py-20 text-center text-xs text-muted-foreground"><FileText className="mx-auto mb-3 size-7 text-slate-300" />No published report is visible in your service scope.</div> : null}
          {selected ? <div className="mt-6 border-t border-slate-200 pt-4">
            <h2 className="px-1 text-xs font-semibold">Saved snapshots</h2>
            <p className="px-1 pt-1 text-[10px] leading-4 text-muted-foreground">Retained without automatic deletion. Current access applies to all historical versions.</p>
            <div className="mt-3 space-y-2">{history.map((item) => <button key={item.id} onClick={() => void openSaved(item)} disabled={saving || generating}
              className={cn("w-full rounded-lg border p-3 text-left disabled:opacity-50", saved?.id === item.id ? "border-indigo-300 bg-indigo-50" : "border-slate-100 hover:bg-slate-50")}>
              <p className="text-[11px] font-medium">{new Date(item.generated_at).toLocaleString()}</p>
              <p className="mt-1 text-[10px] text-muted-foreground">v{item.version} · {item.overall_status} · {item.snapshot_size_bytes === undefined ? "size unavailable" : `${item.snapshot_size_bytes.toLocaleString()} B`} · {item.content_sha256.slice(0, 12)}…</p>
            </button>)}</div>
            {!historyLoading && !history.length ? <p className="px-1 py-4 text-[11px] text-muted-foreground">No saved snapshots yet.</p> : null}
            {historyLoading ? <Loader2 className="mx-auto mt-3 size-4 animate-spin text-indigo-500" /> : null}
            {nextAfter ? <Button className="mt-3 w-full" variant="outline" size="sm" disabled={historyLoading} onClick={() => void loadHistory(selected.artifact_id, nextAfter)}>Load older snapshots</Button> : null}
          </div> : null}
        </aside>

        <section className="min-w-0 p-4 sm:p-6 lg:p-8">
          {selected && generated ? <div className="mx-auto max-w-6xl space-y-5">
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div><div className="flex flex-wrap gap-2"><Badge variant="outline" className={signalClass(generated.overall_status)}>{generated.overall_status}</Badge><Badge variant="outline">{generated.scope_applied ? "Scoped at capture" : "Global at capture"}</Badge><Badge variant="outline">{saved ? `Saved v${generated.version}` : "Live preview"}</Badge></div>
                  <h2 className="mt-3 text-2xl font-semibold">{generated.report_title}</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">{generated.description}</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" size="sm" onClick={() => void generate(selected)} disabled={generating || saving}><RefreshCw className="size-4" /> Live preview</Button>
                  <Button size="sm" onClick={() => void capture()} disabled={generating || saving}>{saving ? <Loader2 className="size-4 animate-spin" /> : <FileText className="size-4" />} Capture saved snapshot</Button>
                </div>
              </div>
              <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 border-t border-slate-100 pt-4 text-[10px] text-muted-foreground"><span className="flex items-center gap-1"><Clock3 className="size-3" />Generated {new Date(generated.generated_at).toLocaleString()}</span><span>{generated.lookback_minutes}m window</span><span>{generated.sample_count} bounded samples</span><span className="font-mono">Artifact sha256 {generated.content_hash.slice(0, 16)}…</span></div>
              <p className="mt-3 text-[11px] leading-5 text-muted-foreground">Capture creates a new immutable snapshot from current evidence using the selected published version. It does not save the previously displayed live preview.</p>
              {saved ? <div className="mt-4 border-t border-slate-100 pt-4">
                <Link href={`/reports/instances/${encodeURIComponent(saved.id)}/retention`} className="text-xs font-medium text-indigo-700 underline underline-offset-2">Retention and legal holds</Link>
                <div className="flex flex-wrap gap-2">{(["pdf", "html", "csv", "json"] as ExportFormat[]).map((format) => <Button key={format} variant="outline" size="sm" disabled={downloading !== null || saving || generating} onClick={() => void download(format)}>{downloading === format ? <Loader2 className="size-3.5 animate-spin" /> : <Download className="size-3.5" />}{format.toUpperCase()}</Button>)}</div>
                <p className="mt-3 break-all font-mono text-[10px] text-muted-foreground">Snapshot sha256 {saved.content_sha256}</p>
                <p className="mt-2 text-[10px] text-muted-foreground">Every export uses these saved values. Downloads recheck current authorization and verify document bytes; exported files are your responsibility.</p>
              </div> : null}
            </div>

            <div className="grid gap-4 lg:grid-cols-2">{generated.sections.map((section) => <article key={section.section_key} className={cn("rounded-2xl border bg-white p-5 shadow-sm", section.state === "drifted" ? "border-red-200" : "border-slate-200")}><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-semibold">{section.title}</p><p className="mt-1 text-[10px] text-muted-foreground">{section.service_name || section.service_key} · {section.indicator_name || section.indicator_key}</p></div><Badge variant="outline" className={signalClass(section.current_status)}>{section.current_status}</Badge></div>{section.state === "drifted" ? <div className="mt-5 rounded-xl bg-red-50 p-4 text-xs text-red-700">Dependency drift: {section.drift_code}</div> : <><div className="mt-5 text-3xl font-semibold">{number(section.current_value, section.unit)}</div><div className="mt-5 grid grid-cols-4 gap-2">{[["Minimum", section.minimum], ["Average", section.average], ["Maximum", section.maximum], ["Samples", section.sample_count]].map(([label, value]) => <div key={String(label)} className="rounded-lg bg-slate-50 p-3"><p className="text-[9px] uppercase tracking-wide text-muted-foreground">{label}</p><p className="mt-1 text-xs font-semibold">{typeof value === "number" ? value.toLocaleString(undefined, { maximumFractionDigits: 2 }) : value}</p></div>)}</div><div className="mt-4 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground"><span className="rounded-md bg-slate-100 px-2 py-1">trend {section.trend}</span><span className="rounded-md bg-slate-100 px-2 py-1">state {section.state}</span>{section.samples_truncated ? <span className="rounded-md bg-amber-50 px-2 py-1 text-amber-700">sample cap applied</span> : null}</div></>}</article>)}</div>

            {generated.retained_proofs?.map((proof) => <article key={proof.section_key} className="min-w-0 rounded-2xl border border-indigo-200 bg-white p-5">
              <div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold">{proof.title}</h3><Badge variant="outline">Historical record</Badge></div>
              <p className="mt-2 break-all font-mono text-[11px] text-muted-foreground">{proof.reference_kind} · {proof.reference_id}</p>
              <p className="mt-3 text-xs leading-5 text-slate-600">Retained control-plane proof, not fresh execution authority. Repair causality and physical truth are not automatically verified. Current and capture-time scope are rechecked when opened or exported.</p>
              <details className="mt-3"><summary className="cursor-pointer text-xs font-medium text-indigo-700">Inspect exact retained record</summary><pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-50 p-3 text-[10px] leading-5">{JSON.stringify(proof.recorded, null, 2)}</pre></details>
            </article>)}
            <div className="rounded-2xl border border-slate-200 bg-white p-5 text-xs text-slate-600"><div className="flex items-center gap-2 font-semibold text-slate-800"><ShieldCheck className="size-4 text-indigo-600" />Immutable provenance and current scope</div><p className="mt-2 leading-5">Version {generated.version} was published {new Date(generated.published_at).toLocaleString()}. {saved ? "This saved snapshot keeps its original time and values; current ownership, snapshot integrity, and exact Artifact provenance are rechecked when opened or exported." : "Preview resolves scoped normalized observations and explicitly selected historical records; it is not retained."} {generated.retained_proofs?.length ? "Proof sections contain explicitly authorized historical source or closure material. They grant no future cutover or closure authority." : "Source queries, observation dimensions, evidence URLs, contacts, components, and actors are omitted."}</p></div>
          </div> : <div className="grid min-h-[540px] place-items-center text-center"><div>{generating ? <Loader2 className="mx-auto size-8 animate-spin text-indigo-500" /> : <CheckCircle2 className="mx-auto size-8 text-slate-300" />}<h2 className="mt-3 text-sm font-semibold">{generating ? "Generating deterministic snapshot" : "Select a published report"}</h2><p className="mt-1 text-xs text-muted-foreground">Reports use governed metrics and exact authorized historical records.</p></div></div>}
        </section>
      </div>
    </main>
  );
}
