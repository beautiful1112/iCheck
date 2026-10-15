"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  FlaskConical,
  Gauge,
  History,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type VersionStatus = "draft" | "validated" | "published" | "deprecated";

type ArtifactVersion = {
  id: string;
  version: number;
  status: VersionStatus;
  content_hash: string | null;
};

type Artifact = {
  id: string;
  name: string;
  kind: string;
  description: string;
  versions: ArtifactVersion[];
};

type ReplayCase = {
  id: string;
  artifact_id: string;
  name: string;
  source_label: string;
  input_count: number;
  expected_count: number;
  input_sha256: string;
  expected_sha256: string;
  configuration_sha256: string;
  created_by: string;
  created_at: string;
};

type ReplayRun = {
  id: string;
  case_id: string;
  artifact_version_id: string;
  status: "passed" | "failed" | "error";
  actual_sha256: string | null;
  mismatch_count: number;
  report: Record<string, unknown>;
  executed_by: string;
  created_at: string;
  finished_at: string;
};

type RevisionSession = {
  id: string;
};

const sampleInput = JSON.stringify(
  [
    {
      kind: "observation",
      type: "device.sample",
      source: "sanitized-lab-capture",
      subject: "sample-device-01",
      payload: { hostname: "sample-device-01", site: "LAB" },
      idempotency_key: "capture-1",
    },
  ],
  null,
  2,
);

const sampleExpected = JSON.stringify(
  [
    {
      kind: "observation",
      type: "device.sample",
      source: "sanitized-lab-capture",
      subject: "sample-device-01",
      payload: {
        hostname: "sample-device-01",
        site: "LAB",
        normalized_site: "LAB",
      },
      idempotency_key: "capture-1",
    },
  ],
  null,
  2,
);

function runClass(status: ReplayRun["status"]) {
  if (status === "passed") return "border-emerald-300 bg-emerald-50 text-emerald-700";
  if (status === "failed") return "border-amber-300 bg-amber-50 text-amber-700";
  return "border-red-300 bg-red-50 text-red-700";
}

function shortHash(value: string | null | undefined) {
  return value ? `${value.slice(0, 12)}…${value.slice(-8)}` : "—";
}

export default function HistoricalReplayPage() {
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [selectedArtifactId, setSelectedArtifactId] = useState<string | null>(null);
  const [cases, setCases] = useState<ReplayCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [runs, setRuns] = useState<ReplayRun[]>([]);
  const [selectedVersionId, setSelectedVersionId] = useState("");
  const [name, setName] = useState("sanitized-lab-baseline");
  const [sourceLabel, setSourceLabel] = useState("sanitized-lab-capture");
  const [configuration, setConfiguration] = useState("{}");
  const [inputEnvelopes, setInputEnvelopes] = useState(sampleInput);
  const [expectedEnvelopes, setExpectedEnvelopes] = useState(sampleExpected);
  const [showCreate, setShowCreate] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedArtifact = useMemo(
    () => artifacts.find((item) => item.id === selectedArtifactId) || null,
    [artifacts, selectedArtifactId],
  );
  const selectedCase = useMemo(
    () => cases.find((item) => item.id === selectedCaseId) || null,
    [cases, selectedCaseId],
  );
  const executableVersions = useMemo(
    () =>
      (selectedArtifact?.versions || [])
        .filter((version) => version.status !== "draft")
        .sort((left, right) => right.version - left.version),
    [selectedArtifact],
  );

  const loadArtifacts = useCallback(async () => {
    try {
      const all = await apiFetch<Artifact[]>("/artifacts?limit=500");
      const collectors = all.filter((artifact) => artifact.kind === "collector");
      setArtifacts(collectors);
      setSelectedArtifactId((current) => current || collectors[0]?.id || null);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load Collector Artifacts");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadCases = useCallback(async (artifactId: string) => {
    try {
      const result = await apiFetch<ReplayCase[]>(
        `/artifact-replay/artifacts/${artifactId}/cases?limit=500`,
      );
      setCases(result);
      setSelectedCaseId((current) =>
        result.some((item) => item.id === current) ? current : result[0]?.id || null,
      );
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load replay cases");
    }
  }, []);

  const loadRuns = useCallback(async (caseId: string) => {
    try {
      const result = await apiFetch<ReplayRun[]>(
        `/artifact-replay/cases/${caseId}/runs?limit=100`,
      );
      setRuns(result);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load replay runs");
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadArtifacts(), 0);
    return () => window.clearTimeout(timer);
  }, [loadArtifacts]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (selectedArtifactId) void loadCases(selectedArtifactId);
      else setCases([]);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadCases, selectedArtifactId]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSelectedVersionId(executableVersions[0]?.id || "");
    }, 0);
    return () => window.clearTimeout(timer);
  }, [executableVersions]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (selectedCaseId) void loadRuns(selectedCaseId);
      else setRuns([]);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadRuns, selectedCaseId]);

  async function createCase(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedArtifactId) return;
    setBusy("create");
    setError(null);
    try {
      const created = await apiFetch<ReplayCase>(
        `/artifact-replay/artifacts/${selectedArtifactId}/cases`,
        {
          method: "POST",
          body: JSON.stringify({
            name: name.trim(),
            source_label: sourceLabel.trim(),
            configuration: JSON.parse(configuration) as Record<string, unknown>,
            input_envelopes: JSON.parse(inputEnvelopes) as unknown[],
            expected_envelopes: JSON.parse(expectedEnvelopes) as unknown[],
            actor: "capability.reviewer",
          }),
        },
      );
      await loadCases(selectedArtifactId);
      setSelectedCaseId(created.id);
      setShowCreate(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to create replay case");
    } finally {
      setBusy(null);
    }
  }

  async function runCase() {
    if (!selectedCaseId || !selectedVersionId) return;
    setBusy("run");
    setError(null);
    try {
      await apiFetch<ReplayRun>(`/artifact-replay/cases/${selectedCaseId}/runs`, {
        method: "POST",
        body: JSON.stringify({
          artifact_version_id: selectedVersionId,
          actor: "capability.reviewer",
        }),
      });
      await loadRuns(selectedCaseId);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to run replay");
    } finally {
      setBusy(null);
    }
  }

  async function reviseRun(run: ReplayRun) {
    setBusy(`revise-${run.id}`);
    setError(null);
    try {
      const session = await apiFetch<RevisionSession>("/capability-studio/sessions/from-runtime", {
        method: "POST",
        body: JSON.stringify({
          source_type: "artifact_replay_run",
          source_id: run.id,
          revision_goal: "Revise this Collector to address the bounded replay failure evidence while preserving its existing data contract and safety controls.",
          route_purpose: "capability.authoring",
          actor: "capability.author",
        }),
      });
      window.location.assign(`/studio?session=${encodeURIComponent(session.id)}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to start a revision session");
      setBusy(null);
    }
  }

  return (
    <main className="flex h-screen min-h-[720px] flex-col overflow-hidden bg-[#eef0f5] text-[#253044]">
      <header className="flex h-16 shrink-0 items-center justify-between border-b border-[#d8dbe0] bg-white px-5">
        <div className="flex items-center gap-3">
          <Link href="/studio/artifacts" className="rounded-md p-2 text-[#59677b] transition hover:bg-[#eef0f5]" aria-label="Back to Artifact Library">
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#303c54] text-white">
            <History className="h-4 w-4" />
          </div>
          <div>
            <h1 className="text-sm font-semibold">Historical Replay</h1>
            <p className="text-xs text-muted-foreground">Sanitized evidence → isolated Collector → golden comparison</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline" size="sm" className="gap-2"><Link href="/studio/rollouts"><Gauge className="h-3.5 w-3.5" /> Rollouts</Link></Button>
          <Button variant="outline" size="sm" className="gap-2" onClick={() => selectedArtifactId && void loadCases(selectedArtifactId)} disabled={loading || !selectedArtifactId}><RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} /> Refresh</Button>
          <Button size="sm" className="gap-2 bg-[#5856d6] hover:bg-[#4947ad]" onClick={() => setShowCreate((current) => !current)} disabled={!selectedArtifactId}>
            <Plus className="h-3.5 w-3.5" /> New replay case
          </Button>
        </div>
      </header>

      {error && (
        <div className="flex shrink-0 items-center gap-2 border-b border-red-200 bg-red-50 px-5 py-2 text-xs text-red-700">
          <XCircle className="h-4 w-4" /> {error}
        </div>
      )}

      <div className="grid min-h-0 flex-1 grid-cols-[280px_390px_minmax(440px,1fr)]">
        <aside className="min-h-0 overflow-y-auto border-r border-[#d8dbe0] bg-[#f8f9fb] p-4">
          <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Collector Artifact</div>
          <select aria-label="Artifact for replay" value={selectedArtifactId || ""} onChange={(event) => setSelectedArtifactId(event.target.value)} className="h-9 w-full rounded-md border border-[#c9ced7] bg-white px-2 text-xs">
            {artifacts.map((artifact) => <option key={artifact.id} value={artifact.id}>{artifact.name}</option>)}
          </select>
          {selectedArtifact && <p className="mt-3 text-[11px] leading-5 text-muted-foreground">{selectedArtifact.description || "No description"}</p>}

          <div className="mb-2 mt-6 flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Golden cases</span>
            <Badge variant="outline" className="text-[9px]">{cases.length}</Badge>
          </div>
          <div className="space-y-2">
            {cases.map((item) => (
              <button key={item.id} onClick={() => setSelectedCaseId(item.id)} className={cn("w-full rounded-lg border p-3 text-left transition", selectedCaseId === item.id ? "border-[#5856d6] bg-white shadow-sm" : "border-transparent hover:border-[#d8dbe0] hover:bg-white")}>
                <div className="truncate text-xs font-semibold">{item.name}</div>
                <div className="mt-1 truncate text-[10px] text-muted-foreground">{item.source_label}</div>
                <div className="mt-2 text-[9px] text-muted-foreground">{item.input_count} input · {item.expected_count} expected</div>
              </button>
            ))}
            {!loading && cases.length === 0 && <div className="rounded-lg border border-dashed border-[#c8cdd5] p-5 text-center text-[11px] leading-5 text-muted-foreground">No sanitized replay cases for this Collector.</div>}
          </div>
        </aside>

        <section className="min-h-0 overflow-y-auto border-r border-[#d8dbe0] bg-white p-5">
          {showCreate ? (
            <form onSubmit={(event) => void createCase(event)}>
              <div className="flex items-center gap-2 text-sm font-semibold"><FlaskConical className="h-4 w-4 text-[#5856d6]" /> New immutable replay case</div>
              <p className="mt-1 text-[11px] leading-5 text-muted-foreground">Use sanitized pre-transform envelopes. Secret-shaped fields are rejected and response metadata exposes hashes, not raw captures.</p>
              <label className="mt-4 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Case name<Input value={name} onChange={(event) => setName(event.target.value)} required className="mt-1 h-9 text-xs normal-case tracking-normal text-[#253044]" /></label>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Source label<Input value={sourceLabel} onChange={(event) => setSourceLabel(event.target.value)} required className="mt-1 h-9 text-xs normal-case tracking-normal text-[#253044]" /></label>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Configuration JSON<Textarea value={configuration} onChange={(event) => setConfiguration(event.target.value)} rows={3} className="mt-1 font-mono text-[10px] normal-case tracking-normal text-[#253044]" /></label>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Input envelope array<Textarea value={inputEnvelopes} onChange={(event) => setInputEnvelopes(event.target.value)} rows={10} className="mt-1 font-mono text-[10px] normal-case tracking-normal text-[#253044]" /></label>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Golden expected array<Textarea value={expectedEnvelopes} onChange={(event) => setExpectedEnvelopes(event.target.value)} rows={10} className="mt-1 font-mono text-[10px] normal-case tracking-normal text-[#253044]" /></label>
              <div className="mt-4 flex gap-2">
                <Button type="submit" size="sm" className="gap-2 bg-[#5856d6] hover:bg-[#4947ad]" disabled={busy !== null || name.trim().length === 0 || sourceLabel.trim().length === 0}>{busy === "create" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />} Store sanitized case</Button>
                <Button type="button" variant="outline" size="sm" onClick={() => setShowCreate(false)}>Cancel</Button>
              </div>
            </form>
          ) : selectedCase ? (
            <>
              <div className="flex items-center justify-between gap-3">
                <div><h2 className="text-base font-semibold">{selectedCase.name}</h2><p className="mt-1 text-xs text-muted-foreground">{selectedCase.source_label}</p></div>
                <Badge variant="outline">immutable</Badge>
              </div>
              <div className="mt-5 space-y-3 rounded-lg border border-[#dfe2e7] bg-[#f8f9fb] p-4 text-[10px]">
                <div><span className="text-muted-foreground">Input</span><code className="mt-1 block break-all text-[#39465a]">{shortHash(selectedCase.input_sha256)}</code></div>
                <div><span className="text-muted-foreground">Expected</span><code className="mt-1 block break-all text-[#39465a]">{shortHash(selectedCase.expected_sha256)}</code></div>
                <div><span className="text-muted-foreground">Configuration</span><code className="mt-1 block break-all text-[#39465a]">{shortHash(selectedCase.configuration_sha256)}</code></div>
              </div>
              <div className="mt-5 rounded-lg border border-[#dfe2e7] p-4">
                <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Version under test<select value={selectedVersionId} onChange={(event) => setSelectedVersionId(event.target.value)} className="mt-1 h-9 w-full rounded-md border border-[#c9ced7] bg-white px-2 text-xs normal-case tracking-normal text-[#253044]">{executableVersions.map((version) => <option key={version.id} value={version.id}>Version {version.version} · {version.status}</option>)}</select></label>
                <Button size="sm" className="mt-3 w-full gap-2 bg-[#5856d6] hover:bg-[#4947ad]" onClick={() => void runCase()} disabled={!selectedVersionId || busy !== null}>{busy === "run" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />} Run isolated replay</Button>
                <p className="mt-2 text-[10px] leading-4 text-muted-foreground">Drafts cannot run. Replay never deploys or promotes a version.</p>
              </div>
            </>
          ) : <div className="flex h-full items-center justify-center text-center text-xs leading-5 text-muted-foreground">Select a replay case or create a sanitized baseline.</div>}
        </section>

        <section className="min-h-0 overflow-y-auto bg-[#f8f9fb] p-5">
          <div className="flex items-center justify-between"><div><h2 className="text-sm font-semibold">Replay evidence</h2><p className="mt-1 text-xs text-muted-foreground">Only bounded hashes, counts, isolation metadata, and mismatch locations are retained here.</p></div><Badge variant="outline">{runs.length} runs</Badge></div>
          <div className="mt-4 space-y-3">
            {runs.map((run) => {
              const version = selectedArtifact?.versions.find((item) => item.id === run.artifact_version_id);
              return (
                <article key={run.id} className="rounded-lg border border-[#dfe2e7] bg-white p-4">
                  <div className="flex items-center justify-between gap-3"><div className="flex items-center gap-2 text-xs font-semibold">{run.status === "passed" ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : <XCircle className="h-4 w-4 text-amber-600" />} Version {version?.version ?? "?"}</div><Badge variant="outline" className={cn("text-[9px]", runClass(run.status))}>{run.status}</Badge></div>
                  <div className="mt-3 grid grid-cols-2 gap-3 text-[10px]"><div><span className="text-muted-foreground">Mismatches</span><div className="mt-1 font-semibold">{run.mismatch_count}</div></div><div><span className="text-muted-foreground">Actual digest</span><code className="mt-1 block">{shortHash(run.actual_sha256)}</code></div></div>
                  <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded bg-[#f4f5f8] p-3 text-[9px] leading-4 text-[#39465a]">{JSON.stringify(run.report, null, 2)}</pre>
                  {run.status !== "passed" && <Button variant="outline" size="sm" className="mt-3 gap-2 border-violet-200 text-violet-700 hover:bg-violet-50" onClick={() => void reviseRun(run)} disabled={busy !== null}>{busy === `revise-${run.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />} Revise in Studio</Button>}
                </article>
              );
            })}
            {selectedCase && runs.length === 0 && <div className="rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs leading-5 text-muted-foreground">No replay evidence yet. Select a validated, published, or deprecated version and run the golden case.</div>}
          </div>
        </section>
      </div>
    </main>
  );
}
