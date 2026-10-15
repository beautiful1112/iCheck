"use client";

import Link from "next/link";
import { ChangeEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Download,
  FileDiff,
  FileUp,
  Gauge,
  History,
  LibraryBig,
  Loader2,
  RefreshCw,
  Rocket,
  RotateCcw,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";
import {legacyKind, validReference} from "@/lib/studio-builder";

type VersionStatus = "draft" | "validated" | "published" | "deprecated";

type ArtifactVersion = {
  id: string;
  version: number;
  status: VersionStatus;
  content_hash: string | null;
  validation_report: Record<string, unknown>;
  created_by: string;
  created_at: string;
  published_by: string | null;
};

type Artifact = {
  id: string;
  name: string;
  kind: string;
  description: string;
  owner: string;
  labels: Record<string, unknown>;
  updated_at: string;
  versions: ArtifactVersion[];
};

type SemanticChange = {
  path: string;
  change_type: "added" | "removed" | "changed";
  before: unknown;
  after: unknown;
};

type VersionDiff = {
  artifact_id: string;
  from_version: number;
  to_version: number;
  change_count: number;
  truncated: boolean;
  changes: SemanticChange[];
};

function statusClass(status: VersionStatus) {
  if (status === "published") return "border-emerald-300 bg-emerald-50 text-emerald-700";
  if (status === "validated") return "border-cyan-300 bg-cyan-50 text-cyan-700";
  if (status === "deprecated") return "border-amber-300 bg-amber-50 text-amber-700";
  return "border-slate-300 bg-slate-50 text-slate-600";
}

function compactValue(value: unknown) {
  if (value === undefined || value === null) return "—";
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

export default function ArtifactLibraryPage() {
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedVersion, setSelectedVersion] = useState<number | null>(null);
  const [fromVersion, setFromVersion] = useState<number | null>(null);
  const [toVersion, setToVersion] = useState<number | null>(null);
  const [diff, setDiff] = useState<VersionDiff | null>(null);
  const [restoreReason, setRestoreReason] = useState("");
  const [importBundle, setImportBundle] = useState<Record<string, unknown> | null>(null);
  const [importFilename, setImportFilename] = useState("");
  const [importName, setImportName] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const epoch = useRef(0);

  const load = useCallback(async () => {
    const context = epoch.current;
    try {
      const data = await apiFetch<Artifact[]>("/artifacts?limit=500");
      if (context !== epoch.current) return;
      setArtifacts(data);
      const requested = new URLSearchParams(window.location.search).get("artifact");
      setSelectedId((current) => validReference(requested) && data.some(row => row.id === requested) ? requested : current || data[0]?.id || null);
      setError(null);
    } catch (cause) {
      if (context === epoch.current) setError(cause instanceof Error ? cause.message : "Unable to load Artifacts");
    } finally {
      if (context === epoch.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const context = epoch;
    const reset = () => {context.current++; setArtifacts([]); setSelectedId(null); setSelectedVersion(null); setFromVersion(null); setToVersion(null); setDiff(null); setRestoreReason(""); setImportBundle(null); setImportFilename(""); setImportName(""); setBusy(null); setError(null); setLoading(true); void load();};
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    const timer = window.setTimeout(() => void load(), 0);
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => {context.current++; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage);};
  }, [load]);

  const selected = useMemo(
    () => artifacts.find((artifact) => artifact.id === selectedId) || null,
    [artifacts, selectedId],
  );

  useEffect(() => {
    if (!selected) return;
    const timer = window.setTimeout(() => {
      const versions = [...selected.versions].sort(
        (left, right) => left.version - right.version,
      );
      const latest = versions.at(-1)?.version || null;
      const previous = versions.at(-2)?.version || latest;
      setSelectedVersion(latest);
      setFromVersion(previous);
      setToVersion(latest);
      setDiff(null);
      setRestoreReason("");
    }, 0);
    return () => window.clearTimeout(timer);
  }, [selected]);

  async function compareVersions() {
    if (!selected || fromVersion === null || toVersion === null) return;
    setBusy("diff");
    setError(null);
    try {
      const result = await apiFetch<VersionDiff>(
        `/artifacts/${selected.id}/diff?from_version=${fromVersion}&to_version=${toVersion}&limit=300`,
      );
      setDiff(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to compare versions");
    } finally {
      setBusy(null);
    }
  }

  async function exportVersion() {
    const version = selected?.versions.find((item) => item.version === selectedVersion);
    if (!selected || !version) return;
    setBusy("export");
    setError(null);
    try {
      const bundle = await apiFetch<Record<string, unknown>>(
        `/artifact-versions/${version.id}/export`,
      );
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${selected.name}-v${version.version}.icheck.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to export version");
    } finally {
      setBusy(null);
    }
  }

  async function loadImportFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setError(null);
    try {
      const document = JSON.parse(await file.text()) as Record<string, unknown>;
      setImportBundle(document);
      setImportFilename(file.name);
    } catch {
      setImportBundle(null);
      setImportFilename("");
      setError("The selected file is not a valid JSON Artifact bundle");
    }
  }

  async function importArtifact() {
    if (!importBundle) return;
    setBusy("import");
    setError(null);
    try {
      const signed = importBundle.format_version === "icheck.artifact.signed-bundle/v1";
      const imported = await apiFetch<Artifact>(signed ? "/artifact-signed-imports" : "/artifact-imports", {
        method: "POST",
        body: JSON.stringify({
          [signed ? "signed_bundle" : "bundle"]: importBundle,
          name_override: importName.trim() || null,
          created_by: "capability.importer",
        }),
      });
      setImportBundle(null);
      setImportFilename("");
      setImportName("");
      await load();
      setSelectedId(imported.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to import Artifact");
    } finally {
      setBusy(null);
    }
  }

  async function createRestore() {
    if (!selected || legacyKind(selected.kind) || selectedVersion === null || restoreReason.trim().length < 3) return;
    setBusy("restore");
    setError(null);
    try {
      await apiFetch(`/artifacts/${selected.id}/restore-candidates`, {
        method: "POST",
        body: JSON.stringify({
          source_version: selectedVersion,
          reason: restoreReason.trim(),
          actor: "capability.operator",
        }),
      });
      await load();
      setRestoreReason("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to create restore candidate");
    } finally {
      setBusy(null);
    }
  }

  async function publishVersion() {
    const version = selected?.versions.find((item) => item.version === selectedVersion);
    if (!version || legacyKind(selected?.kind || "") || version.status !== "validated") return;
    setBusy("publish");
    setError(null);
    try {
      await apiFetch(`/artifact-versions/${version.id}/publish`, {
        method: "POST",
        body: JSON.stringify({ actor: "capability.publisher" }),
      });
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to publish version");
    } finally {
      setBusy(null);
    }
  }

  const activeVersion = selected?.versions.find((item) => item.version === selectedVersion) || null;

  return (
    <main className="flex h-screen min-h-[720px] flex-col overflow-hidden bg-[#eef0f5] text-[#253044]">
      <header className="flex h-16 shrink-0 items-center justify-between border-b border-[#d8dbe0] bg-white px-5">
        <div className="flex items-center gap-3">
          <Link href="/studio" className="rounded-md p-2 text-[#59677b] transition hover:bg-[#eef0f5]" aria-label="Back to Capability Studio">
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#303c54] text-white">
            <LibraryBig className="h-4 w-4" />
          </div>
          <div>
            <h1 className="text-sm font-semibold">Artifact Library</h1>
            <p className="text-xs text-muted-foreground">Compare · transfer · revalidate · restore · publish</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/replay">
              <History className="h-3.5 w-3.5" /> Historical replay
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/catalog">
              <LibraryBig className="h-3.5 w-3.5" /> Runtime catalog
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/workflows">
              <ShieldCheck className="h-3.5 w-3.5" /> Workflows
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/rollouts">
              <Gauge className="h-3.5 w-3.5" /> Canary rollouts
            </Link>
          </Button>
          <Button variant="outline" size="sm" className="gap-2" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} /> Refresh
          </Button>
        </div>
      </header>

      {error && (
        <div className="flex shrink-0 items-center gap-2 border-b border-red-200 bg-red-50 px-5 py-2 text-xs text-red-700">
          <XCircle className="h-4 w-4" /> {error}
        </div>
      )}

      <div className="grid min-h-0 flex-1 grid-cols-[290px_390px_minmax(420px,1fr)]">
        <aside className="min-h-0 overflow-y-auto border-r border-[#d8dbe0] bg-[#f8f9fb] p-3">
          <div className="mb-3 px-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Published knowledge and drafts</div>
          <div className="space-y-1.5">
            {artifacts.map((artifact) => {
              const published = artifact.versions.find((version) => version.status === "published");
              return (
                <button key={artifact.id} onClick={() => setSelectedId(artifact.id)} className={cn("w-full rounded-lg border px-3 py-3 text-left transition", selectedId === artifact.id ? "border-[#5856d6]/30 bg-white shadow-sm" : "border-transparent hover:border-[#d8dbe0] hover:bg-white")}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-xs font-semibold">{artifact.name}</span>
                    <div className="flex items-center gap-1">
                      {artifact.labels.signature_verified === true ? <Badge variant="outline" className="border-emerald-300 bg-emerald-50 text-[9px] text-emerald-700">signed</Badge> : null}
                      <Badge variant="outline" className="text-[9px]">{artifact.kind}</Badge>
                    </div>
                  </div>
                  <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground">
                    <span>{artifact.versions.length} version{artifact.versions.length === 1 ? "" : "s"}</span>
                    <span>{published ? `v${published.version} saved template` : "not published"}</span>
                  </div>
                </button>
              );
            })}
          </div>

          <div className="mt-5 rounded-lg border border-dashed border-[#bfc5ce] bg-white p-3">
            <div className="flex items-center gap-2 text-xs font-semibold"><FileUp className="h-3.5 w-3.5 text-[#5856d6]" /> Import validated bundle</div>
            <p className="mt-1 text-[10px] leading-4 text-muted-foreground">Unsigned bundles verify digest/content hash. Signed envelopes also require a trusted Ed25519 key before target revalidation.</p>
            <Input aria-label="Import Artifact JSON file" type="file" accept="application/json,.json" onChange={(event) => void loadImportFile(event)} className="mt-3 h-8 text-[10px]" />
            {importFilename && <p className="mt-2 truncate text-[10px] text-[#4947ad]">{importFilename}</p>}
            <Input value={importName} onChange={(event) => setImportName(event.target.value)} placeholder="Optional target name" className="mt-2 h-8 text-xs" />
            <Button size="sm" className="mt-2 w-full gap-2 bg-[#5856d6] hover:bg-[#4947ad]" disabled={!importBundle || busy !== null} onClick={() => void importArtifact()}>
              {busy === "import" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />} Verify and import
            </Button>
          </div>
        </aside>

        <section className="min-h-0 overflow-y-auto border-r border-[#d8dbe0] bg-white p-5">
          {selected ? (
            <>
              <div>
                <div className="flex items-center gap-2"><h2 className="text-base font-semibold">{selected.name}</h2><Badge variant="outline">{selected.kind}</Badge></div>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">{selected.description || "No description"}</p>
              </div>
              <div className="mt-5 space-y-2">
                {selected.versions.map((version) => (
                  <button key={version.id} onClick={() => setSelectedVersion(version.version)} className={cn("w-full rounded-lg border p-3 text-left", selectedVersion === version.version ? "border-[#5856d6] bg-[#f4f3ff]" : "border-[#dfe2e7] hover:bg-[#f8f9fb]")}>
                    <div className="flex items-center justify-between"><span className="text-xs font-semibold">Version {version.version}</span><Badge variant="outline" className={cn("text-[9px]", statusClass(version.status))}>{version.status}</Badge></div>
                    <div className="mt-2 break-all font-mono text-[9px] text-muted-foreground">{version.content_hash || "not validated"}</div>
                  </button>
                ))}
              </div>

              {activeVersion && (
                <div className="mt-5 rounded-lg border border-[#dfe2e7] bg-[#f8f9fb] p-4">
                  <div className="mb-3 flex items-center gap-2 text-xs font-semibold"><ShieldCheck className="h-4 w-4 text-[#5856d6]" /> Version actions</div>
                  <div className="grid grid-cols-2 gap-2">
                    <Button variant="outline" size="sm" className="gap-2" onClick={() => void exportVersion()} disabled={!activeVersion.content_hash || busy !== null}><Download className="h-3.5 w-3.5" /> Export</Button>
                    <Button size="sm" className="gap-2 bg-emerald-600 hover:bg-emerald-700" onClick={() => void publishVersion()} disabled={legacyKind(selected.kind) || activeVersion.status !== "validated" || busy !== null}><Rocket className="h-3.5 w-3.5" /> Publish</Button>
                  </div>
                  <Textarea value={restoreReason} onChange={(event) => setRestoreReason(event.target.value)} rows={3} placeholder="Why should this version be restored?" className="mt-3 text-xs" />
                  <Button variant="outline" size="sm" className="mt-2 w-full gap-2" onClick={() => void createRestore()} disabled={legacyKind(selected.kind) || !activeVersion.content_hash || restoreReason.trim().length < 3 || busy !== null}>
                    {busy === "restore" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />} Create revalidated restore candidate
                  </Button>
                  <p className="mt-2 text-[10px] leading-4 text-muted-foreground">Restore creates a new validated version. It never replaces the published version until a separate publish action.</p>
                </div>
              )}
            </>
          ) : <div className="flex h-full items-center justify-center text-sm text-muted-foreground">No Artifacts yet</div>}
        </section>

        <section className="min-h-0 overflow-y-auto bg-[#f8f9fb] p-5">
          <div className="flex items-center justify-between gap-3">
            <div><div className="flex items-center gap-2 text-sm font-semibold"><FileDiff className="h-4 w-4 text-[#5856d6]" /> Semantic diff</div><p className="mt-1 text-xs text-muted-foreground">Named graph nodes and fixtures are compared by identity; large values become hashes.</p></div>
            <Button size="sm" className="gap-2 bg-[#5856d6] hover:bg-[#4947ad]" onClick={() => void compareVersions()} disabled={!selected || fromVersion === null || toVersion === null || busy !== null}>{busy === "diff" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileDiff className="h-3.5 w-3.5" />} Compare</Button>
          </div>
          {selected && (
            <div className="mt-4 grid grid-cols-2 gap-3">
              <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">From<select value={fromVersion ?? ""} onChange={(event) => { setFromVersion(Number(event.target.value)); setDiff(null); }} className="mt-1 h-9 w-full rounded-md border border-[#c9ced7] bg-white px-2 text-xs normal-case tracking-normal text-[#253044]">{selected.versions.map((version) => <option key={version.id} value={version.version}>Version {version.version} · {version.status}</option>)}</select></label>
              <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">To<select value={toVersion ?? ""} onChange={(event) => { setToVersion(Number(event.target.value)); setDiff(null); }} className="mt-1 h-9 w-full rounded-md border border-[#c9ced7] bg-white px-2 text-xs normal-case tracking-normal text-[#253044]">{selected.versions.map((version) => <option key={version.id} value={version.version}>Version {version.version} · {version.status}</option>)}</select></label>
            </div>
          )}
          {diff ? (
            <div className="mt-5">
              <div className="mb-3 flex items-center justify-between text-xs"><span>{diff.change_count} bounded change{diff.change_count === 1 ? "" : "s"}</span>{diff.truncated ? <Badge className="bg-amber-100 text-amber-700">truncated</Badge> : <span className="flex items-center gap-1 text-emerald-700"><CheckCircle2 className="h-3.5 w-3.5" /> complete</span>}</div>
              <div className="space-y-2">{diff.changes.map((change, index) => <div key={`${change.path}-${index}`} className="rounded-lg border border-[#dfe2e7] bg-white p-3"><div className="flex items-start justify-between gap-3"><code className="break-all text-[10px] font-semibold text-[#39465a]">{change.path}</code><Badge variant="outline" className={cn("shrink-0 text-[9px]", change.change_type === "added" ? "border-emerald-300 text-emerald-700" : change.change_type === "removed" ? "border-red-300 text-red-700" : "border-amber-300 text-amber-700")}>{change.change_type}</Badge></div>{change.change_type !== "added" && <pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap break-words rounded bg-red-50 p-2 text-[9px] leading-4 text-red-800">{compactValue(change.before)}</pre>}{change.change_type !== "removed" && <pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap break-words rounded bg-emerald-50 p-2 text-[9px] leading-4 text-emerald-800">{compactValue(change.after)}</pre>}</div>)}</div>
            </div>
          ) : <div className="mt-10 rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs leading-5 text-muted-foreground">Choose two versions and compare their portable contracts. Validation reports and runtime evidence are intentionally outside the diff.</div>}
        </section>
      </div>
    </main>
  );
}
