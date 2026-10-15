"use client";

import Link from "next/link";
import { ChangeEvent, useCallback, useEffect, useState } from "react";
import {
  ArrowLeft,
  ArrowRightLeft,
  Ban,
  CheckCircle2,
  FileUp,
  Globe2,
  Loader2,
  PackageCheck,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type PackArtifactPlan = {
  name: string;
  kind: string;
  content_hash: string;
  state: "install" | "upgrade" | "retain" | "already_present" | "name_conflict" | "unavailable";
};

type PackDependencyPlan = {
  name: string;
  kind: string;
  content_hash: string;
  state: "pack" | "published" | "not_published" | "hash_mismatch" | "missing";
};

type PackPreview = {
  pack_name: string;
  pack_version: string;
  platform_api: string;
  pack_digest_sha256: string;
  key_fingerprint_sha256: string;
  operation: "install" | "upgrade";
  predecessor_installation_id: string | null;
  predecessor_digest_sha256: string | null;
  signer_rotation: boolean;
  artifact_count: number;
  dependency_count: number;
  installable: boolean;
  already_installed: boolean;
  blockers: string[];
  artifacts: PackArtifactPlan[];
  dependencies: PackDependencyPlan[];
};

type PackInstallation = {
  id: string;
  pack_name: string;
  pack_version: string;
  platform_api: string;
  pack_digest_sha256: string;
  key_fingerprint_sha256: string;
  operation: "install" | "upgrade";
  lifecycle_status: "installed" | "uninstalled";
  predecessor_installation_id: string | null;
  distribution_channel: "upload" | "remote_catalog";
  distribution_snapshot: Record<string, string | number>;
  signer_rotation_snapshot: Record<string, string>;
  installed_by: string;
  installed_at: string;
  uninstall_reason: string | null;
  uninstalled_by: string | null;
  uninstalled_at: string | null;
  uninstall_summary: Record<string, number>;
  artifacts: Array<{
    artifact_version_id: string;
    source_name: string;
    source_kind: string;
    install_action: "installed" | "upgraded" | "retained" | "reused";
  }>;
};

type PackUninstallPreview = {
  installation_id: string;
  pack_name: string;
  pack_version: string;
  pack_digest_sha256: string;
  lifecycle_status: "installed" | "uninstalled";
  uninstallable: boolean;
  already_uninstalled: boolean;
  blockers: string[];
  active_successor_installation_id: string | null;
  dependent_pack_installation_ids: string[];
  introduced_artifact_version_ids: string[];
  impact_summary: Record<string, number>;
};

type RevocationFeed = {
  id: string;
  sequence: number;
  issued_at: string;
  feed_digest_sha256: string;
  key_fingerprint_sha256: string;
  entry_count: number;
  quarantine_summary: Record<string, number>;
  reason: string;
  ingested_by: string;
  ingested_at: string;
  entries: Array<{
    id: string;
    pack_digest_sha256: string;
    reason_code: string;
    effective_at: string;
  }>;
};

const blockerLabels: Record<string, string> = {
  platform_api_incompatible: "Pack targets a different platform API",
  artifact_name_conflict: "An Artifact name exists with different content",
  artifact_version_unavailable: "The exact Artifact version is retired or belongs to a revoked pack",
  dependency_missing: "A required capability is missing",
  dependency_hash_mismatch: "A dependency exists with a different content hash",
  dependency_not_published: "A dependency exists but is not published",
  pack_version_conflict: "This pack name and version has a different digest",
  pack_revoked: "This exact signed pack digest has been revoked",
  pack_predecessor_required: "An upgrade must sign the exact predecessor pack digest",
  pack_predecessor_unknown: "The signed predecessor is not installed for this pack",
  pack_predecessor_not_latest: "The signed predecessor is not the current pack head",
  pack_version_not_newer: "The candidate semantic version does not advance the pack",
  pack_signer_changed: "The candidate signer does not match the predecessor signer",
  pack_signer_rotation_invalid: "The dual-signed signer rotation is invalid or expired",
  pack_signer_rotation_unnecessary: "Signer rotation proof was supplied without a signer change",
  pack_previously_uninstalled: "This exact signed digest was previously uninstalled",
  pack_already_uninstalled: "This pack is already uninstalled",
  pack_has_active_successor: "Uninstall the active successor before its predecessor",
  pack_has_active_dependents: "Other installed packs depend on versions introduced here",
};

function shortHash(value: string) {
  return `${value.slice(0, 12)}…`;
}

function stateClass(state: string) {
  if (["install", "pack", "published", "installed"].includes(state)) {
    return "border-emerald-300 bg-emerald-50 text-emerald-700";
  }
  if (["upgrade", "upgraded", "retain", "retained", "already_present", "reused"].includes(state)) {
    return "border-cyan-300 bg-cyan-50 text-cyan-700";
  }
  return "border-red-300 bg-red-50 text-red-700";
}

export default function CapabilityPacksPage() {
  const [signedPack, setSignedPack] = useState<Record<string, unknown> | null>(null);
  const [filename, setFilename] = useState("");
  const [preview, setPreview] = useState<PackPreview | null>(null);
  const [installations, setInstallations] = useState<PackInstallation[]>([]);
  const [uninstallPlans, setUninstallPlans] = useState<Record<string, PackUninstallPreview>>({});
  const [uninstallReasons, setUninstallReasons] = useState<Record<string, string>>({});
  const [signedRevocation, setSignedRevocation] = useState<Record<string, unknown> | null>(null);
  const [revocationFilename, setRevocationFilename] = useState("");
  const [revocationReason, setRevocationReason] = useState("");
  const [revocations, setRevocations] = useState<RevocationFeed[]>([]);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [packHistory, revocationHistory] = await Promise.all([
        apiFetch<PackInstallation[]>("/capability-packs?limit=200"),
        apiFetch<RevocationFeed[]>("/capability-pack-revocations?limit=200"),
      ]);
      setInstallations(packHistory);
      setRevocations(revocationHistory);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load pack history");
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  async function selectPack(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setError(null);
    setMessage(null);
    setPreview(null);
    try {
      const document = JSON.parse(await file.text()) as Record<string, unknown>;
      if (document.format_version !== "icheck.capability-pack.signed/v1") {
        throw new Error("Select an icheck.capability-pack.signed/v1 JSON document");
      }
      setSignedPack(document);
      setFilename(file.name);
    } catch (cause) {
      setSignedPack(null);
      setFilename("");
      setError(cause instanceof Error ? cause.message : "Pack JSON is invalid");
    } finally {
      event.target.value = "";
    }
  }

  async function runPreview() {
    if (!signedPack) return;
    setBusy("preview");
    setError(null);
    setMessage(null);
    try {
      setPreview(
        await apiFetch<PackPreview>("/capability-packs/preview", {
          method: "POST",
          body: JSON.stringify({ signed_pack: signedPack }),
        }),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Pack preview failed");
    } finally {
      setBusy(null);
    }
  }

  async function installPack() {
    if (!signedPack || !preview?.installable || reason.trim().length < 3) return;
    setBusy("install");
    setError(null);
    setMessage(null);
    try {
      const installed = await apiFetch<PackInstallation>("/capability-packs/install", {
        method: "POST",
        body: JSON.stringify({
          signed_pack: signedPack,
          reason: reason.trim(),
          actor: "capability.operator",
        }),
      });
      setReason("");
      await load();
      await runPreview();
      setMessage(`${installed.pack_name} ${installed.pack_version} installed as validated candidates.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Pack installation failed");
    } finally {
      setBusy(null);
    }
  }

  async function selectRevocation(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setError(null);
    setMessage(null);
    try {
      const document = JSON.parse(await file.text()) as Record<string, unknown>;
      if (document.format_version !== "icheck.capability-pack.revocations.signed/v1") {
        throw new Error("Select an icheck.capability-pack.revocations.signed/v1 JSON document");
      }
      setSignedRevocation(document);
      setRevocationFilename(file.name);
    } catch (cause) {
      setSignedRevocation(null);
      setRevocationFilename("");
      setError(cause instanceof Error ? cause.message : "Revocation JSON is invalid");
    } finally {
      event.target.value = "";
    }
  }

  async function ingestRevocation() {
    if (!signedRevocation || revocationReason.trim().length < 3) return;
    setBusy("revoke");
    setError(null);
    setMessage(null);
    try {
      const feed = await apiFetch<RevocationFeed>("/capability-pack-revocations", {
        method: "POST",
        body: JSON.stringify({
          signed_feed: signedRevocation,
          reason: revocationReason.trim(),
          actor: "security.admin",
        }),
      });
      setRevocationReason("");
      setSignedRevocation(null);
      setRevocationFilename("");
      await load();
      setMessage(`Revocation feed ${feed.sequence} accepted; quarantine was applied atomically.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Revocation feed ingestion failed");
    } finally {
      setBusy(null);
    }
  }

  async function previewUninstall(installation: PackInstallation) {
    setBusy(`uninstall-preview:${installation.id}`);
    setError(null);
    setMessage(null);
    try {
      const plan = await apiFetch<PackUninstallPreview>(
        `/capability-packs/${installation.id}/uninstall-preview`,
      );
      setUninstallPlans((current) => ({ ...current, [installation.id]: plan }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Uninstall preview failed");
    } finally {
      setBusy(null);
    }
  }

  async function uninstallPack(installation: PackInstallation) {
    const plan = uninstallPlans[installation.id];
    const uninstallReason = uninstallReasons[installation.id]?.trim() || "";
    if (!plan?.uninstallable || uninstallReason.length < 3) return;
    setBusy(`uninstall:${installation.id}`);
    setError(null);
    setMessage(null);
    try {
      const removed = await apiFetch<PackInstallation>(
        `/capability-packs/${installation.id}/uninstall`,
        {
          method: "POST",
          body: JSON.stringify({
            expected_pack_digest_sha256: plan.pack_digest_sha256,
            reason: uninstallReason,
            actor: "capability.operator",
          }),
        },
      );
      setUninstallPlans((current) => {
        const next = { ...current };
        delete next[installation.id];
        return next;
      });
      setUninstallReasons((current) => {
        const next = { ...current };
        delete next[installation.id];
        return next;
      });
      await load();
      setMessage(
        `${removed.pack_name} ${removed.pack_version} was uninstalled; its immutable origin ledger remains available.`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Pack uninstall failed");
    } finally {
      setBusy(null);
    }
  }

  const revokedDigests = new Set(
    revocations.flatMap((feed) => feed.entries.map((entry) => entry.pack_digest_sha256)),
  );

  return (
    <main className="min-h-screen bg-[#eef0f5] text-[#253044]">
      <header className="border-b border-[#d8dbe0] bg-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] items-center gap-3 px-5">
          <Link href="/studio/catalog" className="rounded-md p-2 text-[#59677b] hover:bg-[#eef0f5]" aria-label="Back to catalog">
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-[#171c2a] text-white"><PackageCheck className="h-4 w-4" /></span>
          <div>
            <h1 className="text-sm font-semibold">Organization capability packs</h1>
            <p className="text-xs text-muted-foreground">Verify trust → preview exact dependencies → install atomically</p>
          </div>
          <Button asChild variant="outline" size="sm" className="gap-2"><Link href="/studio/catalog/remote" className="ml-auto"><Globe2 className="h-3.5 w-3.5" /> Remote catalogs</Link></Button>
          <Button asChild variant="outline" size="sm"><Link href="/studio/catalog/transparency">Transparency</Link></Button>
          <Button asChild variant="outline" size="sm" className="gap-2"><Link href="/studio/catalog/promotions"><ArrowRightLeft className="h-3.5 w-3.5" /> Promotions</Link></Button>
          <Button variant="outline" size="sm" className="gap-2" onClick={() => void load()}><RefreshCw className="h-3.5 w-3.5" /> Refresh</Button>
        </div>
      </header>

      <div className="mx-auto max-w-[1500px] px-5 py-6">
        {error && <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-700"><XCircle className="h-4 w-4" />{error}</div>}
        {message && <div className="mb-4 flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-xs text-emerald-700"><CheckCircle2 className="h-4 w-4" />{message}</div>}

        <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
          <div className="space-y-6">
            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader><CardTitle className="text-base">Signed pack</CardTitle><CardDescription>Private signing keys remain outside iCheck. Upload a signed JSON envelope; the browser never submits a secret.</CardDescription></CardHeader>
              <CardContent className="space-y-4">
                <label className="flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-dashed border-[#b8c0cc] bg-[#f8f9fb] px-4 py-7 text-sm font-medium text-[#59677b] hover:bg-white">
                  <FileUp className="h-4 w-4" /> {filename || "Select signed capability pack"}
                  <input type="file" accept=".json,application/json" className="hidden" onChange={(event) => void selectPack(event)} />
                </label>
                <Button className="w-full bg-[#5856d6] hover:bg-[#4947ad]" disabled={!signedPack || busy !== null} onClick={() => void runPreview()}>
                  {busy === "preview" ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Verify and preview
                </Button>
              </CardContent>
            </Card>

            {preview && <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader><div className="flex items-start justify-between gap-3"><div><CardTitle className="text-base">{preview.pack_name} {preview.pack_version}</CardTitle><CardDescription>{preview.platform_api} · {preview.artifact_count} artifacts · {preview.dependency_count} dependencies</CardDescription></div><Badge className={cn("text-[10px]", preview.installable ? "border-emerald-300 bg-emerald-50 text-emerald-700" : "border-red-300 bg-red-50 text-red-700")}>{preview.installable ? "installable" : "blocked"}</Badge></div></CardHeader>
              <CardContent className="space-y-4">
                <div className="rounded-md bg-[#f8f9fb] px-3 py-2 font-mono text-[10px] text-[#59677b]">{preview.operation} · pack {shortHash(preview.pack_digest_sha256)} · signer {shortHash(preview.key_fingerprint_sha256)}{preview.predecessor_digest_sha256 ? ` · predecessor ${shortHash(preview.predecessor_digest_sha256)}` : ""}</div>
                {preview.signer_rotation && <div className="rounded-md border border-violet-200 bg-violet-50 px-3 py-2 text-xs text-violet-700">This successor carries a short-lived rotation statement signed by both the predecessor and successor keys.</div>}
                {preview.blockers.length > 0 && <div className="space-y-1.5">{preview.blockers.map((blocker) => <div key={blocker} className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">{blockerLabels[blocker] || blocker}</div>)}</div>}
                <div><p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Artifact plan</p><div className="space-y-1.5">{preview.artifacts.map((item) => <div key={`${item.kind}:${item.name}`} className="flex items-center justify-between rounded-md border border-[#e2e5e9] px-3 py-2 text-xs"><span><span className="font-medium">{item.name}</span> <span className="text-muted-foreground">· {item.kind}</span></span><Badge variant="outline" className={cn("text-[9px]", stateClass(item.state))}>{item.state.replace("_", " ")}</Badge></div>)}</div></div>
                {preview.dependencies.length > 0 && <div><p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Dependency plan</p><div className="space-y-1.5">{preview.dependencies.map((item) => <div key={`${item.kind}:${item.name}`} className="flex items-center justify-between rounded-md border border-[#e2e5e9] px-3 py-2 text-xs"><span>{item.name} <span className="text-muted-foreground">· {item.kind}</span></span><Badge variant="outline" className={cn("text-[9px]", stateClass(item.state))}>{item.state.replace("_", " ")}</Badge></div>)}</div></div>}
                <Textarea value={reason} onChange={(event) => setReason(event.target.value)} rows={3} placeholder="Why should this signed pack be installed?" />
                <Button className="w-full bg-emerald-600 hover:bg-emerald-700" disabled={!preview.installable || preview.already_installed || reason.trim().length < 3 || busy !== null} onClick={() => void installPack()}>{busy === "install" ? <Loader2 className="h-4 w-4 animate-spin" /> : <PackageCheck className="h-4 w-4" />}{preview.already_installed ? "Already installed" : preview.operation === "upgrade" ? "Create validated upgrade candidates" : "Install validated candidates"}</Button>
                <p className="text-[11px] leading-5 text-muted-foreground">Installation never publishes, activates, deploys, or executes a capability. Those remain separate governed decisions.</p>
              </CardContent>
            </Card>}
          </div>

          <Card className="h-fit border-[#d8dbe0] shadow-none">
            <CardHeader><CardTitle className="text-base">Installation ledger</CardTitle><CardDescription>Immutable signed origin and per-Artifact install or reuse result.</CardDescription></CardHeader>
            <CardContent className="space-y-3">
              {installations.length === 0 ? <div className="rounded-lg border border-dashed border-[#cbd1da] p-10 text-center text-sm text-muted-foreground">No organization packs installed.</div> : installations.map((item) => {
                const revoked = revokedDigests.has(item.pack_digest_sha256);
                const uninstalled = item.lifecycle_status === "uninstalled";
                const uninstallPlan = uninstallPlans[item.id];
                return <div key={item.id} className={cn("rounded-lg border p-4", revoked ? "border-red-300 bg-red-50/40" : uninstalled ? "border-slate-300 bg-slate-50/60" : "border-[#d8dbe0]")}>
                  <div className="flex items-start justify-between gap-3">
                    <div><p className="text-sm font-semibold">{item.pack_name} {item.pack_version}</p><p className="mt-1 text-[10px] text-muted-foreground">{item.operation} · {new Date(item.installed_at).toLocaleString()} · {item.installed_by}</p></div>
                    <Badge variant="outline" className={cn("text-[9px]", revoked ? "border-red-300 bg-red-50 text-red-700" : uninstalled ? "border-slate-300 bg-slate-100 text-slate-700" : "border-violet-300 bg-violet-50 text-violet-700")}>
                      {revoked ? <><Ban className="mr-1 h-3 w-3" /> revoked</> : uninstalled ? <><Trash2 className="mr-1 h-3 w-3" /> uninstalled</> : <><ShieldCheck className="mr-1 h-3 w-3" /> signed</>}
                    </Badge>
                  </div>
                  <p className="mt-3 font-mono text-[9px] text-muted-foreground">{shortHash(item.pack_digest_sha256)}{item.predecessor_installation_id ? ` · predecessor ${item.predecessor_installation_id.slice(0, 8)}…` : ""}</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <Badge variant="outline" className="text-[9px]">
                      {item.distribution_channel === "remote_catalog" ? "remote catalog" : "signed upload"}
                    </Badge>
                    {item.distribution_channel === "remote_catalog" && (
                      <>
                        <Badge variant="outline" className="font-mono text-[9px]">
                          sequence {String(item.distribution_snapshot.sequence ?? "—")}
                        </Badge>
                        <Badge variant="outline" className="font-mono text-[9px]">
                          index {shortHash(String(item.distribution_snapshot.index_digest_sha256 ?? ""))}
                        </Badge>
                      </>
                    )}
                    {item.signer_rotation_snapshot.statement_digest_sha256 && (
                      <Badge variant="outline" className="border-violet-200 bg-violet-50 font-mono text-[9px] text-violet-700">
                        signer rotation {shortHash(item.signer_rotation_snapshot.statement_digest_sha256)}
                      </Badge>
                    )}
                  </div>
                  <div className="mt-3 space-y-1.5">{item.artifacts.map((artifact) => <div key={artifact.artifact_version_id} className="flex items-center justify-between rounded-md bg-[#f8f9fb] px-3 py-2 text-xs"><span>{artifact.source_name} <span className="text-muted-foreground">· {artifact.source_kind}</span></span><Badge variant="outline" className={cn("text-[9px]", stateClass(artifact.install_action))}>{artifact.install_action}</Badge></div>)}</div>
                  {uninstalled && <div className="mt-3 rounded-md border border-slate-200 bg-white px-3 py-2 text-[11px] text-slate-600">
                    Removed {item.uninstalled_at ? new Date(item.uninstalled_at).toLocaleString() : ""} by {item.uninstalled_by || "unknown"}.
                    {item.uninstall_reason ? <span className="mt-1 block">{item.uninstall_reason}</span> : null}
                    <div className="mt-2 flex flex-wrap gap-1.5">{Object.entries(item.uninstall_summary).filter(([, count]) => count > 0).map(([name, count]) => <Badge key={name} variant="outline" className="border-slate-200 bg-slate-50 text-[9px] text-slate-600">{name.replaceAll("_", " ")}: {count}</Badge>)}</div>
                  </div>}
                  {!uninstalled && <div className="mt-3">
                    <Button variant="outline" size="sm" className="gap-2 text-red-700" disabled={busy !== null} onClick={() => void previewUninstall(item)}>
                      {busy === `uninstall-preview:${item.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />} Preview uninstall
                    </Button>
                  </div>}
                  {uninstallPlan && !uninstalled && <div className="mt-3 space-y-3 rounded-md border border-red-200 bg-red-50/50 p-3">
                    <div className="flex items-center justify-between gap-3"><p className="text-xs font-semibold text-red-800">Uninstall impact</p><Badge variant="outline" className={cn("text-[9px]", uninstallPlan.uninstallable ? "border-amber-300 bg-amber-50 text-amber-700" : "border-red-300 bg-red-50 text-red-700")}>{uninstallPlan.uninstallable ? "review required" : "blocked"}</Badge></div>
                    {uninstallPlan.blockers.map((blocker) => <div key={blocker} className="rounded border border-red-200 bg-white px-2 py-1.5 text-[11px] text-red-700">{blockerLabels[blocker] || blocker}</div>)}
                    <div className="flex flex-wrap gap-1.5">{Object.entries(uninstallPlan.impact_summary).filter(([, count]) => count > 0).map(([name, count]) => <Badge key={name} variant="outline" className="border-amber-200 bg-white text-[9px] text-amber-700">{name.replaceAll("_", " ")}: {count}</Badge>)}</div>
                    {uninstallPlan.dependent_pack_installation_ids.length > 0 && <p className="font-mono text-[9px] text-red-700">dependents: {uninstallPlan.dependent_pack_installation_ids.join(", ")}</p>}
                    {uninstallPlan.uninstallable && <>
                      <Textarea value={uninstallReasons[item.id] || ""} onChange={(event) => setUninstallReasons((current) => ({ ...current, [item.id]: event.target.value }))} rows={2} placeholder="Why should this pack be uninstalled?" />
                      <Button variant="destructive" size="sm" className="w-full gap-2" disabled={(uninstallReasons[item.id]?.trim().length || 0) < 3 || busy !== null} onClick={() => void uninstallPack(item)}>
                        {busy === `uninstall:${item.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />} Confirm compatible uninstall
                      </Button>
                    </>}
                  </div>}
                </div>;
              })}
            </CardContent>
          </Card>
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
          <Card className="h-fit border-red-200 shadow-none">
            <CardHeader><CardTitle className="flex items-center gap-2 text-base"><ShieldAlert className="h-4 w-4 text-red-600" /> Signed revocation feed</CardTitle><CardDescription>Security administrators can ingest a signed, monotonically sequenced digest denylist. Acceptance immediately quarantines capabilities introduced by matching packs.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              <label className="flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-dashed border-red-200 bg-red-50/40 px-4 py-7 text-sm font-medium text-red-700 hover:bg-red-50">
                <FileUp className="h-4 w-4" /> {revocationFilename || "Select signed revocation feed"}
                <input type="file" accept=".json,application/json" className="hidden" onChange={(event) => void selectRevocation(event)} />
              </label>
              <Textarea value={revocationReason} onChange={(event) => setRevocationReason(event.target.value)} rows={3} placeholder="Why is this signed security feed being accepted?" />
              <Button variant="destructive" className="w-full" disabled={!signedRevocation || revocationReason.trim().length < 3 || busy !== null} onClick={() => void ingestRevocation()}>{busy === "revoke" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Ban className="h-4 w-4" />} Verify and quarantine</Button>
              <p className="text-[11px] leading-5 text-muted-foreground">Revocation is intentionally irreversible. Recovery requires a new fixed pack digest and a new governed publish/activation decision.</p>
            </CardContent>
          </Card>

          <Card className="h-fit border-[#d8dbe0] shadow-none">
            <CardHeader><CardTitle className="text-base">Revocation ledger</CardTitle><CardDescription>Trusted feed sequence, exact pack digests, and the state changes made during quarantine.</CardDescription></CardHeader>
            <CardContent className="space-y-3">
              {revocations.length === 0 ? <div className="rounded-lg border border-dashed border-[#cbd1da] p-10 text-center text-sm text-muted-foreground">No signed revocation feeds ingested.</div> : revocations.map((feed) => <div key={feed.id} className="rounded-lg border border-red-200 p-4"><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-semibold">Feed sequence {feed.sequence}</p><p className="mt-1 text-[10px] text-muted-foreground">{new Date(feed.ingested_at).toLocaleString()} · {feed.ingested_by}</p></div><Badge variant="outline" className="border-red-300 bg-red-50 text-[9px] text-red-700"><Ban className="mr-1 h-3 w-3" /> {feed.entry_count} revoked</Badge></div><p className="mt-2 text-xs text-[#59677b]">{feed.reason}</p><p className="mt-2 font-mono text-[9px] text-muted-foreground">feed {shortHash(feed.feed_digest_sha256)} · signer {shortHash(feed.key_fingerprint_sha256)}</p><div className="mt-3 space-y-1.5">{feed.entries.map((entry) => <div key={entry.id} className="flex items-center justify-between rounded-md bg-red-50 px-3 py-2 text-xs"><span className="font-mono text-[10px]">{shortHash(entry.pack_digest_sha256)}</span><Badge variant="outline" className="border-red-300 bg-white text-[9px] text-red-700">{entry.reason_code.replace("_", " ")}</Badge></div>)}</div><div className="mt-3 flex flex-wrap gap-1.5">{Object.entries(feed.quarantine_summary).filter(([, count]) => count > 0).map(([name, count]) => <Badge key={name} variant="outline" className="border-slate-200 bg-slate-50 text-[9px] text-slate-600">{name.replaceAll("_", " ")}: {count}</Badge>)}</div></div>)}
            </CardContent>
          </Card>
        </section>
      </div>
    </main>
  );
}
