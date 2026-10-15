"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, Loader2, RefreshCw, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiBlob, apiFetch } from "@/lib/icheck-api";

type Archive = { id: string; archive_reference: string; snapshot_sha256: string; acknowledged_by: string; acknowledged_at: string; verification_level: "operator_asserted" };
type Verification = { id: string; acknowledgement_id: string; source_id: string; package_sha256: string; package_size_bytes: number; verified_at: string; verified_by: string; verification_level: "https_exact_bytes" };
type ArchiveSource = { id: string; name: string; enabled: boolean };
type Hold = { id: string; hold_reference: string; placed_by: string; placed_at: string; released_by: string | null; released_at: string | null };
type PurgeRequest = { id: string; status: "requested" | "approved" | "rejected" | "executed"; requested_by: string; requested_at: string; reviewed_by: string | null; archive_acknowledgement_id: string };
type Retention = {
  instance_id: string; status: "retained" | "purged"; snapshot_sha256: string;
  archive_acknowledgements: Archive[]; archive_verifications: Verification[]; legal_holds: Hold[]; purge_requests: PurgeRequest[];
  tombstone: { deleted_at: string; deleted_by: string; snapshot_sha256: string } | null;
  blockers: string[];
};

function post(path: string, body: Record<string, unknown>) {
  return apiFetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export default function ReportRetentionPage() {
  const { id } = useParams<{ id: string }>();
  const [state, setState] = useState<Retention | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [archiveReference, setArchiveReference] = useState("");
  const [holdReference, setHoldReference] = useState("");
  const [archiveId, setArchiveId] = useState("");
  const [verificationId, setVerificationId] = useState("");
  const [sources, setSources] = useState<ArchiveSource[]>([]);
  const [sourceId, setSourceId] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const generation = useRef(0);
  const mutation = useRef(0);
  const purgeRequestKey = useRef<string | null>(null);

  const load = useCallback(async () => {
    const current = ++generation.current;
    setLoading(true);
    setError(null);
    try {
      const [result, archiveSources] = await Promise.all([
        apiFetch<Retention>(`/reports/instances/${encodeURIComponent(id)}/retention`),
        apiFetch<ArchiveSource[]>("/reports/archive-sources"),
      ]);
      if (current !== generation.current) return;
      setState(result);
      setSources(archiveSources);
      setSourceId((prior) => archiveSources.some((item) => item.id === prior && item.enabled) ? prior : archiveSources.find((item) => item.enabled)?.id ?? "");
      setArchiveId((prior) => result.archive_acknowledgements.some((item) => item.id === prior) ? prior : result.archive_acknowledgements[0]?.id ?? "");
      setVerificationId(result.archive_verifications.at(-1)?.id ?? "");
    } catch (caught) {
      if (current !== generation.current) return;
      setState(null);
      setError(caught instanceof Error ? caught.message : "Unable to read retention state.");
    } finally {
      if (current === generation.current) setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    const timer = window.setTimeout(() => { void load(); }, 0);
    const currentGeneration = generation;
    const onNamespaceChange = () => { ++mutation.current; setState(null); setSources([]); setSourceId(""); setArchiveId(""); setVerificationId(""); setNotice(null); setConfirmation(""); setBusy(false); purgeRequestKey.current = null; void load(); };
    window.addEventListener("icheck:namespace-changed", onNamespaceChange);
    return () => { ++currentGeneration.current; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", onNamespaceChange); };
  }, [load]);

  async function run(label: string, path: string, body: Record<string, unknown>) {
    if (!state || busy) return;
    if (reason.trim().length < 10 || reason.length > 512) {
      setError("Provide a reason of 10–512 characters for this governed action.");
      return;
    }
    const current = generation.current;
    const action = ++mutation.current;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await post(path, { ...body, reason: reason.trim() });
      if (current !== generation.current) return;
      setNotice(`${label} completed.`);
      setReason("");
      setConfirmation("");
      if (label === "Purge request" || label === "Archive verification") purgeRequestKey.current = null;
      await load();
    } catch (caught) {
      if (current === generation.current) setError(caught instanceof Error ? caught.message : `${label} failed.`);
    } finally {
      if (action === mutation.current) setBusy(false);
    }
  }

  const base = `/reports/instances/${encodeURIComponent(id)}`;
  const retained = state?.status === "retained";
  const selectedVerification = state?.archive_verifications.find((item) => item.id === verificationId && item.acknowledgement_id === archiveId);

  async function downloadArchive() {
    if (!state || busy) return;
    const current = generation.current;
    const action = ++mutation.current;
    setBusy(true); setError(null);
    try {
      const data = await apiBlob(`${base}/archive-export`);
      if (!crypto.subtle || data.snapshotSha256 !== state.snapshot_sha256) throw new Error("Archive download identity could not be verified.");
      const sha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", await data.blob.arrayBuffer()))).map((byte) => byte.toString(16).padStart(2, "0")).join("");
      if (sha !== data.contentSha256) throw new Error("Archive download digest does not match.");
      if (current !== generation.current) return;
      const url = URL.createObjectURL(data.blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = `report-archive-${id}.json`; anchor.click(); URL.revokeObjectURL(url);
    } catch (caught) {
      if (current === generation.current) setError(caught instanceof Error ? caught.message : "Archive download failed.");
    } finally { if (action === mutation.current) setBusy(false); }
  }
  return <main className="min-h-screen bg-[#f4f6f8] text-slate-900">
    <header className="flex min-h-16 items-center justify-between border-b border-slate-200 bg-white px-5 py-3">
      <div className="flex items-center gap-3"><Link href="/reports" className="rounded-md p-2 text-muted-foreground hover:bg-slate-100" aria-label="Back to reports"><ArrowLeft className="size-4" /></Link><span className="grid size-9 place-items-center rounded-xl bg-indigo-600 text-white"><ShieldCheck className="size-4" /></span><div><h1 className="text-sm font-semibold">Report retention</h1><p className="text-xs text-muted-foreground">Archive, legal hold and reviewed deletion for one saved snapshot</p></div></div>
      <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading || busy}><RefreshCw className="size-3.5" />Refresh</Button>
    </header>
    <div className="mx-auto max-w-4xl space-y-5 p-5 lg:p-8">
      {error ? <p role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</p> : null}
      {notice ? <p role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">{notice}</p> : null}
      {loading ? <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />Loading retention state…</p> : null}
      {state ? <>
        <Card><CardHeader><CardTitle className="text-base">{state.status === "retained" ? "Retained snapshot" : "Purged snapshot"}</CardTitle><CardDescription className="break-all">{state.instance_id}</CardDescription></CardHeader><CardContent className="space-y-2 text-xs text-slate-600"><p className="break-all font-mono">SHA256 {state.snapshot_sha256}</p><p>Blockers: {state.blockers.length ? state.blockers.join(", ") : "none detected"}</p>{state.tombstone ? <p>Purged {new Date(state.tombstone.deleted_at).toLocaleString()} by {state.tombstone.deleted_by}. The tombstone remains available, but the saved snapshot and exports do not.</p> : null}</CardContent></Card>
        {retained ? <Card><CardHeader><CardTitle className="text-base">Governed actions</CardTitle><CardDescription>Requires namespace-wide permissions. Every action is audited; reasons are stored as digests.</CardDescription></CardHeader><CardContent className="space-y-4 text-xs">
          <label className="block font-medium text-slate-700">Reason for the next action<Input className="mt-1" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={512} placeholder="At least 10 characters" /></label>
          <div className="grid gap-3 border-t border-slate-100 pt-4 sm:grid-cols-[1fr_auto]"><label className="font-medium text-slate-700">External archive reference<Input className="mt-1" value={archiveReference} onChange={(event) => setArchiveReference(event.target.value)} maxLength={255} placeholder="Approved archive receipt ID" /></label><Button className="self-end" variant="outline" disabled={busy || !archiveReference} onClick={() => void run("Archive acknowledgement", `${base}/archive-acknowledgements`, { archive_reference: archiveReference, snapshot_sha256: state.snapshot_sha256 })}>Acknowledge archive</Button></div>
          <p className="text-amber-800">Acknowledgement alone is not proof. Download the complete archive package, store its unchanged bytes independently, then verify the configured source. Purge fetches and hashes the copy again before deletion.</p>
          <div className="flex flex-wrap gap-3"><Button variant="outline" disabled={busy} onClick={() => void downloadArchive()}>Download complete archive</Button><Link href="/settings/report-archives" className="self-center text-indigo-700 underline">Archive sources</Link></div>
          <div className="grid gap-3 sm:grid-cols-2"><label className="font-medium text-slate-700">Archive acknowledgement<select className="mt-1 block h-9 w-full rounded-md border border-slate-200 bg-white px-3" value={archiveId} onChange={(event) => { setArchiveId(event.target.value); setVerificationId(state.archive_verifications.filter((item) => item.acknowledgement_id === event.target.value).at(-1)?.id ?? ""); purgeRequestKey.current = null; }}><option value="">Select one</option>{state.archive_acknowledgements.map((item) => <option key={item.id} value={item.id}>{item.archive_reference}</option>)}</select></label><label className="font-medium text-slate-700">Independent archive source<select className="mt-1 block h-9 w-full rounded-md border border-slate-200 bg-white px-3" value={sourceId} onChange={(event) => setSourceId(event.target.value)}><option value="">Select enabled source</option>{sources.filter((item) => item.enabled).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label></div>
          <Button variant="outline" disabled={busy || !archiveId || !sourceId} onClick={() => void run("Archive verification", `${base}/archive-verifications`, { acknowledgement_id: archiveId, source_id: sourceId })}>Retrieve and verify archive bytes</Button>
          <div className="grid gap-3 border-t border-slate-100 pt-4 sm:grid-cols-[1fr_auto]"><label className="font-medium text-slate-700">Legal hold reference<Input className="mt-1" value={holdReference} onChange={(event) => setHoldReference(event.target.value)} maxLength={255} placeholder="Case or ticket ID" /></label><Button className="self-end" variant="outline" disabled={busy || !holdReference} onClick={() => void run("Legal hold", `${base}/legal-holds`, { hold_reference: holdReference })}>Place hold</Button></div>
          <div className="grid gap-3 border-t border-slate-100 pt-4 sm:grid-cols-[1fr_auto]"><label className="font-medium text-slate-700">Independent verification receipt<select className="mt-1 block h-9 w-full rounded-md border border-slate-200 bg-white px-3" value={verificationId} onChange={(event) => { setVerificationId(event.target.value); purgeRequestKey.current = null; }}><option value="">Select verified complete copy</option>{state.archive_verifications.filter((item) => item.acknowledgement_id === archiveId).map((item) => <option key={item.id} value={item.id}>{new Date(item.verified_at).toLocaleString()} · {item.package_sha256.slice(0, 12)}</option>)}</select></label><Button className="self-end" variant="outline" disabled={busy || !selectedVerification || state.blockers.length > 0} onClick={() => { purgeRequestKey.current ??= crypto.randomUUID(); void run("Purge request", `${base}/purge-requests`, { archive_acknowledgement_id: archiveId, archive_verification_id: verificationId, request_key: purgeRequestKey.current }); }}>Request purge</Button></div>
        </CardContent></Card> : null}
        <Card><CardHeader><CardTitle className="text-base">Archive acknowledgements</CardTitle><CardDescription>Metadata remains after purge; external archive contents are outside this platform.</CardDescription></CardHeader><CardContent className="space-y-2 text-xs">{state.archive_acknowledgements.length ? state.archive_acknowledgements.map((item) => <p key={item.id} className="rounded-lg border border-slate-200 p-3"><span className="font-medium">{item.archive_reference}</span> · {item.verification_level.replace("_", " ")} · {item.acknowledged_by} · {new Date(item.acknowledged_at).toLocaleString()}</p>) : <p className="text-muted-foreground">No archive acknowledgement.</p>}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-base">Independent byte verification</CardTitle><CardDescription>A receipt proves exact bytes at its observation time, not future availability or external WORM policy.</CardDescription></CardHeader><CardContent className="space-y-2 text-xs">{state.archive_verifications.map((item) => <p key={item.id} className="break-all rounded-lg border border-slate-200 p-3">{item.package_sha256} · {item.package_size_bytes.toLocaleString()} bytes · retrieved {new Date(item.verified_at).toLocaleString()} by {item.verified_by}</p>)}{!state.archive_verifications.length ? <p className="text-muted-foreground">No independent verification. Operator assertions cannot authorize purge.</p> : null}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-base">Legal holds</CardTitle><CardDescription>Only a different authorized principal can release a hold.</CardDescription></CardHeader><CardContent className="space-y-2 text-xs">{state.legal_holds.length ? state.legal_holds.map((hold) => <div key={hold.id} className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 p-3"><p><span className="font-medium">{hold.hold_reference}</span> · {hold.released_at ? `Released by ${hold.released_by}` : `Active · placed by ${hold.placed_by}`}</p>{!hold.released_at ? <Button size="sm" variant="outline" disabled={busy} onClick={() => void run("Hold release", `/reports/legal-holds/${hold.id}/release`, {})}>Release</Button> : null}</div>) : <p className="text-muted-foreground">No legal holds.</p>}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-base">Purge reviews</CardTitle><CardDescription>A separate principal must approve; external bytes, protected references and holds are rechecked before execution.</CardDescription></CardHeader>
          <CardContent className="space-y-3 text-xs">{state.purge_requests.length ? state.purge_requests.map((request) => <div key={request.id} className="space-y-3 rounded-lg border border-slate-200 p-3">
            <p><span className="font-medium">{request.status}</span> · requested by {request.requested_by} · {new Date(request.requested_at).toLocaleString()}</p>
            <p className="break-all font-mono text-[10px] text-muted-foreground">{request.id}</p>
            {request.status === "requested" ? <div className="flex gap-2"><Button size="sm" variant="outline" disabled={busy} onClick={() => void run("Purge approval", `/reports/purge-requests/${request.id}/review`, { decision: "approve" })}>Approve</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => void run("Purge rejection", `/reports/purge-requests/${request.id}/review`, { decision: "reject" })}>Reject</Button></div> : null}
            {request.status === "approved" ? <div className="space-y-2">
              <Button size="sm" variant="outline" disabled={busy} onClick={() => void run("Approval withdrawal", `/reports/purge-requests/${request.id}/review`, { decision: "reject" })}>Withdraw unsafe approval</Button>
              <label className="block font-medium text-red-800">Type the full snapshot ID to confirm irreversible deletion<Input className="mt-1" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} placeholder={state.instance_id} /></label>
              <Button size="sm" variant="destructive" disabled={busy || confirmation !== state.instance_id || state.blockers.length > 0} onClick={() => void run("Report purge", `/reports/purge-requests/${request.id}/execute`, {})}>Reverify archive and purge snapshot</Button>
            </div> : null}
          </div>) : <p className="text-muted-foreground">No purge requests.</p>}</CardContent></Card>
      </> : null}
    </div>
  </main>;
}
