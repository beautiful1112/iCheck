"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";

type Receipt = { id: string; observed_at: string; verdict: string; disposition: string; alert_id: string | null };
type Source = { source_id: string; condition_key: string; entity_type: string; entity_id: string;
  context: { definition?: { title?: string; operator?: string; expected?: unknown; max_age_seconds?: number }; [key: string]: unknown };
  logical_state: string; observed_at: string | null; latest_alert_id: string | null; receipts: Receipt[]; receipts_truncated: boolean };
type Proposal = { id: string; baseline_receipt_id: string; author_principal_id: string; author_subject: string;
  evidence_environment: string; validation_reference: string; expires_at: string; snapshot: Record<string, unknown> };
type Review = { id: string; request_id: string; reviewer_subject: string; acceptance_reference: string; created_at: string };
type Revocation = { review_id: string; reason: string; created_at: string };
type History = { requests: Proposal[]; reviews: Review[]; revocations: Revocation[]; truncated: boolean };
type Identity = { principal_id: string | null; subject: string; principal_type: string; permissions: string[] };
type Proof = { qualified_quiet: boolean; production_qualified: boolean; evidence_environment: string; blockers: string[];
  observed_at: string | null; evaluated_at: string; qualification_expires_at: string; condition_revision: number | null };

function localTime(value: Date) {
  return new Date(value.getTime() - value.getTimezoneOffset()*60000).toISOString().slice(0, 16);
}
function time(value: string | null) { return value ? new Date(value).toLocaleString() : "Not observed"; }

export default function SourceQualificationWorkspace({ sourceId }: { sourceId: string }) {
  const [source, setSource] = useState<Source | null>(null);
  const [history, setHistory] = useState<History | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [proof, setProof] = useState<Proof | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [baselineId, setBaselineId] = useState("");
  const [proposalId, setProposalId] = useState("");
  const [reviewId, setReviewId] = useState("");
  const [environment, setEnvironment] = useState("controlled_fixture");
  const [validationReference, setValidationReference] = useState("");
  const [acceptanceReference, setAcceptanceReference] = useState("");
  const [proposalReason, setProposalReason] = useState("");
  const [reviewReason, setReviewReason] = useState("");
  const [revokeReason, setRevokeReason] = useState("");
  const [expires, setExpires] = useState(() => localTime(new Date(Date.now()+86400000)));
  const [requestKey, setRequestKey] = useState(() => "source-"+crypto.randomUUID());
  const [confirmations, setConfirmations] = useState([false, false, false]);
  const [now, setNow] = useState(() => Date.now());
  const generation = useRef(0);
  const operation = useRef(0);
  const abort = useRef<AbortController | null>(null);
  const path = `/collector-condition-sources/${encodeURIComponent(sourceId)}`;
  const invalidate = useCallback(() => {
    generation.current += 1; operation.current += 1; abort.current?.abort();
  }, []);

  const load = useCallback(async () => {
    const current = ++generation.current;
    abort.current?.abort();
    const controller = new AbortController(); abort.current = controller;
    setLoading(true); setProof(null); setSource(null); setHistory(null); setIdentity(null);
    setBaselineId(""); setProposalId(""); setReviewId("");
    try {
      const [data, ledger, user] = await Promise.all([
        apiFetch<Source>(path, { signal: controller.signal }),
        apiFetch<History>(path+"/qualifications", { signal: controller.signal }),
        apiFetch<Identity>("/auth/me", { signal: controller.signal }),
      ]);
      if (current !== generation.current) return;
      setSource(data); setHistory(ledger); setIdentity(user);
      setBaselineId(data.receipts.find(row => row.disposition === "accepted" && row.verdict !== "unknown" && Date.parse(row.observed_at) <= Date.now())?.id ?? "");
      setProposalId(ledger.requests[0]?.id ?? ""); setReviewId(ledger.reviews[0]?.id ?? "");
    } catch (cause) {
      if (current === generation.current && !controller.signal.aborted) setMessage(cause instanceof Error ? cause.message : "Source evidence could not be loaded.");
    } finally { if (current === generation.current) setLoading(false); }
  }, [path]);

  useEffect(() => {
    function changed() {
      invalidate();
      setBusy(false); setMessage(""); setProof(null); setConfirmations([false, false, false]);
      setValidationReference(""); setAcceptanceReference(""); setProposalReason(""); setReviewReason(""); setRevokeReason("");
      setRequestKey("source-"+crypto.randomUUID()); setEnvironment("controlled_fixture");
      void load();
    }
    changed();
    window.addEventListener("icheck:namespace-changed", changed);
    window.addEventListener("storage", changed);
    return () => {
      invalidate();
      window.removeEventListener("icheck:namespace-changed", changed);
      window.removeEventListener("storage", changed);
    };
  }, [load, invalidate]);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 5000); return () => window.clearInterval(timer); }, []);

  const human = Boolean(identity?.principal_id && identity.principal_type === "user");
  const permits = (permission: string) => human && Boolean(identity?.permissions.includes("*") || identity?.permissions.includes(permission));
  const selectedProposal = history?.requests.find(row => row.id === proposalId);
  const selectedReview = history?.reviews.find(row => row.id === reviewId);
  const revoked = Boolean(history?.revocations.some(row => row.review_id === reviewId));
  const proofFresh = Boolean(proof?.observed_at && now < Math.min(Date.parse(proof.qualification_expires_at),
    Date.parse(proof.observed_at)+(source?.context.definition?.max_age_seconds ?? 0)*1000));

  async function mutate(action: "propose" | "review" | "revoke") {
    if (busy || loading || !source || !identity) return;
    const current = generation.current;
    const operationId = ++operation.current;
    let url: string;
    let body: Record<string, unknown>;
    if (action === "propose") {
      const expiry = new Date(expires);
      if (!baselineId || validationReference.trim().length < 10 || proposalReason.trim().length < 10 || !Number.isFinite(expiry.getTime()) || expiry.getTime() <= Date.now()) {
        setMessage("Choose an accepted baseline, a future expiry and validation reference/reason of at least ten characters."); return;
      }
      url = path+"/qualifications";
      body = { baseline_receipt_id: baselineId, request_key: requestKey, evidence_environment: environment,
        validation_reference: validationReference.trim(), reason: proposalReason.trim(), expires_at: expiry.toISOString() };
    } else if (action === "review") {
      if (!proposalId || !confirmations.every(Boolean) || acceptanceReference.trim().length < 10 || reviewReason.trim().length < 10) {
        setMessage("Confirm all three independent validations and provide the acceptance reference and reason."); return;
      }
      url = `/source-qualification-requests/${encodeURIComponent(proposalId)}/review`;
      body = { independent_semantics_validated: true, independent_identity_validated: true, independent_clock_validated: true,
        acceptance_reference: acceptanceReference.trim(), reason: reviewReason.trim() };
    } else {
      if (!reviewId || revokeReason.trim().length < 10) { setMessage("Provide a revocation reason of at least ten characters."); return; }
      url = `/source-qualification-reviews/${encodeURIComponent(reviewId)}/revoke`;
      body = { reason: revokeReason.trim() };
    }
    setBusy(true); setMessage(""); setProof(null);
    try {
      await apiFetch(url, { method: "POST", body: JSON.stringify(body) });
      if (current !== generation.current) return;
      setConfirmations([false, false, false]);
      if (action === "propose") setRequestKey("source-"+crypto.randomUUID());
      setMessage(action === "revoke" ? "Acceptance revoked; immutable history is retained." : "Recorded. This does not authorize incident closure.");
      await load();
    } catch (cause) { if (current === generation.current) setMessage(cause instanceof Error ? cause.message : "Source qualification failed. Refresh before retrying."); }
    finally { if (operationId === operation.current) setBusy(false); }
  }

  async function checkQuiet() {
    if (!source?.latest_alert_id || !reviewId || busy || loading) return;
    const current = generation.current;
    setBusy(true); setProof(null); setMessage("");
    try {
      const result = await apiFetch<Proof>(path+"/quiet-evidence?"+new URLSearchParams({ review_id: reviewId, alert_id: source.latest_alert_id }));
      if (current === generation.current) { setProof(result); setNow(Date.now()); }
    } catch (cause) { if (current === generation.current) setMessage(cause instanceof Error ? cause.message : "Quiet evidence check failed."); }
    finally { if (current === generation.current) setBusy(false); }
  }

  return <main className="mx-auto w-full max-w-5xl space-y-6 overflow-hidden px-4 py-8 text-sm sm:px-8">
    <Link href="/situations" className="text-sky-700 underline">Back to Situations</Link>
    <header><h1 className="text-2xl font-semibold">Collector source qualification</h1>
      <p className="mt-2 text-slate-600">Independent human acceptance of one exact source generation. No incident closure authority.</p></header>
    <Link className="text-sky-700 underline" href={`/assets/condition-sources/${encodeURIComponent(sourceId)}/replacements`}>Review source evolution and permanent cutover</Link>
    <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 leading-6">A resolved Alert is not independent recovery proof. Peer references are external attestations, not automatic verification of physical truth. This page checks one Alert only, not all evidence in a Situation.</div>
    {message ? <p role="status" className="break-words rounded-lg border p-3">{message}</p> : null}
    <Button variant="outline" disabled={busy || loading} onClick={() => { setMessage(""); void load(); }}>Refresh source and history</Button>
    {loading ? <p role="status">Loading authorized source evidence…</p> : null}
    {!loading && source && history ? <>
      <section className="space-y-2 rounded-lg border p-4">
        <h2 className="text-lg font-semibold">{source.context.definition?.title ?? source.condition_key}</h2>
        <p className="break-words">{source.entity_type} · {source.entity_id}</p>
        <p>Logical state: <strong>{source.logical_state}</strong> · observed {time(source.observed_at)}</p>
        <p>Predicate: {source.context.definition?.operator} {JSON.stringify(source.context.definition?.expected)} · measurement freshness {source.context.definition?.max_age_seconds}s</p>
        <details><summary className="cursor-pointer text-sky-700">Exact source provenance</summary><pre role="region" aria-label={`Source provenance for ${sourceId}`} tabIndex={0} className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-3 text-xs focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#5856d6]">{JSON.stringify(source.context, null, 2)}</pre></details>
      </section>
      {!human ? <p className="rounded-lg border p-3">Read-only here. Proposals and acceptance require signed-in persisted human accounts; development mode cannot approve.</p> : <p>Signed in as {identity?.subject}. Server-side roles and scope are rechecked on every operation.</p>}
      <section className="space-y-3 rounded-lg border p-4">
        <h2 className="text-lg font-semibold">Peer-reviewed quiet check</h2>
        <label className="block">Acceptance record<select aria-label="Acceptance record" className="mt-1 w-full rounded border p-2" value={reviewId} onChange={event => { setReviewId(event.target.value); setProof(null); }}>
          <option value="">Select an acceptance</option>{history.reviews.map(row => <option key={row.id} value={row.id}>{row.reviewer_subject} · {time(row.created_at)}{history.revocations.some(item => item.review_id === row.id) ? " · revoked" : ""}</option>)}</select></label>
        <p className="break-words">{selectedReview?.acceptance_reference ?? "No independent peer acceptance recorded."}</p>
        <Button disabled={!reviewId || !source.latest_alert_id || busy || loading} onClick={() => void checkQuiet()}>Check current quiet evidence</Button>
        {proof ? <div role="status" className="space-y-2 rounded bg-slate-50 p-3">
          <p className="font-semibold">{proof.qualified_quiet && proofFresh ? "Qualified quiet for this Alert at check time" : "Quiet evidence unavailable or stale"}</p>
          <p>Evidence environment: {proof.evidence_environment.replaceAll("_", " ")} · {proof.production_qualified && proofFresh ? "production source acceptance" : "not production qualified"}</p>
          <p>Checked {time(proof.evaluated_at)} · condition revision {proof.condition_revision} · expires no later than {time(proof.qualification_expires_at)}</p>
          {proof.blockers.length ? <ul className="list-inside list-disc">{proof.blockers.map(item => <li key={item}>{item.replaceAll("_", " ")}</li>)}</ul> : null}
          <p>Point-in-time evidence only. Refresh after source or authority changes. No Situation coverage or closure permission.</p>
        </div> : null}
      </section>
      <details className="rounded-lg border p-4"><summary className="cursor-pointer font-semibold">Propose external source validation</summary><div className="mt-4 space-y-3">
        <p>Validate the condition mapping, exact device/credential identity and observation-clock controls outside this software. Keep fixtures separate from lab and production acceptance.</p>
        <label className="block">Baseline receipt<select aria-label="Baseline receipt" className="mt-1 w-full rounded border p-2" value={baselineId} onChange={event => setBaselineId(event.target.value)}>
          <option value="">Select an accepted typed receipt</option>{source.receipts.filter(row => row.disposition === "accepted" && row.verdict !== "unknown").map(row => <option key={row.id} value={row.id}>{row.verdict} · {time(row.observed_at)}</option>)}</select></label>
        {source.receipts_truncated ? <p className="text-amber-700">Receipt history is truncated. This is not a complete source history.</p> : null}
        <label className="block">Validation environment<select aria-label="Validation environment" className="mt-1 w-full rounded border p-2" value={environment} onChange={event => setEnvironment(event.target.value)}><option value="controlled_fixture">Controlled fixture</option><option value="live_lab">Live lab</option><option value="production">Production (verified Worker mTLS required)</option></select></label>
        <label className="block">External validation reference<Input value={validationReference} maxLength={1024} onChange={event => setValidationReference(event.target.value)} /></label>
        <label className="block">Proposal reason<Input value={proposalReason} maxLength={512} onChange={event => setProposalReason(event.target.value)} /></label>
        <label className="block">Acceptance expiry (local time, maximum 30 days)<Input type="datetime-local" value={expires} onChange={event => setExpires(event.target.value)} /></label>
        <Button disabled={!permits("alerts.manage") || busy || loading} onClick={() => void mutate("propose")}>Record proposal for peer review</Button>
      </div></details>
      <details className="rounded-lg border p-4"><summary className="cursor-pointer font-semibold">Independent peer acceptance</summary><div className="mt-4 space-y-3">
        <label className="block">Proposal<select aria-label="Proposal" className="mt-1 w-full rounded border p-2" value={proposalId} onChange={event => { setProposalId(event.target.value); setConfirmations([false, false, false]); }}><option value="">Select a proposal</option>{history.requests.map(row => <option key={row.id} value={row.id}>{row.author_subject} · {row.evidence_environment.replaceAll("_", " ")} · expires {time(row.expires_at)}</option>)}</select></label>
        <p className="break-words">External validation: {selectedProposal?.validation_reference ?? "No proposal selected."}</p>
        {selectedProposal ? <details><summary className="cursor-pointer text-sky-700">Inspect the exact proposed material</summary><pre role="region" aria-label={`Proposed source acceptance ${selectedProposal.id}`} tabIndex={0} className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-3 text-xs focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#5856d6]">{JSON.stringify(selectedProposal.snapshot, null, 2)}</pre></details> : null}
        <p>You must differ from the proposal author and the Collector author, validator and publisher. Every checkbox is a human attestation, not an automated test result.</p>
        {["I independently validated the condition semantics.", "I independently validated the exact source identity.", "I independently validated the observation-clock controls."].map((label, index) => <label key={label} className="flex items-start gap-2"><input type="checkbox" checked={confirmations[index]} onChange={event => setConfirmations(previous => previous.map((value, position) => position === index ? event.target.checked : value))} /><span>{label}</span></label>)}
        <label className="block">Independent acceptance reference<Input value={acceptanceReference} maxLength={1024} onChange={event => setAcceptanceReference(event.target.value)} /></label>
        <label className="block">Peer acceptance reason<Input value={reviewReason} maxLength={512} onChange={event => setReviewReason(event.target.value)} /></label>
        <Button disabled={!permits("alerts.sources.qualify") || !selectedProposal || selectedProposal.author_principal_id === identity?.principal_id || Date.parse(selectedProposal.expires_at) <= now || !confirmations.every(Boolean) || busy || loading} onClick={() => void mutate("review")}>Record independent acceptance</Button>
      </div></details>
      <details className="rounded-lg border p-4"><summary className="cursor-pointer font-semibold">Withdraw source acceptance</summary><div className="mt-4 space-y-3">
        <p>Revocation remains possible after source drift or expiry. The selected acceptance and its proposal stay in immutable history.</p>
        <label className="block">Revocation reason<Input value={revokeReason} maxLength={512} onChange={event => setRevokeReason(event.target.value)} /></label>
        <Button variant="outline" disabled={!permits("alerts.sources.qualify") || !reviewId || revoked || busy || loading} onClick={() => void mutate("revoke")}>Revoke selected acceptance</Button>
        {history.revocations.map(row => <p key={row.review_id} className="break-words text-slate-600">Revoked {time(row.created_at)}: {row.reason}</p>)}
      </div></details>
      {history.truncated ? <p role="status" className="rounded border border-amber-200 p-3 text-amber-700">Qualification history is truncated; omitted proposals and descendants are not covered by this view.</p> : null}
    </> : null}
  </main>;
}
