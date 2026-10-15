"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { APIError, apiFetch } from "@/lib/icheck-api";
import { closureDeadlineFresh, closureLeaseMetadata, closureVersionEnabled, type ClosureLease, type ClosureReceipt } from "@/lib/situation-closure";

type Identity = { principal_id: string | null; principal_type: string; permissions: string[] };
type Policy = { id: string; name: string; review_id: string | null; author_principal_id: string;
  evidence_environment: string; expires_at: string; record_state: string; source_count: number;
  proof_version: 1 | 2; replacement_count: number };
type Grant = { id: string; policy_review_id: string; proof_basis: string; reviewer_principal_id: string;
  reviewer_subject: string; acceptance_reference: string; expires_at: string; max_lease_seconds: number; proof_version: 1 | 2 };
type GrantEntry = { grant: Grant; policy_request_id: string; evidence_environment: string; record_state: string;
  revocation: { reason: string } | null };
type Workspace = { host_enabled: boolean; replacement_closure_enabled: boolean; can_review_authority: boolean; can_revoke_authority: boolean;
  can_request_closure: boolean; policies: Policy[]; grants: GrantEntry[]; catalog_truncated: boolean;
  policy_scan_limit: number; grant_limit: number; latest_receipt_matches_current_membership: boolean;
  history: { receipts: ClosureReceipt[]; truncated: boolean; ownership_epoch: number };
  ownership: { request_id: string; owner_principal_id: string; owner_subject: string; state: string; epoch: number; lease_expires_at: string } | null };
type Proof = { qualified_recovery: boolean; covers_situation: boolean; production_qualified: boolean;
  evidence_environment: string; valid_until: string | null; member_count: number; blockers: string[] };
type ClaimIntent = { grant_id: string; request_key: string; reason: string; lease_seconds: number; expected_epoch: number; proof_version: 1 | 2 };
type ClaimResult = ClosureLease & { lease_token?: string | null; receipt?: ClosureReceipt | null };
type RequestDetail = ClosureLease & { receipt: ClosureReceipt | null };
const displayTime = (value: string | null) => value ? new Date(value).toLocaleString() : "Unavailable";
const localTime = (value: Date) => new Date(value.getTime()-value.getTimezoneOffset()*60000).toISOString().slice(0, 16);

export default function ClosureWorkspace({ situationId }: { situationId: string }) {
  const [title, setTitle] = useState(""); const [identity, setIdentity] = useState<Identity | null>(null);
  const [view, setView] = useState<Workspace | null>(null); const [grantId, setGrantId] = useState("");
  const [policyId, setPolicyId] = useState(""); const [proof, setProof] = useState<Proof | null>(null);
  const [exactGrant, setExactGrant] = useState(""); const [exactPolicy, setExactPolicy] = useState("");
  const [lease, setLease] = useState<ClosureLease | null>(null); const [receipt, setReceipt] = useState<ClosureReceipt | null>(null);
  const [reason, setReason] = useState(""); const [leaseSeconds, setLeaseSeconds] = useState("30");
  const [intentPinned, setIntentPinned] = useState(false); const [hasSecret, setHasSecret] = useState(false);
  const [basis, setBasis] = useState("source_recovery"); const [versionId, setVersionId] = useState("");
  const [reference, setReference] = useState(""); const [reviewReason, setReviewReason] = useState("");
  const [expires, setExpires] = useState(""); const [maxLease, setMaxLease] = useState("30");
  const [confirmed, setConfirmed] = useState(false); const [reviewPinned, setReviewPinned] = useState(false);
  const [revokeReason, setRevokeReason] = useState(""); const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true); const [message, setMessage] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const generation = useRef(0); const operation = useRef(0); const controller = useRef<AbortController | null>(null);
  const secret = useRef<string | null>(null); const principal = useRef<string | null>(null);
  const claimIntent = useRef<ClaimIntent | null>(null); const reviewIntent = useRef<Record<string, unknown> | null>(null);
  const reviewKey = useRef(""); const path = `/situations/${encodeURIComponent(situationId)}`;
  const workspaceQuery = useRef("");
  const eraseLease = useCallback(() => { secret.current = null; claimIntent.current = null;
    setHasSecret(false); setIntentPinned(false); setLease(null); setReceipt(null); }, []);
  const cancel = useCallback(() => { operation.current += 1; controller.current?.abort(); }, []);
  const load = useCallback(async () => {
    cancel(); const current = generation.current; const op = operation.current;
    const abort = new AbortController(); controller.current = abort;
    setLoading(true); setBusy(false); setView(null); setProof(null); setMessage("");
    try {
      const [detail, user] = await Promise.all([apiFetch<{ situation: { title: string } }>(path, { signal: abort.signal, cache: "no-store" }),
        apiFetch<Identity>("/auth/me", { signal: abort.signal, cache: "no-store" })]);
      if (current !== generation.current || op !== operation.current) return;
      if (principal.current !== user.principal_id) { eraseLease(); reviewIntent.current = null; setReviewPinned(false); setConfirmed(false); }
      principal.current = user.principal_id; setIdentity(user); setTitle(detail.situation.title);
      const result = await apiFetch<Workspace>(path+"/closure-workspace"+workspaceQuery.current, { signal: abort.signal, cache: "no-store" });
      if (current !== generation.current || op !== operation.current) return;
      setView(result);
    } catch (cause) {
      if (current === generation.current && op === operation.current && !abort.signal.aborted) {
        if (cause instanceof APIError && [401, 403, 404].includes(cause.status)) { eraseLease(); setTitle(""); }
        setMessage(cause instanceof Error ? cause.message : "Closure workspace unavailable.");
      }
    } finally { if (current === generation.current && op === operation.current) setLoading(false); }
  }, [cancel, eraseLease, path]);
  useEffect(() => {
    function changed() {
      generation.current += 1; eraseLease(); principal.current = null; setIdentity(null); setTitle("");
      workspaceQuery.current = ""; setExactGrant(""); setExactPolicy("");
      setGrantId(""); setPolicyId(""); setReason(""); setRevokeReason(""); setReference(""); setReviewReason("");
      setBasis("source_recovery"); setVersionId(""); setMaxLease("30"); setLeaseSeconds("30");
      setConfirmed(false); setReviewPinned(false); reviewIntent.current = null; reviewKey.current = "closure-grant-"+crypto.randomUUID();
      setExpires(localTime(new Date(Date.now()+3600000))); void load();
    }
    changed(); window.addEventListener("icheck:namespace-changed", changed); window.addEventListener("storage", changed);
    return () => { generation.current += 1; cancel(); secret.current = null; claimIntent.current = null; reviewIntent.current = null;
      window.removeEventListener("icheck:namespace-changed", changed); window.removeEventListener("storage", changed); };
  }, [cancel, eraseLease, load]);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  const selected = view?.grants.find(item => item.grant.id === grantId);
  const policy = view?.policies.find(item => item.id === policyId);
  const usable = Boolean(view && identity?.principal_id && !loading && !busy);
  const grantFresh = Boolean(selected?.record_state === "accepted" && closureDeadlineFresh(selected.grant.expires_at, now));
  const proofFresh = Boolean(proof?.qualified_recovery && proof.covers_situation && closureDeadlineFresh(proof.valid_until, now));
  const liveOwnership = Boolean(view?.ownership?.state === "claimed" && closureDeadlineFresh(view.ownership.lease_expires_at, now));
  const liveLease = Boolean(lease?.state === "claimed" && closureDeadlineFresh(lease.lease_expires_at, now));
  const leaseCurrent = Boolean(lease && (!view?.ownership || (view.ownership.request_id === lease.request_id && view.ownership.epoch === lease.epoch)));
  const independentExecutor = Boolean(selected && identity?.principal_id !== selected.grant.reviewer_principal_id);
  const compatibleClosure = Boolean(selected && closureVersionEnabled(selected.grant.proof_version, view?.replacement_closure_enabled));
  const canClaim = usable && Boolean(view?.host_enabled && view.can_request_closure) && grantFresh && independentExecutor && proofFresh && !hasSecret
    && compatibleClosure && (!liveOwnership || Boolean(intentPinned && view?.ownership?.request_id === lease?.request_id));
  const canReview = usable && Boolean(view?.can_review_authority && policy?.review_id && policy.record_state === "accepted"
    && closureVersionEnabled(policy.proof_version, view?.replacement_closure_enabled)
    && identity?.principal_id !== policy.author_principal_id && closureDeadlineFresh(policy.expires_at, now));

  async function run(action: "check" | "review" | "revoke" | "claim" | "finalize" | "release" | "recover") {
    if (!usable || !view) return;
    const current = generation.current; const op = ++operation.current;
    controller.current?.abort(); const abort = new AbortController(); controller.current = abort;
    const active = () => current === generation.current && op === operation.current && !abort.signal.aborted;
    setBusy(true); setMessage("");
    try {
      if (action === "check") {
        setProof(null);
        if (!selected) throw new Error("Select an accepted closure record.");
        const result = await apiFetch<Proof>(path+"/recovery-evidence?policy_review_id="+encodeURIComponent(selected.grant.policy_review_id), { signal: abort.signal, cache: "no-store" });
        if (active()) setProof(result); return;
      }
      if (action === "review") {
        if (!confirmed || !canReview || !policy?.review_id) throw new Error("Independent human attestation and a reviewed policy are required.");
        if (!reviewIntent.current) {
          const expiry = new Date(expires);
          if (!Number.isFinite(expiry.getTime()) || expiry.getTime() <= now) throw new Error("Select a future expiry within the policy lifetime.");
          reviewIntent.current = { request_key: reviewKey.current, policy_review_id: policy.review_id, proof_basis: basis, proof_version: policy.proof_version,
            remediation_version_id: basis === "verified_remediation" ? versionId.trim() : null, independent_closure_authority_validated: true,
            acceptance_reference: reference.trim(), reason: reviewReason.trim(), max_lease_seconds: Number(maxLease), expires_at: expiry.toISOString() };
          setReviewPinned(true);
        }
        const result = await apiFetch<Grant>("/situation-closure-grants", { method: "POST", signal: abort.signal, body: JSON.stringify(reviewIntent.current) });
        if (!active()) return;
        setGrantId(result.id); setConfirmed(false); reviewIntent.current = null; setReviewPinned(false);
        reviewKey.current = "closure-grant-"+crypto.randomUUID(); setReference(""); setReviewReason("");
      } else if (action === "revoke") {
        if (!selected || !view.can_revoke_authority) throw new Error("Current independent revocation authority is required.");
        await apiFetch(`/situation-closure-grants/${encodeURIComponent(selected.grant.id)}/revoke`, { method: "POST", signal: abort.signal, body: JSON.stringify({ reason: revokeReason.trim() }) });
        if (active()) setRevokeReason("");
      } else if (action === "claim") {
        if (!canClaim || !selected) throw new Error("Fresh recovery, a usable record, an independent executor and enabled host gate are required.");
        if (!claimIntent.current) {
          claimIntent.current = { grant_id: selected.grant.id, request_key: "web-closure-"+crypto.randomUUID(), reason: reason.trim(),
            lease_seconds: Number(leaseSeconds), expected_epoch: view.history.ownership_epoch, proof_version: selected.grant.proof_version }; setIntentPinned(true);
        }
        const result = await apiFetch<ClaimResult>(path+"/closure-claims", { method: "POST", signal: abort.signal,
          body: JSON.stringify({ ...claimIntent.current, expected_epoch: view.history.ownership_epoch }) });
        if (!active()) return;
        secret.current = result.lease_token ?? null; setHasSecret(Boolean(secret.current)); setLease(closureLeaseMetadata(result));
        if (result.receipt) { setReceipt(result.receipt); secret.current = null; setHasSecret(false); }
        else if (!secret.current) setMessage("The existing attempt has no recoverable lease secret. No second token was issued. Recover a committed receipt, or wait for expiry and make an explicit fresh request.");
      } else if (action === "recover") {
        const requestId = lease?.request_id ?? (view.ownership?.owner_principal_id === identity?.principal_id ? view.ownership?.request_id : null);
        if (!requestId) throw new Error("No exact owned request is available to recover.");
        const result = await apiFetch<RequestDetail>(`/situation-closure-requests/${encodeURIComponent(requestId)}`, { signal: abort.signal, cache: "no-store" });
        if (!active()) return;
        setLease(closureLeaseMetadata(result)); setReceipt(result.receipt);
        if (result.receipt || result.state !== "claimed" || (lease && result.attempt_id !== lease.attempt_id)) { secret.current = null; setHasSecret(false); }
        setMessage(result.receipt ? "Recovered a historical committed receipt. No closure was replayed." : "Read-only recovery found no committed receipt. It neither finalized the request nor issued a token.");
      } else {
        if (!lease?.attempt_id || !secret.current || !leaseCurrent) throw new Error("This exact current attempt's transient secret is unavailable.");
        const result = await apiFetch<ClosureReceipt | ClaimResult>(`/situation-closure-requests/${encodeURIComponent(lease.request_id)}/${action}`, {
          method: "POST", signal: abort.signal, body: JSON.stringify({ attempt_id: lease.attempt_id, lease_token: secret.current }) });
        if (!active()) return;
        secret.current = null; setHasSecret(false);
        if (action === "finalize") { setReceipt(result as ClosureReceipt); setLease({ ...lease, state: "committed" }); }
        else setLease(closureLeaseMetadata(result as ClaimResult));
      }
      if (!active()) return;
      setProof(null);
      const result = await apiFetch<Workspace>(path+"/closure-workspace"+workspaceQuery.current, { signal: abort.signal, cache: "no-store" });
      if (active()) setView(result);
    } catch (cause) {
      if (active()) {
        setProof(null);
        if (cause instanceof APIError && [401, 403, 404].includes(cause.status)) { setView(null); setTitle(""); eraseLease(); }
        setMessage(cause instanceof Error ? cause.message : "Closure operation failed. Recover the exact request before retrying.");
      }
    } finally { if (active()) setBusy(false); }
  }

  return <main className="mx-auto w-full max-w-5xl space-y-5 p-4 pb-12 md:p-7">
    <nav aria-label="Situation context" className="flex flex-wrap gap-4 text-sm text-sky-700 underline">
      <Link href={`/situations/${encodeURIComponent(situationId)}`}>Back to Situation</Link><Link href={`${path}/recovery`}>Recovery policies and evidence</Link>
    </nav>
    <header><h1 className="text-2xl font-semibold">Reviewed Situation closure</h1><p className="mt-2 text-sm text-slate-600">{title || "Independent authority and exact incident ownership"}</p></header>
    <p className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm">Closure is a control-plane decision, not proof that a repair caused recovery or automatic physical truth. Catalog records and historical receipts grant no future permission.</p>
    {message && <p role="alert" className="break-words rounded-lg border border-red-200 p-3 text-sm text-red-700">{message}</p>}
    {loading && <p role="status">Loading selected namespace…</p>}
    {!loading && <Button variant="outline" disabled={busy} onClick={() => void load()}>Refresh current state</Button>}
    {view && <>
      <section className="space-y-3 rounded-xl border p-4">
        <h2 className="font-semibold">Current control state</h2>
        <p className="text-sm">Host gate: <strong>{view.host_enabled ? "Enabled" : "Disabled"}</strong>. This page cannot enable it. Every write revalidates current authority, sources and actions.</p>
        <p className="text-sm">Replacement closure v2: {view.replacement_closure_enabled ? "Enabled" : "Disabled"}. Historical recovery remains read-only when this gate is disabled.</p>
        {view.ownership ? <p className="break-words text-sm">Ownership epoch {view.ownership.epoch}: {view.ownership.state} · {view.ownership.owner_subject} · lease deadline {displayTime(view.ownership.lease_expires_at)}</p> : <p className="text-sm">No retained closure owner.</p>}
        {view.history.receipts.length > 0 && <p className="text-sm">Latest historical receipt {view.latest_receipt_matches_current_membership ? "matches the current membership identity" : "belongs to a different membership identity"}. This comparison is not fresh recovery proof.</p>}
        {view.catalog_truncated && <p className="text-sm text-amber-800">Discovery is incomplete: at most {view.policy_scan_limit} policy records and {view.grant_limit} grants were considered/displayed. Missing records are not proof that no authority exists.</p>}
        <details><summary className="cursor-pointer text-sm">Find an older exact scoped record</summary><div className="mt-3 space-y-2 text-sm">
          <label className="block">Exact grant ID<Input value={exactGrant} disabled={busy || intentPinned || reviewPinned} onChange={event => setExactGrant(event.target.value)} /></label>
          <label className="block">Exact policy request ID<Input value={exactPolicy} disabled={busy || intentPinned || reviewPinned} onChange={event => setExactPolicy(event.target.value)} /></label>
          <div className="flex flex-wrap gap-2"><Button variant="outline" disabled={!usable || intentPinned || reviewPinned || (!exactGrant && !exactPolicy)} onClick={() => {
            const query = new URLSearchParams(); if (exactGrant.trim()) query.set("grant_id", exactGrant.trim()); if (exactPolicy.trim()) query.set("policy_request_id", exactPolicy.trim());
            workspaceQuery.current = "?"+query.toString(); setGrantId(exactGrant.trim()); setPolicyId(exactPolicy.trim()); void load();
          }}>Find exact record</Button><Button variant="outline" disabled={busy || intentPinned || reviewPinned} onClick={() => {
            workspaceQuery.current = ""; setExactGrant(""); setExactPolicy(""); void load();
          }}>Return to bounded discovery</Button></div></div></details>
      </section>
      <section className="space-y-3 rounded-xl border p-4">
        <h2 className="font-semibold">Select independently accepted authority</h2>
        <label className="block text-sm">Closure grant<select className="mt-1 w-full rounded-md border bg-white p-2" value={grantId} disabled={busy || intentPinned} onChange={event => { setGrantId(event.target.value); setProof(null); }}>
          <option value="">Choose a scoped record</option>{view.grants.map(item => <option key={item.grant.id} value={item.grant.id}>{item.grant.proof_basis} · {item.grant.reviewer_subject} · {item.record_state} · {item.grant.id}</option>)}
        </select></label>
        {selected && <div className="space-y-2 break-words text-sm"><p>Proof v{selected.grant.proof_version} · record: {selected.record_state} · environment: {selected.evidence_environment} · expires {displayTime(selected.grant.expires_at)}</p>
          {!compatibleClosure && <p className="text-amber-800">This v2 record is retained for history. Replacement closure is disabled; it cannot be submitted as v1.</p>}
          <p>Independent reviewer: {selected.grant.reviewer_subject} · reference: {selected.grant.acceptance_reference}</p>
          <p>Current source, peer, semantic and action eligibility has not been validated by discovery.</p>
          {selected.revocation && <p>Revoked: {selected.revocation.reason}</p>}
          {!independentExecutor && <p className="text-amber-800">The authority reviewer cannot also execute closure.</p>}
          <Button variant="outline" disabled={!usable || !grantFresh} onClick={() => void run("check")}>Check fresh source recovery</Button></div>}
        {proof && <div role="status" className="space-y-1 rounded-lg border p-3 text-sm"><p>{proofFresh ? "Qualified source recovery within the current display deadline" : "Recovery unavailable or expired; check again"}</p>
          <p>{proof.member_count} members · {proof.evidence_environment} · production qualified: {String(proof.production_qualified)} · deadline {displayTime(proof.valid_until)}</p>
          <p>{proof.blockers.length ? proof.blockers.join(", ") : "This source check grants no closure permission and does not validate all related actions."}</p></div>}
      </section>
      <details className="rounded-xl border p-4"><summary className="cursor-pointer font-medium">Exact manual admission and recovery</summary>
        <div className="mt-4 space-y-3 text-sm">
          <p>AI uses the same separately governed closure path. Manual controls retain a token only in transient page memory. Reload, navigation or namespace changes discard it; they never issue a replacement token.</p>
          <label className="block">Closure reason<Input value={reason} disabled={busy || intentPinned} onChange={event => setReason(event.target.value)} /></label>
          <label className="block">Lease seconds<Input type="number" min={5} max={selected?.grant.max_lease_seconds ?? 120} value={leaseSeconds} disabled={busy || intentPinned} onChange={event => setLeaseSeconds(event.target.value)} /></label>
          <div className="flex flex-wrap gap-2"><Button disabled={!canClaim || reason.trim().length < 10} onClick={() => void run("claim")}>{intentPinned ? "Retry exact admission" : "Admit reviewed closure"}</Button>
            <Button variant="outline" disabled={!usable || liveOwnership || liveLease} onClick={() => { eraseLease(); setProof(null); }}>Start a fresh request</Button></div>
          {lease && <p className="break-words">Request {lease.request_id} · epoch {lease.epoch} · {lease.state} · deadline {displayTime(lease.lease_expires_at)} · transient secret {hasSecret ? "available only in memory" : "unavailable"}</p>}
          <div className="flex flex-wrap gap-2"><Button disabled={!usable || !view.host_enabled || !compatibleClosure || !view.can_request_closure || !hasSecret || !liveLease || !leaseCurrent} onClick={() => void run("finalize")}>Finalize reviewed closure</Button>
            <Button variant="outline" disabled={!usable || !hasSecret || !leaseCurrent} onClick={() => void run("release")}>Release exact attempt</Button>
            <Button variant="outline" disabled={!usable || !(lease?.request_id || view.ownership?.owner_principal_id === identity?.principal_id)} onClick={() => void run("recover")}>Recover exact request read-only</Button></div>
        </div>
      </details>
      <details className="rounded-xl border p-4"><summary className="cursor-pointer font-medium">Independent authority review and revocation</summary>
        <div className="mt-4 space-y-3 text-sm">
          <p>Review requires a persisted human with situations.closure.qualify and capabilities.read, independent of the policy author and, for remediation, the Tool authors/publishers. Revocation survives material-read withdrawal.</p>
          <label className="block">Candidate recovery policy<select className="mt-1 w-full rounded-md border bg-white p-2" value={policyId} disabled={busy || reviewPinned} onChange={event => {
            setPolicyId(event.target.value); setConfirmed(false); const value = view.policies.find(item => item.id === event.target.value);
            if (value) setExpires(localTime(new Date(Math.min(Date.now()+3600000, Date.parse(value.expires_at)))));
          }}><option value="">Choose reviewed sampling criteria</option>{view.policies.map(item => <option key={item.id} value={item.id}>{item.name} · {item.record_state} · {item.evidence_environment}</option>)}</select></label>
          {policy && <p>Proof v{policy.proof_version} · {policy.source_count} current sources · {policy.replacement_count} retired mappings · policy expires {displayTime(policy.expires_at)}. Candidate discovery is not a fresh qualification.</p>}
          <label className="block">Proof basis<select className="mt-1 w-full rounded-md border bg-white p-2" value={basis} disabled={busy || reviewPinned} onChange={event => { setBasis(event.target.value); setConfirmed(false); }}><option value="source_recovery">Observed source recovery</option><option value="verified_remediation">Structured verified remediation</option></select></label>
          {basis === "verified_remediation" && <label className="block">Exact published semantic Tool version ID<Input value={versionId} disabled={busy || reviewPinned} onChange={event => setVersionId(event.target.value)} /></label>}
          <div className="grid gap-3 sm:grid-cols-2"><label>Expiry in your local timezone<Input type="datetime-local" value={expires} disabled={busy || reviewPinned} onChange={event => setExpires(event.target.value)} /></label>
            <label>Maximum lease seconds<Input type="number" min={5} max={120} value={maxLease} disabled={busy || reviewPinned} onChange={event => setMaxLease(event.target.value)} /></label></div>
          <label className="block">Independent acceptance reference<Input value={reference} disabled={busy || reviewPinned} onChange={event => setReference(event.target.value)} /></label>
          <label className="block">Authority review reason<Input value={reviewReason} disabled={busy || reviewPinned} onChange={event => setReviewReason(event.target.value)} /></label>
          <label className="flex items-start gap-2"><input type="checkbox" className="mt-1" checked={confirmed} disabled={busy || reviewPinned} onChange={event => setConfirmed(event.target.checked)} />I independently validated this exact closure authority, separate from source evidence and physical-truth claims.</label>
          <div className="flex flex-wrap gap-2"><Button disabled={!canReview || !confirmed || reference.trim().length < 10 || reviewReason.trim().length < 10} onClick={() => void run("review")}>{reviewPinned ? "Retry exact authority review" : "Qualify independent authority"}</Button>
            <Button variant="outline" disabled={busy} onClick={() => { reviewIntent.current = null; setReviewPinned(false); setConfirmed(false); reviewKey.current = "closure-grant-"+crypto.randomUUID(); }}>New authority review intent</Button></div>
          <label className="block">Revocation reason<Input value={revokeReason} disabled={busy} onChange={event => setRevokeReason(event.target.value)} /></label>
          <Button variant="outline" disabled={!usable || !view.can_revoke_authority || !selected || selected.record_state === "revoked" || revokeReason.trim().length < 10} onClick={() => void run("revoke")}>Revoke selected authority</Button>
        </div>
      </details>
      <section className="space-y-3 rounded-xl border p-4"><h2 className="font-semibold">Historical closure receipts</h2>
        <p className="text-sm">These are durable past decisions, not current permission, fresh recovery, repair causality or automatically verified physical truth.</p>
        {view.history.truncated && <p className="text-sm text-amber-800">Receipt history is clipped; this page is not complete retained history.</p>}
        {receipt && !view.history.receipts.some(item => item.id === receipt.id) && <ReceiptSummary receipt={receipt} />}
        {view.history.receipts.map(item => <ReceiptSummary key={item.id} receipt={receipt?.id === item.id ? receipt : item} />)}
        {!receipt && !view.history.receipts.length && <p className="text-sm text-slate-600">No historical closure receipt in this bounded view.</p>}
      </section>
    </>}
  </main>;
}

function ReceiptSummary({ receipt }: { receipt: ClosureReceipt }) {
  const sources = receipt.proof?.recovery.source_evidence ?? []; const actions = receipt.proof?.related_actions ?? [];
  const summary = receipt.proof_summary;
  return <details className="rounded-lg border p-3 text-sm"><summary className="cursor-pointer break-words">Historical epoch {receipt.epoch} · {displayTime(receipt.committed_at)} · {summary?.proof_basis ?? receipt.proof?.proof_basis}</summary>
    <div className="mt-3 space-y-2 break-words"><p>Receipt {receipt.id} · {summary?.evidence_environment ?? receipt.proof?.evidence_environment} · owner {summary?.owner_subject ?? receipt.proof?.owner_subject} · reviewer {summary?.reviewer_subject ?? receipt.proof?.reviewer_subject}</p>
      <p>{summary?.member_count ?? receipt.proof?.recovery.member_count} historical members · {summary?.source_count ?? sources.length} source proofs · {summary?.related_action_count ?? actions.length} related action records</p>
      {receipt.summary_only && <p>Metadata summary only; full source/action proof was not loaded. Exact owned-request recovery reads one retained receipt.</p>}
      {sources.slice(0, 24).map((source, index) => <p key={`${source.source_id}-${index}`}>Source {source.source_id}: quiet sample {displayTime(source.quiet_observed_at)}</p>)}
      {actions.slice(0, 24).map(action => <p key={action.proposal_id}>Action {action.proposal_id}: {action.outcome}</p>)}
      {(sources.length > 24 || actions.length > 24) && <p>This summary clips source/action entries at 24 per group; the counts above disclose the retained proof size.</p>}
    </div></details>;
}
