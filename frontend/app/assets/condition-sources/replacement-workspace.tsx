"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";
import { rememberReplacement, replacementCanApply, replacementCanReview, replacementIntentMatches,
  type ReplacementDetail as Detail, type ReplacementIntent, type ReplacementSummary as Summary } from "@/lib/source-replacement";

type Source = { source_id: string; condition_key: string; entity_type: string; entity_id: string; deployment_id: string;
  definition: Record<string, unknown>; logical_state: string; observed_at: string | null; retirement_id: string | null };
type Qualification = { source_id: string; review_id: string | null; reviewer_subject: string | null; evidence_environment: string; expires_at: string; revoked: boolean };
type Workspace = { old_source: Source; new_source: Source | null; candidates: Source[]; candidates_truncated: boolean;
  qualifications: Qualification[]; qualifications_truncated: boolean; requests: Summary[]; requests_truncated: boolean;
  host_enabled: boolean; can_propose: boolean; can_review: boolean; can_revoke: boolean; can_apply: boolean };
type Receipt = { id: string; request_id: string; old_source_id: string; new_source_id: string; created_at: string; [key: string]: unknown };
type Identity = { principal_id: string | null; subject: string; principal_type: string };

function localTime(value: Date) { return new Date(value.getTime()-value.getTimezoneOffset()*60000).toISOString().slice(0,16); }
function time(value: string | null) { return value ? new Date(value).toLocaleString() : "Not observed"; }

export default function SourceReplacementWorkspace({ sourceId }: { sourceId: string }) {
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [newId, setNewId] = useState("");
  const [exactTarget, setExactTarget] = useState("");
  const [requestId, setRequestId] = useState("");
  const [detail, setDetail] = useState<Detail | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [oldReview, setOldReview] = useState("");
  const [newReview, setNewReview] = useState("");
  const [environment, setEnvironment] = useState("controlled_fixture");
  const [validation, setValidation] = useState("");
  const [proposalReason, setProposalReason] = useState("");
  const [acceptance, setAcceptance] = useState("");
  const [reviewReason, setReviewReason] = useState("");
  const [revokeReason, setRevokeReason] = useState("");
  const [applyReason, setApplyReason] = useState("");
  const [expiry, setExpiry] = useState(() => localTime(new Date(Date.now()+3600000)));
  const [key, setKey] = useState(() => "replacement-"+crypto.randomUUID());
  const [confirmations, setConfirmations] = useState([false,false,false]);
  const [confirmApply, setConfirmApply] = useState(false);
  const [confirmHistorical, setConfirmHistorical] = useState(false);
  const [pending, setPending] = useState<ReplacementIntent | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const generation = useRef(0);
  const operation = useRef(0);
  const abort = useRef<AbortController | null>(null);
  const base = `/collector-condition-sources/${encodeURIComponent(sourceId)}`;
  const invalidate = useCallback(() => { generation.current++; operation.current++; abort.current?.abort(); }, []);

  const load = useCallback(async () => {
    const current = ++generation.current;
    abort.current?.abort(); const controller = new AbortController(); abort.current = controller;
    setLoading(true); setWorkspace(null); setIdentity(null); setDetail(null); setReceipt(null);
    try {
      const [data, user] = await Promise.all([
        apiFetch<Workspace>(base+"/replacement-workspace"+(newId ? "?"+new URLSearchParams({new_source_id:newId}) : ""), {signal:controller.signal}),
        apiFetch<Identity>("/auth/me", {signal:controller.signal}),
      ]);
      if (current !== generation.current) return;
      setWorkspace(data); setIdentity(user);
    } catch (cause) { if (current === generation.current && !controller.signal.aborted) setMessage(cause instanceof Error ? cause.message : "Replacement discovery failed."); }
    finally { if (current === generation.current) setLoading(false); }
  }, [base,newId]);

  useEffect(() => {
    let cancelled = false;
    void Promise.resolve().then(() => { if (!cancelled) return load(); });
    return () => { cancelled = true; invalidate(); };
  }, [load,invalidate]);
  useEffect(() => {
    function changed() {
      generation.current++; operation.current++; abort.current?.abort();
      setWorkspace(null); setIdentity(null); setDetail(null); setReceipt(null); setPending(null); setBusy(false);
      setNewId(""); setExactTarget(""); setRequestId(""); setOldReview(""); setNewReview("");
      setValidation(""); setProposalReason(""); setAcceptance(""); setReviewReason(""); setRevokeReason(""); setApplyReason("");
      setConfirmations([false,false,false]); setConfirmApply(false); setConfirmHistorical(false); setMessage("");
      setEnvironment("controlled_fixture"); setExpiry(localTime(new Date(Date.now()+3600000)));
      setKey("replacement-"+crypto.randomUUID()); void load();
    }
    window.addEventListener("icheck:namespace-changed", changed); window.addEventListener("storage", changed);
    return () => { window.removeEventListener("icheck:namespace-changed", changed); window.removeEventListener("storage", changed); };
  }, [load]);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 5000);
    return () => window.clearInterval(timer);
  }, []);

  function remember(detail: Detail) {
    setWorkspace(value => {
      if (!value) return value;
      const retained = rememberReplacement(value.requests, detail);
      return {...value, requests:retained.requests, requests_truncated:value.requests_truncated||retained.truncated};
    });
  }

  async function inspect(id = requestId) {
    if (!id || busy || loading) return;
    const current = generation.current; const op = ++operation.current;
    setBusy(true); setDetail(null); setReceipt(null); setMessage(""); setConfirmations([false,false,false]); setConfirmApply(false);
    try {
      const data = await apiFetch<Detail>(`/source-replacement-requests/${encodeURIComponent(id)}`);
      if (current !== generation.current || op !== operation.current) return;
      if (data.request.old_source_id !== sourceId) throw new Error("This request belongs to another old generation.");
      setDetail(data); setRequestId(data.request.id); remember(data);
    } catch (cause) { if (current === generation.current && op === operation.current) setMessage(cause instanceof Error ? cause.message : "Request unavailable."); }
    finally { if (op === operation.current) setBusy(false); }
  }

  async function mutate(action: "propose" | "review" | "revoke" | "apply") {
    if (!workspace || busy || loading) return;
    const current = generation.current; const op = ++operation.current;
    let url: string; let body: Record<string,unknown>;
    if (action === "propose") {
      const at = new Date(expiry);
      if (!newId || !oldReview || !newReview || validation.trim().length<10 || proposalReason.trim().length<10 || !Number.isFinite(at.getTime()) || at.getTime()<=Date.now()
        || (workspace.old_source.retirement_id && !confirmHistorical)) { setMessage("Select both source acceptances and a future expiry; provide validation and reason. Retired history needs explicit revalidation consent."); return; }
      url = "/source-replacement-requests";
      body = {old_source_id:sourceId,new_source_id:newId,old_qualification_review_id:oldReview,new_qualification_review_id:newReview,
        request_key:key,evidence_environment:environment,validation_reference:validation.trim(),reason:proposalReason.trim(),expires_at:at.toISOString(),
        prior_retirement_id:workspace.old_source.retirement_id};
    } else {
      if (!detail || detail.request.id !== requestId) return;
      if (action === "review") {
        if (!confirmations.every(Boolean) || acceptance.trim().length<10 || reviewReason.trim().length<10) {setMessage("Provide all independent attestations, acceptance reference and reason.");return;}
        url = `/source-replacement-requests/${encodeURIComponent(requestId)}/review`;
        body = {independent_semantics_validated:true,independent_identity_validated:true,independent_clock_validated:true,acceptance_reference:acceptance.trim(),reason:reviewReason.trim()};
      } else if (action === "revoke") {
        if (!detail.review || revokeReason.trim().length<10) {setMessage("Provide a revocation reason of at least ten characters.");return;}
        url = `/source-replacement-reviews/${encodeURIComponent(detail.review.id)}/revoke`; body = {reason:revokeReason.trim()};
      } else {
        if (!confirmApply || applyReason.trim().length<10) {setMessage("Confirm permanent cutover and provide an execution reason.");return;}
        const intent = pending ?? {requestId,executionKey:"web-replacement-"+crypto.randomUUID(),reason:applyReason.trim()};
        if (!replacementIntentMatches(intent,requestId,applyReason)) {setMessage("An uncertain execution is bound to the original request and reason. Recover its receipt or retry that exact intent.");return;}
        setPending(intent); url = `/source-replacement-requests/${encodeURIComponent(intent.requestId)}/apply`;
        body = {execution_key:intent.executionKey,reason:intent.reason};
      }
    }
    setBusy(true); setMessage("");
    try {
      const result = await apiFetch<Record<string,unknown>>(url,{method:"POST",body:JSON.stringify(body)});
      if (current !== generation.current || op !== operation.current) return;
      setConfirmations([false,false,false]); setConfirmApply(false);
      if (action === "apply") {
        setReceipt(result as Receipt);setPending(null);
        setDetail(value => value ? {...value,retirement_id:String(result.id),producer_cutover_performed:true} : null);
        setWorkspace(value => value ? {...value,old_source:{...value.old_source,retirement_id:String(result.id)},
          requests:value.requests.map(row => row.request_id===requestId ? {...row,retirement_id:String(result.id)} : row)} : null);
        setMessage("Permanent control-plane cutover recorded. Measured history is unchanged; no incident closure or physical operation occurred.");
        // A confirmed receipt is durable history even if the following metadata
        // read fails. Never turn that failure into a new uncertain intent.
        try {
          const updated = await apiFetch<Detail>(`/source-replacement-requests/${encodeURIComponent(requestId)}`);
          if (current !== generation.current || op !== operation.current) return;
          setDetail(updated); remember(updated);
        } catch {
          if (current === generation.current && op === operation.current) setMessage("Cutover is confirmed by the retained receipt. Current mapping metadata could not be refreshed; refresh or read the receipt without replaying cutover.");
        }
      }
      else {
        const id = action === "propose" ? String(result.id) : requestId;
        const updated = await apiFetch<Detail>(`/source-replacement-requests/${encodeURIComponent(id)}`);
        if (current !== generation.current || op !== operation.current) return;
        setRequestId(id);setDetail(updated);remember(updated);setKey("replacement-"+crypto.randomUUID());
        setMessage(action === "revoke" ? "Future mapping authority revoked. Any completed retirement remains permanent." : "Recorded. Acceptance is separate from cutover and incident closure.");
      }
    } catch (cause) { if (current === generation.current && op === operation.current) setMessage((cause instanceof Error ? cause.message : "Operation failed.")+(action === "apply" ? " If the response was lost, retry this exact intent or refresh and open the retained receipt." : "")); }
    finally { if (op === operation.current) setBusy(false); }
  }

  async function recover() {
    if (!detail?.retirement_id || busy || loading) return;
    const current = generation.current; const op = ++operation.current; setBusy(true); setReceipt(null);
    try { const value = await apiFetch<Receipt>(`/source-retirements/${encodeURIComponent(detail.retirement_id)}`);
      if (current === generation.current && op === operation.current) {setReceipt(value);setPending(null);setMessage("Historical receipt recovered without replaying cutover.");} }
    catch (cause) {if (current === generation.current && op === operation.current) setMessage(cause instanceof Error ? cause.message : "Receipt unavailable.");}
    finally {if (op === operation.current) setBusy(false);}
  }
  const applyAllowed = Boolean(workspace && detail && replacementCanApply({hostEnabled:workspace.host_enabled,canApply:workspace.can_apply,
    reviewId:detail.review?.id??null,revoked:detail.revocation!==null,retirementId:detail.retirement_id,
    priorRetirementId:detail.request.prior_retirement_id,expiresAt:detail.request.expires_at,
    executorIndependent:Boolean(identity?.principal_id&&detail.review?.reviewer_principal_id&&identity.principal_id!==detail.review.reviewer_principal_id)},now));
  const reviewAllowed = Boolean(workspace && detail && replacementCanReview({canReview:workspace.can_review,
    principalId:identity?.principal_id??null,authorPrincipalId:detail.request.author_principal_id,expiresAt:detail.request.expires_at},now));
  return <main className="mx-auto max-w-5xl space-y-6 px-4 py-8 text-sm sm:px-8">
    <Link className="text-sky-700 underline" href={`/assets/condition-sources/${encodeURIComponent(sourceId)}`}>Back to source qualification</Link>
    <header><h1 className="text-2xl font-semibold">Evolve a Collector source</h1><p className="mt-2 text-slate-600">Propose, independently review, then explicitly retire an old generation. This is control-plane orchestration, not a physical device change.</p></header>
    <p className="rounded border border-amber-200 bg-amber-50 p-4">Retirement is permanent. Original measurements remain historical. Neither replacement nor a quiet target authorizes incident closure or proves a repair.</p>
    {message && <p role="status" className="break-words rounded border p-3">{message}</p>}
    <Button variant="outline" disabled={busy||loading} onClick={() => void load()}>Refresh scoped discovery</Button>
    {loading && <p role="status">Loading exact source generations…</p>}
    {workspace && <>
      <section className="space-y-3 rounded border p-4"><h2 className="text-lg font-semibold">Choose the target generation</h2>
        <p className="break-all">Old source {sourceId}: {workspace.old_source.logical_state} · observed {time(workspace.old_source.observed_at)}{workspace.old_source.retirement_id ? " · permanently retired" : ""}</p>
        <label className="block">Target generation<select aria-label="Target generation" className="mt-1 w-full rounded border p-2" disabled={busy||Boolean(pending)} value={newId} onChange={event => {setNewId(event.target.value);setRequestId("");setOldReview("");setNewReview("");}}>
          <option value="">Select another generation of the same entity</option>{workspace.candidates.map(row => <option key={row.source_id} value={row.source_id}>{row.source_id} · {row.logical_state}{row.retirement_id ? " · retired" : ""}</option>)}
          {workspace.new_source&&!workspace.candidates.some(row=>row.source_id===newId)&&<option value={newId}>{newId} · exact loaded target</option>}</select></label>
        <label className="block">Exact target source ID (for omitted generations)<Input value={exactTarget} disabled={busy||Boolean(pending)} onChange={event => setExactTarget(event.target.value)} /></label>
        <Button variant="outline" disabled={busy||Boolean(pending)||exactTarget.length!==36} onClick={() => {setRequestId("");setNewId(exactTarget);}}>Load exact target</Button>
        {workspace.new_source && <p className="break-all">Target {workspace.new_source.source_id}: {workspace.new_source.logical_state} · observed {time(workspace.new_source.observed_at)}</p>}
        <p>Discovery is record metadata, not validated current authority. Execution rechecks all clocks, source ownership, roles and peer scopes.</p>
        {workspace.candidates_truncated && <p role="status">Candidate list is truncated. Load an exact source ID to inspect an omitted generation.</p>}
      </section>
      <details className="rounded border p-4"><summary className="cursor-pointer font-semibold">Propose equivalent source generations</summary><div className="mt-4 space-y-3">
        {[{label:"Old source acceptance",id:sourceId,value:oldReview,set:setOldReview},{label:"Target source acceptance",id:newId,value:newReview,set:setNewReview}].map(field => <fieldset className="space-y-2" key={field.label}><legend>{field.label}</legend><select aria-label={field.label} className="mt-1 w-full rounded border p-2" value={field.value} onChange={event => field.set(event.target.value)}><option value="">Select independent acceptance</option>{workspace.qualifications.filter(row => row.source_id===field.id&&row.review_id&&!row.revoked).map(row => <option key={row.review_id} value={row.review_id!}>{row.reviewer_subject} · {row.evidence_environment} · expires {time(row.expires_at)}</option>)}</select>
          <label className="block">Exact accepted review ID (for omitted records)<Input aria-label={field.label+" exact ID"} value={field.value} maxLength={36} onChange={event=>field.set(event.target.value)} /></label></fieldset>)}
        {workspace.qualifications_truncated && <p role="status">Qualification list is truncated. Exact source qualification history remains available from each source page.</p>}
        <label className="block">Evidence environment<select aria-label="Evidence environment" className="mt-1 w-full rounded border p-2" value={environment} onChange={event => setEnvironment(event.target.value)}><option value="controlled_fixture">Controlled fixture</option><option value="live_lab">Live lab</option><option value="production">Production</option></select></label>
        <label className="block">External validation reference<Input value={validation} maxLength={1024} onChange={event => setValidation(event.target.value)} /></label>
        <label className="block">Proposal reason<Input value={proposalReason} maxLength={512} onChange={event => setProposalReason(event.target.value)} /></label>
        <label className="block">Mapping expiry (local time)<Input type="datetime-local" value={expiry} onChange={event => setExpiry(event.target.value)} /></label>
        {workspace.old_source.retirement_id && <label className="flex gap-2"><input type="checkbox" checked={confirmHistorical} onChange={event => setConfirmHistorical(event.target.checked)} />I am revalidating historical equivalence against the exact original permanent retirement. This cannot retire the old source again.</label>}
        <Button disabled={!workspace.can_propose||!newId||busy||Boolean(pending)} onClick={() => void mutate("propose")}>Record mapping proposal</Button>
      </div></details>
      <section className="space-y-3 rounded border p-4"><h2 className="text-lg font-semibold">Inspect an exact mapping</h2>
        <label className="block">Known requests<select aria-label="Known requests" className="mt-1 w-full rounded border p-2" disabled={busy||Boolean(pending)} value={requestId} onChange={event => {setRequestId(event.target.value);setDetail(null);setConfirmations([false,false,false]);setConfirmApply(false);}}><option value="">Select a retained mapping</option>{workspace.requests.map(row => <option key={row.request_id} value={row.request_id}>{row.author_subject} → {row.new_source_id}{row.retirement_id ? " · cutover recorded" : row.revoked ? " · revoked" : row.review_id ? " · accepted record" : " · pending review"}</option>)}</select></label>
        <label className="block">Exact request ID<Input value={requestId} disabled={busy||Boolean(pending)} onChange={event => {setRequestId(event.target.value);setDetail(null);}} /></label>
        <Button variant="outline" disabled={busy||requestId.length!==36} onClick={() => void inspect()}>Inspect exact retained material</Button>
        {workspace.requests_truncated && <p role="status">History is truncated. Load an exact request ID; omitted records are not covered here.</p>}
        {detail && <div className="space-y-3">
          <p className="break-all">{detail.request.old_source_id} → {detail.request.new_source_id} · {detail.request.evidence_environment} · expires {time(detail.request.expires_at)}</p>
          <p className="break-words">Validation: {detail.request.validation_reference}</p>
          <details><summary className="cursor-pointer text-sky-700">Exact proposed semantics, identity and sealed provenance</summary><pre role="region" aria-label={`Source replacement proposal ${detail.request.id}`} tabIndex={0} className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#5856d6]">{JSON.stringify(detail.request.snapshot,null,2)}</pre></details>
          {detail.review && <p className="break-words">Reviewed by {detail.review.reviewer_subject}: {detail.review.acceptance_reference}{detail.revocation ? " · revoked" : ""}</p>}
          {!detail.review && <details><summary className="cursor-pointer font-semibold">Independent human acceptance</summary><div className="mt-3 space-y-3">
            <p>The reviewer must differ from the mapping author and both Collectors’ authors, validators and publishers. These are external human attestations, not automatic verification.</p>
            {["I independently validated equivalent condition semantics.","I independently validated both exact source identities.","I independently validated observation-clock controls."].map((label,index) => <label key={label} className="flex gap-2"><input type="checkbox" checked={confirmations[index]} onChange={event => setConfirmations(values => values.map((value,i) => i===index?event.target.checked:value))} />{label}</label>)}
            <label className="block">Acceptance reference<Input value={acceptance} maxLength={1024} onChange={event => setAcceptance(event.target.value)} /></label>
            <label className="block">Review reason<Input value={reviewReason} maxLength={512} onChange={event => setReviewReason(event.target.value)} /></label>
            <Button disabled={!reviewAllowed||!confirmations.every(Boolean)||busy||Boolean(pending)} onClick={() => void mutate("review")}>Accept independently validated mapping</Button>
          </div></details>}
          {detail.review && <details><summary className="cursor-pointer font-semibold">Withdraw future mapping authority</summary><div className="mt-3 space-y-3">
            <label className="block">Revocation reason<Input value={revokeReason} maxLength={512} onChange={event => setRevokeReason(event.target.value)} /></label>
            <Button variant="outline" disabled={!workspace.can_revoke||Boolean(detail.revocation)||busy||Boolean(pending)} onClick={() => void mutate("revoke")}>Revoke acceptance</Button>
          </div></details>}
          <div className="space-y-3 rounded border p-3"><h3 className="font-semibold">Explicit permanent cutover</h3>
            <p>Host gate: {workspace.host_enabled ? "enabled" : "disabled"}. The executor must differ from the human reviewer. A historical revalidation cannot replace the original retirement.</p>
            <label className="block">Execution reason<Input value={pending?.reason??applyReason} disabled={Boolean(pending)||busy} maxLength={512} onChange={event => setApplyReason(event.target.value)} /></label>
            <label className="flex gap-2"><input type="checkbox" checked={confirmApply} onChange={event => setConfirmApply(event.target.checked)} />I confirm permanent source retirement with preserved measurements and no incident closure.</label>
            <Button disabled={busy||!confirmApply||(!pending&&!applyAllowed)} onClick={() => void mutate("apply")}>{pending ? "Retry exact uncertain execution" : "Apply reviewed cutover"}</Button>
            {pending && <p role="status">The original request, reason and execution key remain pinned. Refresh and inspect this mapping to recover a committed receipt; do not create another intent after a lost response.</p>}
            {detail.retirement_id && <Button variant="outline" disabled={busy} onClick={() => void recover()}>Read retained cutover receipt</Button>}
          </div>
        </div>}
      </section>
    </>}
    {receipt && <section className="space-y-2 rounded border p-4"><h2 className="text-lg font-semibold">Historical cutover receipt</h2><p className="break-all">{receipt.id} · recorded {time(receipt.created_at)}</p><p>Read-only history. No future execution or incident-closure authority.</p><details><summary className="cursor-pointer text-sky-700">Exact retained receipt</summary><pre role="region" aria-label={`Source retirement receipt ${receipt.id}`} tabIndex={0} className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#5856d6]">{JSON.stringify(receipt,null,2)}</pre></details></section>}
  </main>;
}
