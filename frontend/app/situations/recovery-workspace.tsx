"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";

type Identity = { principal_id: string | null; principal_type: string; permissions: string[] };
type Binding = { source_id: string; qualification_review_id: string };
type Detail = { situation: { title: string }; alerts: { alert_id: string; title: string; condition_source_id: string | null }[]; alerts_truncated: boolean };
type Policy = { request: { id: string; name: string; source_bindings: Binding[]; evidence_environment: string;
  min_quiet_samples: number; min_quiet_seconds: number; max_sample_gap_seconds: number; max_age_seconds: number;
  expires_at: string; validation_reference: string; author_subject: string };
  review: { id: string; reviewer_subject: string; acceptance_reference: string } | null;
  revocation: { reason: string } | null };
type Proof = { qualified_recovery: boolean; production_qualified: boolean; covers_situation: boolean;
  evidence_environment: string; evaluated_at: string; valid_until: string | null; member_count: number; blockers: string[];
  source_evidence: { source_id: string; current_alert_id: string; quiet_observed_at: string; quiet_window_start: string;
    quiet_sample_receipt_ids: string[]; members: { alert_id: string; active_receipt_id: string }[] }[] };

const localTime = (value: Date) => new Date(value.getTime() - value.getTimezoneOffset()*60000).toISOString().slice(0, 16);
const displayTime = (value: string | null) => value ? new Date(value).toLocaleString() : "Unavailable";

export default function RecoveryWorkspace({ situationId }: { situationId: string }) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [proof, setProof] = useState<Proof | null>(null);
  const [policyId, setPolicyId] = useState("");
  const [bindings, setBindings] = useState<Binding[]>([]);
  const [name, setName] = useState("Observed source recovery");
  const [requestKey, setRequestKey] = useState("");
  const [environment, setEnvironment] = useState("controlled_fixture");
  const [criteria, setCriteria] = useState({ samples: "2", duration: "60", gap: "60", age: "120" });
  const [expires, setExpires] = useState("");
  const [validation, setValidation] = useState("");
  const [reason, setReason] = useState("");
  const [acceptance, setAcceptance] = useState("");
  const [reviewReason, setReviewReason] = useState("");
  const [revokeReason, setRevokeReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const generation = useRef(0);
  const operation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const path = `/situations/${encodeURIComponent(situationId)}`;

  const invalidate = useCallback(() => {
    generation.current += 1; operation.current += 1; controller.current?.abort();
  }, []);
  const load = useCallback(async () => {
    const current = ++generation.current;
    controller.current?.abort(); const abort = new AbortController(); controller.current = abort;
    setLoading(true); setDetail(null); setIdentity(null); setPolicy(null); setProof(null); setBindings([]); setPolicyId("");
    try {
      const [data, user] = await Promise.all([apiFetch<Detail>(path, { signal: abort.signal }),
        apiFetch<Identity>("/auth/me", { signal: abort.signal })]);
      if (current !== generation.current) return;
      setDetail(data); setIdentity(user);
      setBindings([...new Set(data.alerts.flatMap(row => row.condition_source_id ? [row.condition_source_id] : []))]
        .slice(0, 64).map(source_id => ({ source_id, qualification_review_id: "" })));
    } catch (cause) {
      if (current === generation.current && !abort.signal.aborted) setMessage(cause instanceof Error ? cause.message : "Recovery workspace unavailable.");
    } finally { if (current === generation.current) setLoading(false); }
  }, [path]);
  useEffect(() => {
    function changed() {
      invalidate(); setBusy(false); setMessage(""); setConfirmed(false); setValidation(""); setReason("");
      setAcceptance(""); setReviewReason(""); setRevokeReason(""); setName("Observed source recovery");
      setEnvironment("controlled_fixture"); setRequestKey("recovery-"+crypto.randomUUID());
      setCriteria({ samples: "2", duration: "60", gap: "60", age: "120" });
      setExpires(localTime(new Date(Date.now()+3600000))); void load();
    }
    changed(); window.addEventListener("icheck:namespace-changed", changed); window.addEventListener("storage", changed);
    return () => { invalidate(); window.removeEventListener("icheck:namespace-changed", changed); window.removeEventListener("storage", changed); };
  }, [invalidate, load]);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  const human = Boolean(identity?.principal_id && identity.principal_type === "user");
  const permits = (permission: string) => Boolean(human && (identity?.permissions.includes("*") || identity?.permissions.includes(permission)));
  const canPropose = permits("alerts.manage") && permits("capabilities.read");
  const canReview = permits("situations.recovery.qualify") && permits("capabilities.read");
  const fresh = Boolean(proof?.valid_until && Number.isFinite(Date.parse(proof.valid_until)) && now < Date.parse(proof.valid_until));
  const usable = Boolean(detail && identity && !loading && !busy);

  async function run(action: "load" | "propose" | "review" | "revoke" | "check") {
    if (!usable) return;
    const current = generation.current; const op = ++operation.current;
    controller.current?.abort(); const abort = new AbortController(); controller.current = abort;
    setBusy(true); setMessage(""); setProof(null);
    try {
      if (action === "check") {
        if (!policy?.review || policy.revocation) throw new Error("Load a currently reviewed, non-revoked policy.");
        const result = await apiFetch<Proof>(path+"/recovery-evidence?policy_review_id="+encodeURIComponent(policy.review.id), { signal: abort.signal });
        if (current === generation.current && op === operation.current) setProof(result);
        return;
      }
      let requestId = policyId.trim();
      if (action === "propose") {
        const expiry = new Date(expires);
        if (!Number.isFinite(expiry.getTime()) || expiry.getTime() <= Date.now()) throw new Error("Select a future policy expiry.");
        const body = { request_key: requestKey.trim(), name: name.trim(), source_bindings: bindings,
          evidence_environment: environment, min_quiet_samples: Number(criteria.samples), min_quiet_seconds: Number(criteria.duration),
          max_sample_gap_seconds: Number(criteria.gap), max_age_seconds: Number(criteria.age), expires_at: expiry.toISOString(),
          validation_reference: validation.trim(), reason: reason.trim() };
        const result = await apiFetch<{ id: string }>("/situation-recovery-policies", { method: "POST", body: JSON.stringify(body), signal: abort.signal });
        if (current !== generation.current || op !== operation.current) return;
        requestId = result.id; setPolicyId(requestId);
      } else if (action === "review") {
        if (!policy || !confirmed) throw new Error("Explicit independent criteria validation is required.");
        requestId = policy.request.id;
        await apiFetch(`/situation-recovery-policies/${encodeURIComponent(requestId)}/review`, { method: "POST", signal: abort.signal,
          body: JSON.stringify({ independent_criteria_validated: true, acceptance_reference: acceptance.trim(), reason: reviewReason.trim() }) });
      } else if (action === "revoke") {
        if (!policy?.review) throw new Error("Load the reviewed policy first.");
        requestId = policy.request.id;
        await apiFetch(`/situation-recovery-policy-reviews/${encodeURIComponent(policy.review.id)}/revoke`, { method: "POST", signal: abort.signal,
          body: JSON.stringify({ reason: revokeReason.trim() }) });
      }
      if (current !== generation.current || op !== operation.current) return;
      if (!requestId) throw new Error("Enter a recovery policy request ID.");
      // Invalidate old material before loading a different policy. Failure is
      // never displayed alongside a stale successful recovery proof.
      setPolicy(null);
      const result = await apiFetch<Policy>(`/situation-recovery-policies/${encodeURIComponent(requestId)}`, { signal: abort.signal });
      if (current === generation.current && op === operation.current) {
        setPolicy(result); setConfirmed(false); setAcceptance(""); setReviewReason("");
      }
    } catch (cause) {
      if (current === generation.current && op === operation.current && !abort.signal.aborted) {
        setProof(null); setPolicy(null); setMessage(cause instanceof Error ? cause.message : "Recovery operation failed.");
      }
    } finally { if (current === generation.current && op === operation.current) setBusy(false); }
  }

  return <main className="mx-auto w-full max-w-5xl space-y-5 p-4 pb-12 md:p-7">
    <Link href={`/situations/${encodeURIComponent(situationId)}`} className="text-sm text-sky-700 underline">Back to Situation</Link>
    <header><h1 className="text-2xl font-semibold">Situation recovery evidence</h1>
      <p className="mt-2 text-sm text-slate-600">{detail?.situation.title ?? "Exact sources and reusable reviewed criteria"}</p></header>
    <p className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm">Observed source recovery is not incident closure authority, automatic physical truth or proof that a repair caused recovery. Independently reviewed closure has its own default-off control plane.</p>
    <Link href={`${path}/closure`} className="inline-block text-sm text-sky-700 underline">Open focused closure authority and historical receipts</Link>
    {message && <p role="alert" className="break-words rounded-lg border border-red-200 p-3 text-sm text-red-700">{message}</p>}
    {loading && <p role="status">Loading selected namespace…</p>}
    {detail && <section className="space-y-4 rounded-xl border p-4">
      <h2 className="font-semibold">Use a recovery policy</h2>
      <div className="flex flex-col gap-2 sm:flex-row"><label className="min-w-0 flex-1 text-sm">Policy request ID
        <Input value={policyId} disabled={loading || busy} onChange={event => { setPolicyId(event.target.value); setPolicy(null); setProof(null); }} /></label>
        <Button className="sm:self-end" variant="outline" disabled={!usable || !policyId.trim()} onClick={() => void run("load")}>Load policy</Button></div>
      {policy && <div className="space-y-2 text-sm">
        <h3 className="font-medium">{policy.request.name}</h3>
        <p>Environment: {policy.request.evidence_environment} · {policy.request.source_bindings.length} exact source generations</p>
        <p>{policy.request.min_quiet_samples} samples over at least {policy.request.min_quiet_seconds}s · gap at most {policy.request.max_sample_gap_seconds}s · latest age at most {policy.request.max_age_seconds}s</p>
        <p>Expires {displayTime(policy.request.expires_at)}</p>
        <p className="break-words">Author: {policy.request.author_subject} · Validation: {policy.request.validation_reference}</p>
        <p className="break-words">{policy.revocation ? "Revoked: "+policy.revocation.reason : policy.review ? "Accepted by "+policy.review.reviewer_subject : "Independent acceptance pending"}</p>
        <Button disabled={!usable || !identity?.principal_id || !policy.review || Boolean(policy.revocation) || now >= Date.parse(policy.request.expires_at)} onClick={() => void run("check")}>Check every Situation member</Button>
      </div>}
    </section>}
    {proof && <section aria-label="Recovery proof" className="space-y-3 rounded-xl border p-4">
      <h2 className="font-semibold">{proof.qualified_recovery && fresh ? "Qualified observed recovery" : proof.qualified_recovery ? "Recovery evidence expired" : "Recovery requirements not met"}</h2>
      <p className="text-sm">{proof.member_count} members · {proof.covers_situation ? "Complete membership coverage" : "Incomplete coverage"} · {proof.evidence_environment}</p>
      <p className="text-sm">Checked {displayTime(proof.evaluated_at)} · Valid until {displayTime(proof.valid_until)}</p>
      {!proof.production_qualified && <p className="text-sm text-amber-800">Not production-qualified evidence.</p>}
      {!fresh && proof.qualified_recovery && <p role="alert" className="text-sm text-amber-800">Run a new check; this historical result cannot authorize current work.</p>}
      {proof.blockers.length > 0 && <ul className="list-inside list-disc text-sm text-red-700">{proof.blockers.map(item => <li key={item}>{item.replaceAll("_", " ")}</li>)}</ul>}
      <details><summary className="cursor-pointer text-sm font-medium">Exact source and episode evidence</summary>
        <div className="mt-3 space-y-3">{proof.source_evidence.map(item => <div key={item.source_id} className="min-w-0 rounded-lg bg-slate-50 p-3 text-sm">
          <Link className="break-all text-sky-700 underline" href={`/assets/condition-sources/${encodeURIComponent(item.source_id)}`}>{item.source_id}</Link>
          <p>{item.members.length} episodes · {item.quiet_sample_receipt_ids.length} accepted quiet samples</p>
          <p>Window {displayTime(item.quiet_window_start)} to {displayTime(item.quiet_observed_at)}</p>
          <ul className="mt-2 space-y-1 text-xs">{item.members.map(member => <li className="break-all" key={member.alert_id}>Alert {member.alert_id} · Active receipt {member.active_receipt_id}</li>)}</ul>
        </div>)}</div>
      </details>
    </section>}
    {detail && <details className="rounded-xl border p-4"><summary className="cursor-pointer font-medium">Author a reusable recovery policy</summary>
      <div className="mt-4 space-y-4">
        <p className="text-sm text-slate-600">Bind independently accepted exact source generations. Unsupported or omitted Situation members always block qualification. Credential or identity rotation cannot inherit acceptance.</p>
        {detail.alerts_truncated && <p role="alert" className="text-sm text-amber-800">The Situation preview is truncated. Suggested bindings are incomplete; the server still checks the entire bounded membership set.</p>}
        {!canPropose && <p className="text-sm text-amber-800">A persisted human with alerts.manage and capabilities.read is required to propose criteria.</p>}
        <div className="grid gap-3 sm:grid-cols-2"><label className="text-sm">Policy name<Input value={name} onChange={event => setName(event.target.value)} /></label>
          <label className="text-sm">Request key<Input value={requestKey} onChange={event => setRequestKey(event.target.value)} /></label></div>
        <div className="space-y-3">{bindings.map((binding, index) => <div key={index} className="space-y-2 rounded-lg border p-3">
          <label className="block text-sm">Exact source ID<Input value={binding.source_id} onChange={event => setBindings(rows => rows.map((row, i) => i === index ? { ...row, source_id: event.target.value } : row))} /></label>
          <label className="block text-sm">Source qualification review ID<Input value={binding.qualification_review_id} onChange={event => setBindings(rows => rows.map((row, i) => i === index ? { ...row, qualification_review_id: event.target.value } : row))} /></label>
          <div className="flex flex-wrap gap-3 text-sm"><Link className="text-sky-700 underline" href={`/assets/condition-sources/${encodeURIComponent(binding.source_id)}`}>Inspect source acceptance</Link>
            <button type="button" className="text-red-700 underline" onClick={() => setBindings(rows => rows.filter((_, i) => i !== index))}>Remove binding {index+1}</button></div>
        </div>)}</div>
        <Button variant="outline" disabled={bindings.length >= 64} onClick={() => setBindings(rows => [...rows, { source_id: "", qualification_review_id: "" }])}>Add exact source binding</Button>
        <div className="grid gap-3 sm:grid-cols-2"><label className="text-sm">Evidence environment<select className="mt-1 h-9 w-full rounded-md border px-2" value={environment} onChange={event => setEnvironment(event.target.value)}>
          <option value="controlled_fixture">Controlled fixture</option><option value="live_lab">Live lab</option><option value="production">Production</option></select></label>
          <label className="text-sm">Expiry<Input type="datetime-local" value={expires} onChange={event => setExpires(event.target.value)} /></label></div>
        <div className="grid gap-3 sm:grid-cols-2">{([["samples", "Minimum quiet samples"], ["duration", "Minimum quiet seconds"], ["gap", "Maximum sample gap seconds"], ["age", "Maximum latest age seconds"]] as const).map(([key, label]) =>
          <label key={key} className="text-sm">{label}<Input type="number" min={key === "samples" ? 2 : 1} max={key === "samples" ? 128 : 86400} value={criteria[key]} onChange={event => setCriteria(value => ({ ...value, [key]: event.target.value }))} /></label>)}</div>
        <label className="block text-sm">Validation reference<Input value={validation} onChange={event => setValidation(event.target.value)} /></label>
        <label className="block text-sm">Proposal reason<Input value={reason} onChange={event => setReason(event.target.value)} /></label>
        <Button disabled={!usable || !canPropose} onClick={() => void run("propose")}>Propose recovery criteria</Button>
      </div>
    </details>}
    {policy && <details className="rounded-xl border p-4"><summary className="cursor-pointer font-medium">Independent review and revocation</summary>
      <div className="mt-4 space-y-3">
        {!canReview && <p className="text-sm text-amber-800">Independent acceptance requires a persisted human with situations.recovery.qualify and capabilities.read. Revocation does not require material-read access.</p>}
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />I independently validated these exact sources and recovery criteria.</label>
        <label className="block text-sm">Acceptance reference<Input value={acceptance} onChange={event => setAcceptance(event.target.value)} /></label>
        <label className="block text-sm">Review reason<Input value={reviewReason} onChange={event => setReviewReason(event.target.value)} /></label>
        <Button disabled={!usable || !canReview || !confirmed || Boolean(policy.review) || Boolean(policy.revocation)} onClick={() => void run("review")}>Accept reviewed criteria</Button>
        <label className="block text-sm">Revocation reason<Input value={revokeReason} onChange={event => setRevokeReason(event.target.value)} /></label>
        <Button variant="outline" disabled={!usable || !permits("situations.recovery.qualify") || !policy.review || Boolean(policy.revocation)} onClick={() => void run("revoke")}>Revoke policy acceptance</Button>
      </div>
    </details>}
  </main>;
}
