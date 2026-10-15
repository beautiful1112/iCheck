"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";
import RollbackQualification from "./rollback-qualification";

type Policy = { id: string; name: string; review_sha256: string | null; target_site: string; expires_at: string };
type Qualification = { ready: boolean; quality_policy_id: string | null; assessment_id: string | null; valid_until: string | null; matching_samples: number; required_samples: number | null; reason: string | null };
type Grant = { id: string; policy_review_sha256: string; granted_by: string; expires_at: string; acceptance_reference: string };
type Grants = { items: Grant[]; execution_enabled: boolean };

function localTime(date: Date) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export default function ExecutionQualification({ policy, deviceName, onClose }: {
  policy: Policy; deviceName: string; onClose: () => void;
}) {
  const [qualification, setQualification] = useState<Qualification | null>(null);
  const [grants, setGrants] = useState<Grants | null>(null);
  const [reference, setReference] = useState("");
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [expires, setExpires] = useState(() => localTime(new Date(Math.min(Date.now() + 86400000, Date.parse(policy.expires_at)))));
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const generation = useRef(0);

  const load = useCallback(async () => {
    const current = ++generation.current;
    setLoading(true); setQualification(null); setGrants(null);
    try {
      const [nextQualification, nextGrants] = await Promise.all([
        apiFetch<Qualification>(`/agent/change-preapprovals/${policy.id}/execution-qualification`),
        apiFetch<Grants>(`/agent/change-preapprovals/${policy.id}/execution-grants`),
      ]);
      if (current !== generation.current) return;
      setQualification(nextQualification); setGrants(nextGrants);
    } catch (cause) {
      if (current === generation.current) setMessage(cause instanceof Error ? cause.message : "Unable to read execution qualification.");
    } finally { if (current === generation.current) setLoading(false); }
  }, [policy.id]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    const currentGeneration = generation;
    return () => { window.clearTimeout(timer); window.clearInterval(clock); ++currentGeneration.current; };
  }, [load]);

  const existing = grants?.items.find((grant) => grant.policy_review_sha256 === policy.review_sha256);
  const evidenceCurrent = Boolean(qualification?.ready && qualification.valid_until && Date.parse(qualification.valid_until) > now);

  async function qualify() {
    if (!evidenceCurrent || !qualification?.quality_policy_id || !qualification.assessment_id) return;
    if (!confirmed || reason.trim().length < 10 || reference.trim().length < 10) {
      setMessage("Confirm your independent validation and provide the acceptance reference and audit reason."); return;
    }
    const expiry = new Date(expires);
    if (!Number.isFinite(expiry.getTime()) || expiry.getTime() <= Date.now() || expiry.getTime() > Date.parse(policy.expires_at)) {
      setMessage("Choose a future expiry within this policy's expiry."); return;
    }
    const current = generation.current;
    setBusy(true); setMessage("");
    try {
      await apiFetch(`/agent/change-preapprovals/${policy.id}/execution-grants`, {
        method: "POST", body: JSON.stringify({ expected_policy_review_sha256: policy.review_sha256,
          quality_policy_id: qualification.quality_policy_id, expected_assessment_id: qualification.assessment_id,
          independent_validation_confirmed: true, acceptance_reference: reference.trim(),
          expires_at: expiry.toISOString(), reason: reason.trim() }),
      });
      if (current !== generation.current) return;
      setConfirmed(false); setMessage("Execution grant recorded. Every action still needs current evidence and an available Alert budget slot.");
      await load();
    } catch (cause) {
      if (current === generation.current) setMessage(cause instanceof Error ? cause.message : "Execution qualification failed.");
    } finally { if (current === generation.current || current + 1 === generation.current) setBusy(false); }
  }

  return <Card><CardHeader className="flex flex-row flex-wrap items-center justify-between gap-3">
    <CardTitle className="text-base">Execution qualification · {policy.name}</CardTitle>
    <Button size="sm" variant="outline" disabled={busy} onClick={onClose}>Close qualification</Button>
  </CardHeader><CardContent className="space-y-4 text-sm">
    <p className="break-words">Target: {deviceName} · {policy.target_site}. The fixed arguments and Alert limit remain those of this reviewed policy.</p>
    {message ? <p role="status" className="rounded-lg border border-slate-200 p-3">{message}</p> : null}
    {loading ? <p>Loading current outcome evidence…</p> : <>
      <p className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-amber-900">Host execution switch: {grants?.execution_enabled ? "on" : "off"}. When enabled, a qualified policy can approve matching actions without another human decision. The platform rechecks the reviewer, exact target, fresh state evidence and Alert budget before execution.</p>
      <p>{evidenceCurrent ? `${qualification?.matching_samples} exact-device/template outcomes meet the ${qualification?.required_samples}-sample requirement.` : "Current exact-device outcome evidence is not sufficient for qualification."}</p>
      <p className="text-xs text-slate-600">A zero-failure outcome policy and structured before/after observations are required. <Link href="/studio/quality" className="text-violet-700 underline">Review outcome evidence</Link>. The server verifies the exact version and template; a healthy version-wide score alone is insufficient.</p>
      {existing ? <div className="space-y-1 rounded-lg border border-slate-200 p-3">
        <p>Recorded grant by {existing.granted_by} · {Date.parse(existing.expires_at) <= now ? "expired" : `expires ${new Date(existing.expires_at).toLocaleString()}`}</p>
        <p className="break-all text-xs text-slate-600">Acceptance reference: {existing.acceptance_reference}</p>
        <p className="text-xs text-slate-600">Revoke this policy to stop new admissions. To change or renew the grant, revise and independently review the policy again.</p>
      </div> : <div className="space-y-3">
        <label className="block">Acceptance reference<Input value={reference} maxLength={1024} disabled={busy} onChange={(event) => setReference(event.target.value)} placeholder="Evidence from independent validation of this device and Tool" /></label>
        <div className="grid gap-3 sm:grid-cols-2"><label className="block">Execution grant expiry<Input type="datetime-local" value={expires} max={localTime(new Date(policy.expires_at))} disabled={busy} onChange={(event) => setExpires(event.target.value)} /></label><label className="block">Qualification audit reason<Input value={reason} maxLength={512} disabled={busy} onChange={(event) => setReason(event.target.value)} /></label></div>
        <label className="flex items-start gap-2"><input type="checkbox" checked={confirmed} disabled={busy} onChange={(event) => setConfirmed(event.target.checked)} className="mt-1" /><span>I independently reviewed the accuracy of the observed state transitions for this device and fixed action template.</span></label>
        <Button disabled={busy || !evidenceCurrent || !confirmed || reference.trim().length < 10 || reason.trim().length < 10} onClick={() => void qualify()}>Record execution grant</Button>
      </div>}
      <Button size="sm" variant="outline" disabled={busy} onClick={() => void load()}>Refresh qualification evidence</Button>
      {existing ? <RollbackQualification key={existing.id} policyId={policy.id} primaryGrantId={existing.id} primaryExpiry={existing.expires_at} /> : null}
    </>}
  </CardContent></Card>;
}
