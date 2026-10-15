"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { APIError, apiFetch } from "@/lib/icheck-api";

type Settings = { min_samples: number; window_minutes: number; max_sample_age_seconds: number; max_start_delay_seconds: number };
type Evidence = { ready: boolean; matching_samples: number; required_samples: number; evidence_sha256: string; valid_until: string | null; reason: string | null };
type Grant = { id: string; granted_by: string; expires_at: string; acceptance_reference: string; settings_snapshot: Settings };
type Grants = { items: Grant[]; revoked_grant_ids: string[]; execution_enabled: boolean };

function localTime(value: Date) {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

export default function RollbackQualification({ policyId, primaryGrantId, primaryExpiry }: {
  policyId: string; primaryGrantId: string; primaryExpiry: string;
}) {
  const [settings, setSettings] = useState<Settings>({ min_samples: 5, window_minutes: 1440, max_sample_age_seconds: 86400, max_start_delay_seconds: 300 });
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [grants, setGrants] = useState<Grants | null>(null);
  const [reference, setReference] = useState("");
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [expiry, setExpiry] = useState(() => localTime(new Date(Math.min(Date.now() + 3600000, Date.parse(primaryExpiry)))));
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const generation = useRef(0);
  const endpoint = `/agent/change-preapprovals/${policyId}/execution-grants/${primaryGrantId}`;

  const load = useCallback(async () => {
    const current = ++generation.current;
    setEvidence(null);
    try {
      const query = new URLSearchParams(Object.entries(settings).map(([key, value]) => [key, String(value)]));
      const [proof, history] = await Promise.all([
        apiFetch<Evidence>(`${endpoint}/rollback-qualification?${query}`), apiFetch<Grants>(`${endpoint}/rollback-grants`),
      ]);
      if (current === generation.current) {
        setGrants(history);
        const recorded = history.items[0]?.settings_snapshot;
        if (recorded && Object.entries(recorded).some(([key, value]) => settings[key as keyof Settings] !== value)) {
          setConfirmed(false);
          setSettings(recorded);
        } else { setEvidence(proof); }
      }
    } catch (cause) {
      if (current === generation.current) setMessage(cause instanceof Error ? cause.message : "Unable to read recovery evidence.");
    }
  }, [endpoint, settings]);

  useEffect(() => {
    const refresh = window.setTimeout(() => void load(), 0);
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    const current = generation;
    return () => { window.clearTimeout(refresh); window.clearInterval(clock); ++current.current; };
  }, [load]);

  function edit(key: keyof Settings, value: string) {
    ++generation.current; setEvidence(null); setConfirmed(false);
    setSettings(previous => ({ ...previous, [key]: Number(value) }));
  }

  const existing = grants?.items[0];
  const revoked = Boolean(existing && grants?.revoked_grant_ids.includes(existing.id));
  const currentEvidence = Boolean(evidence?.ready && evidence.valid_until && Date.parse(evidence.valid_until) > now);

  async function submit(revoke = false) {
    if (!revoke && (!currentEvidence || !confirmed || reference.trim().length < 10 || reason.trim().length < 10)) return;
    if (revoke && (!existing || reason.trim().length < 10)) return;
    const expires = new Date(expiry);
    if (!revoke && (!Number.isFinite(expires.getTime()) || expires.getTime() <= Date.now() || expires.getTime() > Date.parse(primaryExpiry))) {
      setMessage("Choose a future rollback expiry within the primary grant expiry."); return;
    }
    const current = generation.current;
    setBusy(true); setMessage("");
    try {
      await apiFetch(revoke ? `${endpoint}/rollback-grants/${existing?.id}/revoke` : `${endpoint}/rollback-grants`, {
        method: "POST", body: JSON.stringify(revoke ? { reason: reason.trim() } : { ...settings,
          expected_evidence_sha256: evidence?.evidence_sha256, independent_validation_confirmed: true,
          acceptance_reference: reference.trim(), expires_at: expires.toISOString(), reason: reason.trim() }),
      });
      if (current !== generation.current) return;
      setConfirmed(false); setMessage(revoke ? "Rollback grant revoked. Sealed history remains available." : "Separate rollback grant recorded; no action was approved or executed.");
      await load();
    } catch (cause) {
      if (current === generation.current) {
        setMessage(cause instanceof Error ? cause.message : "Rollback qualification failed.");
        if (!revoke && cause instanceof APIError && [403, 409].includes(cause.status)) {
          setEvidence(null); setConfirmed(false);
        }
      }
    } finally { setBusy(false); }
  }

  return <section aria-label="Separate rollback qualification" className="space-y-3 rounded-lg border border-violet-200 p-3">
    <h3 className="font-semibold">Separate rollback authority</h3>
    <p className="text-xs text-slate-600">Primary execution does not authorize rollback. Independently validate original-state restoration for this exact device, template and pinned Tool implementations. Restored state is not successful remediation or incident closure.</p>
    <p className="text-xs">Rollback host switch: {grants?.execution_enabled ? "on" : "off"}. Budget: one rollback per exact failed parent; unknown writes require human reconciliation.</p>
    {message ? <p role="status" className="break-words rounded border p-2 text-xs">{message}</p> : null}
    {!existing ? <div className="grid gap-3 sm:grid-cols-2">
      {([{ key: "min_samples", label: "Independent recovery samples", min: 1, max: 200 },
        { key: "window_minutes", label: "Recovery evidence window (minutes)", min: 1, max: 1440 },
        { key: "max_sample_age_seconds", label: "Recovery sample age (seconds)", min: 60, max: 86400 },
        { key: "max_start_delay_seconds", label: "Rollback start deadline (seconds)", min: 60, max: 3600 }] as const).map(field =>
        <label key={field.key} className="block text-xs">{field.label}<Input type="number" min={field.min} max={field.max} value={settings[field.key]} disabled={busy} onChange={event => edit(field.key, event.target.value)} /></label>)}
    </div> : null}
    <p className="text-xs">{currentEvidence ? `${evidence?.matching_samples} independent recovery samples meet the ${evidence?.required_samples}-sample requirement.` : "Current independent restoration evidence is not ready."}</p>
    {existing ? <div className="space-y-2 text-xs">
      <p>Rollback grant by {existing.granted_by} · {revoked ? "revoked" : Date.parse(existing.expires_at) <= now ? "expired" : "recorded"}</p>
      <p className="break-all">{existing.acceptance_reference}</p>
      <p>Required samples: {existing.settings_snapshot.min_samples} · evidence window: {existing.settings_snapshot.window_minutes} minutes · maximum age: {existing.settings_snapshot.max_sample_age_seconds} seconds · start deadline: {existing.settings_snapshot.max_start_delay_seconds} seconds.</p>
      <p>A changed, expired or revoked grant requires a newly reviewed primary policy revision.</p>
      {!revoked ? <><label className="block">Rollback revocation reason<Input maxLength={512} value={reason} disabled={busy} onChange={event => setReason(event.target.value)} /></label><Button variant="outline" disabled={busy || reason.trim().length < 10} onClick={() => void submit(true)}>Revoke rollback grant</Button></> : null}
    </div> : <>
      <label className="block text-xs">Rollback acceptance reference<Input maxLength={1024} value={reference} disabled={busy} onChange={event => setReference(event.target.value)} /></label>
      <label className="block text-xs">Rollback grant expiry<Input type="datetime-local" max={localTime(new Date(primaryExpiry))} value={expiry} disabled={busy} onChange={event => setExpiry(event.target.value)} /></label>
      <label className="block text-xs">Rollback qualification reason<Input maxLength={512} value={reason} disabled={busy} onChange={event => setReason(event.target.value)} /></label>
      <label className="flex items-start gap-2 text-xs"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} className="mt-1" /><span>I independently verified restoration observations and the exact rollback implementation, not its declared success flag.</span></label>
      <Button disabled={busy || !currentEvidence || !confirmed || reference.trim().length < 10 || reason.trim().length < 10} onClick={() => void submit()}>Record separate rollback grant</Button>
    </>}
    <Button variant="outline" size="sm" disabled={busy} onClick={() => void load()}>Refresh recovery evidence</Button>
  </section>;
}
