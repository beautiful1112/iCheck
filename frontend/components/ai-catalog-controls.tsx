"use client";
import { useEffect, useRef, useState } from "react";
import { apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY } from "@/lib/icheck-api";

type Kind = "credentials" | "providers" | "models" | "routes";
type Plan = { preview_hash: string; blockers: string[]; dependencies: { id: string; kind: string; name: string }[]; warning: string };
export function AICatalogControls({ kind, id, name, enabled, onChanged }: { kind: Kind; id: string; name: string; enabled: boolean; onChanged: () => Promise<void> }) {
  const [plan, setPlan] = useState<Plan | null>(null); const [reason, setReason] = useState("");
  const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false); const epoch = useRef(0);
  useEffect(() => {
    const reset = () => { epoch.current++; setPlan(null); setReason(""); setMessage(""); setBusy(false); };
    const storage = (event: StorageEvent) => { if (event.key === NAMESPACE_KEY || event.key === SESSION_CHANGE_KEY || event.key === null) reset(); };
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => { epoch.current++; window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage); };
  }, [id, enabled]);
  async function preview() {
    const current = epoch.current; setBusy(true); setMessage(""); setPlan(null);
    try {
      const result = await apiFetch<Plan>(`/ai/catalog/${kind}/${id}/lifecycle/preview`, { method: "POST",
        headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: !enabled }) });
      if (current === epoch.current) setPlan(result);
    } catch (error) { if (current === epoch.current) setMessage(error instanceof Error ? error.message : "Unable to review dependencies"); }
    finally { if (current === epoch.current) setBusy(false); }
  }
  async function apply() {
    if (!plan) return; const current = epoch.current; setBusy(true); setMessage("");
    try {
      await apiFetch(`/ai/catalog/${kind}/${id}/lifecycle`, { method: "POST",
        headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: !enabled, preview_hash: plan.preview_hash, reason }) });
      if (current === epoch.current) { setPlan(null); setReason(""); await onChanged(); }
    } catch (error) { if (current === epoch.current) setMessage(error instanceof Error ? error.message : "Configuration changed; review again"); }
    finally { if (current === epoch.current) setBusy(false); }
  }
  return <div className="mt-3 text-xs">
    <button type="button" disabled={busy} onClick={() => void preview()} className="rounded-md border px-2 py-1.5 text-violet-700 disabled:opacity-50" aria-label={`${enabled ? "Remove" : "Restore"} ${kind}: ${name}`}>{enabled ? "Remove from active catalog" : "Restore"}</button>
    {plan && <div className="mt-2 rounded-md border border-violet-200 bg-violet-50 p-3">
      <p>{plan.warning}</p>
      {plan.dependencies.map(item => <p key={item.id} className="mt-1">Used by {item.kind}: {item.name}</p>)}
      {plan.blockers.map(item => <p key={item} role="alert" className="mt-2 text-red-700">{item}</p>)}
      {!plan.blockers.length && <><input aria-label={`Reason to ${enabled ? "remove" : "restore"} ${name}`} maxLength={1000} placeholder="Approval reason" value={reason} onChange={event => setReason(event.target.value)} className="mt-2 w-full rounded-md border bg-white px-2 py-2" />
        <button type="button" disabled={busy || !reason.trim()} onClick={() => void apply()} className="mt-2 rounded-md bg-violet-600 px-2 py-2 text-white disabled:opacity-50">Confirm {enabled ? "removal" : "restore"}</button></>}
      <button type="button" disabled={busy} onClick={() => setPlan(null)} className="ml-2 mt-2 underline">Cancel</button>
    </div>}
    {message && <p role="alert" className="mt-2 text-red-700">{message}</p>}
  </div>;
}
