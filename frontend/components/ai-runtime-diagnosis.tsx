"use client";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY } from "@/lib/icheck-api";
import { AIProviderDiagnosticDetails, type SafeProviderDiagnostic } from "@/components/ai-provider-diagnostic-details";

type Diagnosis = { diagnostic: SafeProviderDiagnostic;
  model_usage?: { reported_tokens: number; investigation_tokens: number; late_usage_tokens: number; unresolved_charges: boolean };
  evidence: { audit_event_id: string }[]; repair: { configuration_url: string; current_model_name: string; proposed_model_name: string | null } | null };

export function AIRuntimeDiagnosis({ investigationId, canManage, canRetry }: { investigationId: string; canManage: boolean; canRetry: boolean }) {
  const [data, setData] = useState<Diagnosis | null>(null);
  const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false);
  const epoch = useRef(0);
  useEffect(() => {
    function refresh() {
      const current = ++epoch.current; setData(null); setMessage(""); setBusy(false);
      void apiFetch<Diagnosis>(`/agent/investigations/${investigationId}/diagnosis`).then(result => {
        if (current === epoch.current) setData(result);
      }).catch(error => { if (current === epoch.current) setMessage(error instanceof Error ? error.message : "Diagnosis unavailable"); });
    }
    const storage = (event: StorageEvent) => { if (event.key === NAMESPACE_KEY || event.key === SESSION_CHANGE_KEY || event.key === null) refresh(); };
    refresh(); window.addEventListener("icheck:namespace-changed", refresh); window.addEventListener("storage", storage);
    return () => { epoch.current++; window.removeEventListener("icheck:namespace-changed", refresh); window.removeEventListener("storage", storage); };
  }, [investigationId]);
  async function retry() {
    const current = epoch.current; setBusy(true); setMessage("");
    try {
      const result = await apiFetch<{ id: string }>(`/agent/investigations/${investigationId}/repair-retry`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ actor: "web.operator" }) });
      if (current === epoch.current) window.location.assign(`/?investigation=${encodeURIComponent(result.id)}`);
    } catch (error) { if (current === epoch.current) setMessage(error instanceof Error ? error.message : "Retry failed"); }
    finally { if (current === epoch.current) setBusy(false); }
  }
  return <section className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-4" aria-label="AI runtime root cause and self-repair">
    <h3 className="font-semibold">Root cause and proposed repair</h3>
    {data && <><p className="mt-2 text-sm font-medium">{data.diagnostic.summary}</p>
      <p className="mt-2 text-sm">{data.diagnostic.cause}</p>
      <p className="mt-2 text-sm">Next: {data.diagnostic.recommendation}</p>
      <AIProviderDiagnosticDetails diagnostic={data.diagnostic} />
      {data.model_usage && (data.model_usage.late_usage_tokens > 0 || data.model_usage.unresolved_charges) && <p className="mt-2 text-sm" role="status">
        Provider-reported usage: {data.model_usage.reported_tokens.toLocaleString()} tokens.
        {data.model_usage.late_usage_tokens > 0 && ` ${data.model_usage.late_usage_tokens.toLocaleString()} tokens were recorded outside the worker's retained progress; historical counters are unchanged.`}
        {data.model_usage.unresolved_charges && " A provider charge is unresolved; do not assume this failed call was free."}
      </p>}
      <p className="mt-2 text-xs text-slate-600">{data.diagnostic.code}{data.diagnostic.upstream_status ? ` · Provider HTTP ${data.diagnostic.upstream_status}` : ""} · {data.evidence.length} retained failure record(s)</p>
      {data.repair && <><p className="mt-3 break-all text-sm">Configured model: {data.repair.current_model_name}</p>
        {data.repair.proposed_model_name && <p className="mt-1 break-all text-sm">Proposed synchronous model: {data.repair.proposed_model_name}. You can choose another model.</p>}
        {canManage && <Link href={data.repair.configuration_url} className="mt-3 inline-block rounded-md bg-violet-600 px-3 py-2 text-sm text-white">Review proposed configuration repair</Link>}</>}
      {canRetry && <><p className="mt-3 text-xs">After approving a repair, retry creates a new investigation with the original task and scope, current permissions and route. It may incur model charges; device approval remains separate.</p>
        <button type="button" disabled={busy} onClick={() => void retry()} className="mt-2 rounded-md border border-violet-300 bg-white px-3 py-2 text-sm disabled:opacity-50">Retry original task after repair</button></>}
    </>}
    {message && <p role="alert" className="mt-2 text-sm text-red-700">{message}</p>}
  </section>;
}
