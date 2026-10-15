"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { apiFetch } from "@/lib/icheck-api";

type Receipt = { id: string; grant_id: string; primary_authorization_id: string; parent_change_plan_id: string;
  authorized_at: string; rollback_budget: number; failure_snapshot: { postcheck_call_id?: string } };

export default function RollbackAuthorityReceipt({ proposalId, automatic }: { proposalId: string; automatic: boolean }) {
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let current = true;
    const timer = window.setTimeout(() => {
      setReceipt(null); setLoaded(false); setError("");
      void apiFetch<Receipt | null>(`/agent/action-proposals/${proposalId}/rollback-authorization`).then(value => {
        if (current) { setReceipt(value); setLoaded(true); }
      }).catch(cause => {
        if (current) { setError(cause instanceof Error ? cause.message : "Unable to read rollback ownership."); setLoaded(true); }
      });
    }, 0);
    return () => { current = false; window.clearTimeout(timer); };
  }, [proposalId, automatic, refresh]);
  return <section aria-label="Rollback authority receipt" className="space-y-2 rounded-xl border border-violet-200 bg-violet-50/40 p-4 text-xs">
    <h3 className="font-semibold">Separate rollback authorization</h3>
    {!loaded ? <p>Loading historical ownership…</p> : error ? <p role="status">{error}</p> : receipt ? <>
      <p>One failed-parent recovery slot · budget {receipt.rollback_budget} · recorded {new Date(receipt.authorized_at).toLocaleString()}</p>
      <dl className="space-y-1 break-all text-[10px]">
        <div><dt className="font-semibold">Recovery grant</dt><dd>{receipt.grant_id}</dd></div>
        <div><dt className="font-semibold">Original primary authorization</dt><dd>{receipt.primary_authorization_id}</dd></div>
        <div><dt className="font-semibold">Failed parent</dt><dd>{receipt.parent_change_plan_id}</dd></div>
        <div><dt className="font-semibold">Failed post-check</dt><dd>{receipt.failure_snapshot.postcheck_call_id || "Unavailable"}</dd></div>
      </dl>
      <p>This immutable receipt is historical ownership, not current permission, successful remediation or incident closure.</p>
    </> : <p>{automatic ? "Automatic recovery receipt is missing; do not treat the approval marker as authority." : "No automatic recovery receipt recorded. Human rollback decisions remain separate from primary approval."}</p>}
    <Button variant="outline" size="sm" disabled={!loaded} onClick={() => setRefresh(value => value+1)}>Refresh rollback ownership</Button>
  </section>;
}
