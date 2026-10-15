"use client";

import { useEffect, useRef, useState } from "react";
import { AlertTriangle, Loader2, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { APIError, apiFetch } from "@/lib/icheck-api";

type UnresolvedCustodyRecord = {
  id: string;
  request_id: string;
  decision: "unresolved";
  reviewed_by: string;
  reason: string;
  recorded_at: string;
  evidence_refs: {
    format_version: "icheck.mcp-write-disposition-refs/v1";
    provider: Array<{ observation_id: string }>;
    independent: Array<{ observation_id: string }>;
  };
  original_outcome: "unknown";
  automatic_retry_allowed: false;
  delivery_verified: false;
};

export default function MCPUnresolvedCustody({
  proposalId,
  nativeLocking,
}: {
  proposalId: string;
  nativeLocking: boolean;
}) {
  const [rows, setRows] = useState<UnresolvedCustodyRecord[] | null>(null);
  const [reason, setReason] = useState("");
  const requestIdRef = useRef<string | null>(null);
  const submitPendingRef = useRef(false);
  const [historyRevision, setHistoryRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void apiFetch<UnresolvedCustodyRecord[]>(`/agent/action-proposals/${proposalId}/dispositions`)
      .then((history) => {
        if (active) setRows(history);
      })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "Custody history unavailable");
      });
    return () => { active = false; };
  }, [proposalId, historyRevision]);

  function refreshHistory() {
    if (submitPendingRef.current) return;
    setRows(null);
    setError(null);
    setHistoryRevision((current) => current + 1);
  }

  async function recordUnresolved() {
    const trimmed = reason.trim();
    if (!nativeLocking || rows === null || submitPendingRef.current || trimmed.length < 10 || trimmed.length > 1000) return;
    submitPendingRef.current = true;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const stableRequestId = requestIdRef.current ?? crypto.randomUUID();
      requestIdRef.current = stableRequestId;
      const saved = await apiFetch<UnresolvedCustodyRecord>(
        `/agent/action-proposals/${proposalId}/dispositions`,
        { method: "POST", body: JSON.stringify({ request_id: stableRequestId, reason: trimmed }) },
      );
      setRows((current) => current?.some((row) => row.id === saved.id)
        ? current : [...(current ?? []), saved]);
      setReason("");
      requestIdRef.current = null;
      setNotice("Unresolved custody recorded. The original write remains unknown; retry and delivery verification are still blocked.");
    } catch (caught) {
      if (caught instanceof APIError && caught.status === 503) {
        setError("Custody recording is disabled on this server or native PostgreSQL locking is unavailable.");
      } else if (caught instanceof APIError && caught.status < 500) {
        setError(`Custody request was rejected: ${caught.message}. Inspect the history before submitting again.`);
      } else {
        setError("The custody result could not be confirmed. Refresh history or retry with the same request ID; do not resend the device action.");
      }
    } finally {
      submitPendingRef.current = false;
      setBusy(false);
    }
  }

  return (
    <section className="mt-3 rounded border border-amber-200 bg-white p-3" aria-label="Unresolved MCP write custody">
      <p className="flex items-center gap-1 font-semibold"><AlertTriangle className="size-4 text-amber-700" /> Unresolved-write custody</p>
      <p className="mt-1">A separate change approver can preserve an unresolved record after reviewing all evidence. This does not decide whether the write happened, authorize a retry, or verify delivery. The server rechecks the complete evidence and reviewer separation at submission.</p>
      {rows === null && !error ? <p className="mt-2 text-slate-600">Loading custody history…</p> : null}
      {rows?.length === 0 ? <p className="mt-2">No unresolved custody record yet.</p> : null}
      {rows && rows.length > 0 ? (
        <ol className="mt-2 space-y-2">
          {rows.map((row) => (
            <li key={row.id} className="rounded border border-amber-100 bg-amber-50 p-2">
              <p className="font-semibold">Unresolved · {new Date(row.recorded_at).toLocaleString()} · {row.reviewed_by}</p>
              <p className="mt-1 whitespace-pre-wrap break-words">{row.reason}</p>
              <p className="mt-1 text-slate-600">Bound evidence: {row.evidence_refs.provider.length} provider and {row.evidence_refs.independent.length} independent observations. Original outcome unknown; automatic retry blocked; delivery unverified.</p>
            </li>
          ))}
        </ol>
      ) : null}
      {notice ? <p className="mt-2 text-emerald-800" role="status">{notice}</p> : null}
      {error ? <p className="mt-2 text-rose-800" role="alert">{error}</p> : null}
      {error ? <Button className="mt-2" size="sm" variant="outline" disabled={busy} onClick={refreshHistory}>Refresh custody history</Button> : null}
      {nativeLocking ? (
        <div className="mt-3 space-y-2 border-t border-amber-100 pt-3">
          <p className="font-medium">Record unresolved, if the server feature is enabled</p>
          <Textarea
            aria-label="Reason to record the write as unresolved"
            placeholder="Explain why the complete evidence still cannot establish the original outcome. Do not include secrets."
            value={reason}
            maxLength={1000}
            disabled={busy || rows === null}
            onChange={(event) => {
              setReason(event.target.value);
              requestIdRef.current = null;
              setError(null);
            }}
          />
          <Button size="sm" variant="outline" disabled={busy || rows === null || reason.trim().length < 10} onClick={() => void recordUnresolved()}>
            {busy ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />} Record unresolved custody
          </Button>
        </div>
      ) : <p className="mt-2 font-medium text-amber-900">Recording is unavailable in this SQLite preview; native PostgreSQL locking is required.</p>}
    </section>
  );
}
