"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Clock,
  Fingerprint,
  Loader2,
  RefreshCw,
  ShieldCheck,
  UserRoundCheck,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

const API_URL =
  process.env.NEXT_PUBLIC_ICHECK_API_URL || "http://localhost:8000/api/v1";

type ProposalStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "executing"
  | "succeeded"
  | "failed";

type ActionProposal = {
  id: string;
  investigation_id: string;
  tool_id: string;
  tool_call_id: string | null;
  iteration: number;
  arguments: Record<string, unknown>;
  purpose: string;
  plan_hash: string;
  status: ProposalStatus;
  requested_by_principal_id: string | null;
  requested_by: string;
  approved_by: string | null;
  decision_reason: string | null;
  error: string | null;
  requested_at: string;
};

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const document = (await response.json()) as { detail?: string };
      if (document.detail) detail = document.detail;
    } catch {
      // Keep the status when an intermediary returns non-JSON content.
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

function relativeTime(value: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return hours < 24 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
}

function statusTone(status: ProposalStatus): string {
  if (status === "pending") return "border-amber-200 bg-amber-50 text-amber-700";
  if (status === "approved" || status === "executing") {
    return "border-sky-200 bg-sky-50 text-sky-700";
  }
  if (status === "succeeded") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
  return "border-red-200 bg-red-50 text-red-700";
}

export default function ApprovalsPage() {
  const [proposals, setProposals] = useState<ActionProposal[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadProposals = useCallback(async () => {
    setLoading(true);
    try {
      const next = await apiFetch<ActionProposal[]>("/agent/action-proposals?limit=200");
      setProposals(next);
      setSelectedId((current) =>
        current && next.some((item) => item.id === current)
          ? current
          : next.find((item) => item.status === "pending")?.id || next[0]?.id || null,
      );
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load approvals");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadProposals(), 0);
    return () => window.clearTimeout(timer);
  }, [loadProposals]);

  const selected = useMemo(
    () => proposals.find((item) => item.id === selectedId) || null,
    [proposals, selectedId],
  );
  const pendingCount = proposals.filter((item) => item.status === "pending").length;

  async function decide(decision: "approve" | "reject") {
    if (!selected || selected.status !== "pending" || !reason.trim()) return;
    setSubmitting(decision);
    setError(null);
    try {
      await apiFetch(`/agent/action-proposals/${selected.id}/decision`, {
        method: "POST",
        body: JSON.stringify({
          decision,
          expected_plan_hash: selected.plan_hash,
          reason: reason.trim(),
        }),
      });
      setReason("");
      await loadProposals();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to record decision");
    } finally {
      setSubmitting(null);
    }
  }

  return (
    <main className="min-h-screen bg-[#f5f6f8] px-4 py-6 text-slate-900 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1380px]">
        <header className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="grid size-9 place-items-center rounded-xl border border-slate-200 bg-white text-slate-600 shadow-sm hover:text-violet-700"
              aria-label="Back to AI operator"
            >
              <ArrowLeft className="size-4" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <ShieldCheck className="size-5 text-violet-600" />
                <h1 className="text-xl font-semibold tracking-tight">Governed actions</h1>
              </div>
              <p className="mt-1 text-xs text-slate-500">
                Peer review for exact plans paused inside durable investigations.
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={() => void loadProposals()}>
            <RefreshCw className={cn("size-3.5", loading && "animate-spin")} /> Refresh
          </Button>
        </header>

        {error ? (
          <div className="mt-5 flex items-start gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" /> {error}
          </div>
        ) : null}

        <section className="mt-6 grid gap-4 sm:grid-cols-3">
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-medium text-slate-500">Awaiting peer review</p>
            <p className="mt-2 text-2xl font-semibold">{pendingCount}</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-medium text-slate-500">Four-eyes rule</p>
            <p className="mt-2 text-sm font-semibold">Requester cannot approve</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-medium text-slate-500">Resume behavior</p>
            <p className="mt-2 text-sm font-semibold">Same LangGraph thread</p>
          </div>
        </section>

        <div className="mt-5 grid items-start gap-5 lg:grid-cols-[360px_minmax(0,1fr)]">
          <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="border-b border-slate-100 px-5 py-4">
              <h2 className="text-sm font-semibold">Action queue</h2>
              <p className="mt-1 text-[11px] text-slate-500">Pending plans appear first.</p>
            </div>
            <div className="max-h-[680px] overflow-y-auto p-2">
              {loading && !proposals.length ? (
                <div className="grid min-h-40 place-items-center"><Loader2 className="size-5 animate-spin text-violet-500" /></div>
              ) : proposals.length ? (
                [...proposals]
                  .sort((left, right) => Number(right.status === "pending") - Number(left.status === "pending"))
                  .map((item) => (
                    <button
                      type="button"
                      key={item.id}
                      onClick={() => { setSelectedId(item.id); setReason(""); }}
                      className={cn(
                        "w-full rounded-xl px-3 py-3 text-left hover:bg-slate-50",
                        item.id === selectedId && "bg-violet-50 hover:bg-violet-50",
                      )}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <p className="line-clamp-2 text-xs font-semibold leading-5 text-slate-700">{item.purpose}</p>
                        <Badge variant="outline" className={cn("shrink-0 capitalize", statusTone(item.status))}>{item.status}</Badge>
                      </div>
                      <p className="mt-2 truncate font-mono text-[9px] text-slate-400">{item.tool_id}</p>
                      <p className="mt-1 text-[9px] text-slate-400">{item.requested_by} · {relativeTime(item.requested_at)}</p>
                    </button>
                  ))
              ) : (
                <div className="px-5 py-12 text-center">
                  <CheckCircle2 className="mx-auto size-8 text-emerald-500" />
                  <p className="mt-3 text-sm font-semibold">No governed actions</p>
                  <p className="mt-1 text-xs leading-5 text-slate-500">State-changing requests will pause here.</p>
                </div>
              )}
            </div>
          </section>

          <section className="min-h-[520px] rounded-2xl border border-slate-200 bg-white shadow-sm">
            {selected ? (
              <>
                <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-4 sm:px-6">
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">Exact action plan</p>
                    <h2 className="mt-2 text-lg font-semibold tracking-tight">{selected.purpose}</h2>
                  </div>
                  <Badge variant="outline" className={cn("capitalize", statusTone(selected.status))}>{selected.status}</Badge>
                </div>
                <div className="space-y-5 p-5 sm:p-6">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-xl bg-slate-50 p-4">
                      <div className="flex items-center gap-2 text-xs font-semibold"><UserRoundCheck className="size-4 text-violet-600" /> Requester</div>
                      <p className="mt-2 text-sm">{selected.requested_by}</p>
                      <p className="mt-1 font-mono text-[9px] text-slate-400">{selected.requested_by_principal_id || "development identity"}</p>
                    </div>
                    <div className="rounded-xl bg-slate-50 p-4">
                      <div className="flex items-center gap-2 text-xs font-semibold"><Clock className="size-4 text-sky-600" /> Investigation</div>
                      <Link href={`/?investigation=${selected.investigation_id}`} className="mt-2 block truncate font-mono text-xs text-violet-700 hover:underline">{selected.investigation_id}</Link>
                      <p className="mt-1 text-[9px] text-slate-400">Iteration {selected.iteration}</p>
                    </div>
                  </div>

                  <div>
                    <p className="text-xs font-semibold">Proposed arguments</p>
                    <pre className="mt-2 max-h-72 overflow-auto rounded-xl bg-[#182134] p-4 text-[11px] leading-5 text-slate-200">{JSON.stringify(selected.arguments, null, 2)}</pre>
                  </div>

                  <div className="rounded-xl border border-slate-200 p-4">
                    <div className="flex items-center gap-2 text-xs font-semibold"><Fingerprint className="size-4 text-slate-500" /> Approval-bound plan hash</div>
                    <p className="mt-2 break-all font-mono text-[10px] leading-5 text-slate-500">{selected.plan_hash}</p>
                    <p className="mt-2 text-[10px] text-slate-400">Changing the tool, arguments, or purpose invalidates the decision.</p>
                  </div>

                  {selected.status === "pending" ? (
                    <div className="rounded-xl border border-amber-200 bg-amber-50/60 p-4">
                      <p className="text-xs font-semibold text-amber-900">Peer decision</p>
                      <p className="mt-1 text-[10px] text-amber-800">The backend rejects self-approval and stale hashes.</p>
                      <Textarea value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Record the operational reason." className="mt-3 min-h-24 bg-white text-sm" />
                      <div className="mt-3 flex justify-end gap-2">
                        <Button variant="outline" onClick={() => void decide("reject")} disabled={!reason.trim() || submitting !== null}>
                          {submitting === "reject" ? <Loader2 className="animate-spin" /> : <XCircle />} Reject
                        </Button>
                        <Button onClick={() => void decide("approve")} disabled={!reason.trim() || submitting !== null} className="bg-violet-600 text-white hover:bg-violet-700">
                          {submitting === "approve" ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Approve exact plan
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs text-slate-600">
                      <p className="font-semibold capitalize">{selected.status} by {selected.approved_by || "runtime"}</p>
                      {selected.decision_reason ? <p className="mt-2 leading-5">{selected.decision_reason}</p> : null}
                      {selected.error ? <p className="mt-2 text-red-700">{selected.error}</p> : null}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="grid min-h-[520px] place-items-center text-center">
                <div><ShieldCheck className="mx-auto size-10 text-slate-300" /><p className="mt-3 text-sm font-semibold">Select an action plan</p></div>
              </div>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}
