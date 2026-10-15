"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, RefreshCw, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";

type Principal = {
  principal_id: string | null;
  subject: string;
  principal_type: string;
  permissions: string[];
  authorization_scope: Record<string, unknown>;
};

type Candidate = {
  reservation_id: string;
  actor: string;
  period_start: string;
  reserved_tokens: number;
  created_at: string;
  source_entity_type: string | null;
  source_entity_id: string | null;
  source_step: number | null;
  eligible: boolean;
  eligibility_reason: string;
  source_status: string | null;
  source_terminal_at: string | null;
  audited_known_tokens: number | null;
  audit_event_count: number | null;
  audit_sha256: string | null;
};

type Case = {
  id: string;
  reservation_id: string;
  actor: string;
  period_start: string;
  source_entity_type: string;
  source_entity_id: string;
  source_step: number | null;
  source_status_snapshot: string;
  source_terminal_at: string;
  reserved_tokens_snapshot: number;
  audited_known_tokens: number | null;
  audit_event_count: number | null;
  audit_sha256: string | null;
  reason: string;
  proposed_by_principal_id: string;
  proposed_by: string;
  proposed_at: string;
  status: "proposed" | "closed" | "rejected";
};

type Page<T> = { items: T[]; next_cursor: string | null };

export default function QuotaRecoveryPage() {
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [cases, setCases] = useState<Case[]>([]);
  const [candidateCursor, setCandidateCursor] = useState<string | null>(null);
  const [caseCursor, setCaseCursor] = useState<string | null>(null);
  const [selectedReceiptId, setSelectedReceiptId] = useState("");
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [proposalReason, setProposalReason] = useState("");
  const [reviewReason, setReviewReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const requestId = useRef(0);

  const load = useCallback(async () => {
    const current = ++requestId.current;
    setLoading(true);
    setMessage(null);
    try {
      const nextPrincipal = await apiFetch<Principal>("/auth/me");
      if (
        !nextPrincipal.principal_id || nextPrincipal.principal_type !== "user" ||
        nextPrincipal.authorization_scope.all !== true ||
        !(nextPrincipal.permissions.includes("*") || nextPrincipal.permissions.includes("ai.manage"))
      ) {
        throw new Error("A signed-in global AI administrator is required. Development-mode identity cannot close an abandoned hold.");
      }
      const [candidatePage, casePage] = await Promise.all([
        apiFetch<Page<Candidate>>("/ai/authoring-quota/orphan-candidates?limit=50"),
        apiFetch<Page<Case>>("/ai/authoring-quota/orphan-cases?state=proposed&limit=50"),
      ]);
      if (current !== requestId.current) return;
      setPrincipal(nextPrincipal);
      setCandidates(candidatePage.items);
      setCandidateCursor(candidatePage.next_cursor);
      setCases(casePage.items);
      setCaseCursor(casePage.next_cursor);
      setSelectedReceiptId((old) => candidatePage.items.some((row) => row.reservation_id === old && row.eligible)
        ? old : candidatePage.items.find((row) => row.eligible)?.reservation_id ?? "");
      setSelectedCaseId((old) => casePage.items.some((row) => row.id === old)
        ? old : casePage.items[0]?.id ?? "");
    } catch (error) {
      if (current !== requestId.current) return;
      setPrincipal(null);
      setCandidates([]);
      setCases([]);
      setMessage(error instanceof Error ? error.message : "Unable to load the orphan recovery queue.");
    } finally {
      if (current === requestId.current) setLoading(false);
    }
  }, []);

  const invalidateRequests = useCallback(() => { ++requestId.current; }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    const onNamespaceChange = () => void load();
    window.addEventListener("icheck:namespace-changed", onNamespaceChange);
    return () => {
      invalidateRequests();
      window.clearTimeout(timer);
      window.removeEventListener("icheck:namespace-changed", onNamespaceChange);
    };
  }, [load, invalidateRequests]);

  async function loadMore(kind: "candidates" | "cases") {
    const cursor = kind === "candidates" ? candidateCursor : caseCursor;
    if (!cursor || working) return;
    setWorking(true);
    setMessage(null);
    try {
      if (kind === "candidates") {
        const page = await apiFetch<Page<Candidate>>(`/ai/authoring-quota/orphan-candidates?limit=50&cursor=${encodeURIComponent(cursor)}`);
        setCandidates((old) => [...old, ...page.items]);
        setCandidateCursor(page.next_cursor);
        setSelectedReceiptId((old) => old || page.items.find((row) => row.eligible)?.reservation_id || "");
      } else {
        const page = await apiFetch<Page<Case>>(`/ai/authoring-quota/orphan-cases?state=proposed&limit=50&cursor=${encodeURIComponent(cursor)}`);
        setCases((old) => [...old, ...page.items]);
        setCaseCursor(page.next_cursor);
        setSelectedCaseId((old) => old || page.items[0]?.id || "");
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to load another page.");
    } finally {
      setWorking(false);
    }
  }

  async function propose(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedReceiptId || working || !principal) return;
    if (proposalReason.trim().length < 10) {
      setMessage("Recovery reason must contain at least 10 characters.");
      return;
    }
    setWorking(true);
    setMessage(null);
    try {
      await apiFetch("/ai/authoring-quota/orphan-cases", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ reservation_id: selectedReceiptId, reason: proposalReason.trim() }),
      });
      setProposalReason("");
      await load();
      setMessage("Recovery proposed. Another global AI administrator must review the exact source state. No quota has been released.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to propose recovery.");
    } finally {
      setWorking(false);
    }
  }

  async function review(decision: "close" | "reject") {
    if (!selectedCaseId || working || !principal) return;
    if (reviewReason.trim().length < 10) {
      setMessage("Review reason must contain at least 10 characters.");
      return;
    }
    setWorking(true);
    setMessage(null);
    try {
      await apiFetch(`/ai/authoring-quota/orphan-cases/${selectedCaseId}/review`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ decision, reason: reviewReason.trim() }),
      });
      setReviewReason("");
      await load();
      setMessage(decision === "close"
        ? "Pending hold closed as an unknown charge. All reserved tokens remain counted; an audited overrun is added, and any credit needs separate billing review."
        : "Recovery proposal rejected. The pending hold remains unchanged.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to review recovery.");
    } finally {
      setWorking(false);
    }
  }

  const selected = candidates.find((row) => row.reservation_id === selectedReceiptId);
  const selectedCase = cases.find((row) => row.id === selectedCaseId);
  const cannotSelfReview = Boolean(selectedCase && principal && (
    selectedCase.proposed_by_principal_id === principal.principal_id || selectedCase.actor === principal.subject
  ));

  return <main className="min-h-screen bg-[#f3f4f7] px-4 py-8 text-[#2c384a] sm:px-6">
    <div className="mx-auto max-w-5xl">
      <Link href="/settings/ai/authoring-quota" className="inline-flex items-center gap-2 text-sm text-[#5856d6] hover:underline"><ArrowLeft className="size-4" /> AI model-call quota</Link>
      <div className="mt-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-semibold"><ShieldCheck className="size-7 text-[#5856d6]" /> Abandoned hold recovery</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-[#627084]">Only an exact terminal Studio attempt or Investigation execution, aged at least 24 hours, can be proposed. Model-audit usage must form one valid candidate chain; the proposal seals its digest and token total for independent review. Closing never releases the original hold; a verified overrun adds only the positive difference. Provider billing is not independently confirmed, and a later conflicting result is recorded separately.</p>
        </div>
        <Button variant="outline" disabled={loading || working} onClick={() => void load()}><RefreshCw className="size-4" /> Refresh</Button>
      </div>
      {message && <p role="status" className="mt-5 rounded-lg border bg-white p-3 text-sm">{message}</p>}
      {loading && <p className="mt-5 text-sm text-[#627084]">Loading recovery queue…</p>}
      {principal && <div className="mt-6 grid gap-5 lg:grid-cols-2">
        <section className="rounded-lg border bg-white p-5">
          <h2 className="font-semibold">Propose hold closure</h2>
          <p className="mt-2 text-xs leading-5 text-[#627084]">This queue pages only holds older than 24 hours. Receipts without a supported terminality verifier remain visible but cannot be selected. Check the source record, execution lease, and reason before proposing.</p>
          <form onSubmit={(event) => void propose(event)} className="mt-4 space-y-3">
            <label className="block text-xs font-medium">Eligible pending receipt
              <select className="mt-1 block h-10 w-full rounded-md border px-2 text-sm" value={selectedReceiptId} onChange={(event) => setSelectedReceiptId(event.target.value)} required>
                {!candidates.some((row) => row.eligible) && <option value="">No eligible receipts in this page</option>}
                {candidates.filter((row) => row.eligible).map((row) => <option key={row.reservation_id} value={row.reservation_id}>{row.actor} · {row.source_entity_type} · {row.reservation_id.slice(0, 8)} · held {row.reserved_tokens}</option>)}
              </select>
            </label>
            {selected && <p className="break-all text-xs leading-5 text-[#627084]">Receipt {selected.reservation_id} · source {selected.source_entity_id} {selected.source_step !== null ? `· step ${selected.source_step}` : ""} · {selected.source_status} since {selected.source_terminal_at ? new Date(selected.source_terminal_at).toLocaleString() : "unknown"} · audited known usage {selected.audited_known_tokens ?? "unknown"} tokens across {selected.audit_event_count ?? 0} model events · audit SHA-256 {selected.audit_sha256 ?? "unavailable"}</p>}
            <label className="block text-xs font-medium">Recovery reason<Textarea className="mt-1" value={proposalReason} onChange={(event) => setProposalReason(event.target.value)} minLength={10} maxLength={1000} required /></label>
            <Button type="submit" disabled={!selectedReceiptId || working}>Submit for independent review</Button>
          </form>
          {candidateCursor && <Button type="button" variant="outline" className="mt-4" disabled={working} onClick={() => void loadMore("candidates")}>Load more pending receipts</Button>}
          <div className="mt-5 space-y-2">
            <h3 className="text-xs font-semibold">Why other receipts are blocked</h3>
            {candidates.filter((row) => !row.eligible).slice(0, 12).map((row) => <p key={row.reservation_id} className="break-all rounded-md bg-[#f7f8fb] p-2 text-xs text-[#627084]">{row.reservation_id.slice(0, 8)} · {row.eligibility_reason}</p>)}
            {candidates.filter((row) => !row.eligible).length > 12 && <p className="text-xs text-[#627084]">Showing the first 12 blocked reasons on this page.</p>}
          </div>
        </section>
        <section className="rounded-lg border bg-white p-5">
          <h2 className="font-semibold">Awaiting independent review</h2>
          <p className="mt-2 text-xs leading-5 text-[#627084]">The proposer and original model-call actor cannot decide. Approval rechecks the source and receipt under a transaction; changed evidence must be rejected and proposed again.</p>
          <label className="mt-4 block text-xs font-medium">Proposal
            <select className="mt-1 block h-10 w-full rounded-md border px-2 text-sm" value={selectedCaseId} onChange={(event) => setSelectedCaseId(event.target.value)}>
              {cases.length === 0 && <option value="">No recovery proposals awaiting review</option>}
              {cases.map((row) => <option key={row.id} value={row.id}>{row.proposed_by} · {row.reservation_id.slice(0, 8)} · held {row.reserved_tokens_snapshot}</option>)}
            </select>
          </label>
          {caseCursor && <Button type="button" variant="outline" className="mt-3" disabled={working} onClick={() => void loadMore("cases")}>Load more proposals</Button>}
          {selectedCase && <div className="mt-4 space-y-2 rounded-md bg-[#f7f8fb] p-3 text-xs leading-5">
            <p>Actor {selectedCase.actor} · proposer {selectedCase.proposed_by} · {new Date(selectedCase.proposed_at).toLocaleString()}</p>
            <p className="break-all">Receipt {selectedCase.reservation_id} · UTC day {selectedCase.period_start}</p>
            <p className="break-all">Source {selectedCase.source_entity_type} {selectedCase.source_entity_id}{selectedCase.source_step !== null ? ` · step ${selectedCase.source_step}` : ""}</p>
            <p>Source state {selectedCase.source_status_snapshot} since {new Date(selectedCase.source_terminal_at).toLocaleString()} · held {selectedCase.reserved_tokens_snapshot.toLocaleString()}</p>
            <p className="break-all">Audited known usage {selectedCase.audited_known_tokens ?? "legacy unknown"} tokens across {selectedCase.audit_event_count ?? "legacy"} events · SHA-256 {selectedCase.audit_sha256 ?? "legacy proposal without audit snapshot"}</p>
            <p>Proposer reason: {selectedCase.reason}</p>
          </div>}
          {selectedCase && <div className="mt-4 space-y-3">
            {cannotSelfReview && <p className="text-xs text-amber-700">Independent review is required; this account cannot decide this proposal.</p>}
            <label className="block text-xs font-medium">Review reason<Textarea className="mt-1" value={reviewReason} onChange={(event) => setReviewReason(event.target.value)} minLength={10} maxLength={1000} /></label>
            <div className="flex flex-wrap gap-2">
              <Button disabled={working || cannotSelfReview} onClick={() => void review("close")}>Close without credit</Button>
              <Button variant="outline" disabled={working || cannotSelfReview} onClick={() => void review("reject")}>Reject proposal</Button>
            </div>
          </div>}
        </section>
      </div>}
      {principal && <p className="mt-5 text-xs leading-5 text-[#627084]">After closure, any credit requires separate <Link href="/settings/ai/quota-reconciliation" className="text-[#5856d6] underline">manual billing adjustment review</Link>. This page does not verify provider statements or release quota.</p>}
    </div>
  </main>;
}
