"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, FileClock, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";

type Principal = {
  principal_id: string | null;
  subject: string;
  principal_type: string;
  permissions: string[];
  authorization_scope: Record<string, unknown>;
};

type Receipt = {
  id: string;
  actor: string;
  period_start: string;
  source_entity_type: string | null;
  source_entity_id: string | null;
  source_step: number | null;
  known_tokens: number;
  charged_tokens: number;
  effective_charged_tokens: number;
  adjustment_id: string | null;
  latest_adjustment_id: string | null;
  supplemental_adjustment_count: number;
};

type Case = {
  id: string;
  reservation_id: string;
  base_adjustment_id: string;
  sequence: number;
  actor: string;
  period_start: string;
  source_entity_type: string | null;
  source_entity_id: string | null;
  source_step: number | null;
  previous_total_tokens: number;
  confirmed_total_tokens: number;
  delta_tokens: number;
  evidence_sha256: string;
  evidence_reference: string;
  reason: string;
  proposed_by_principal_id: string;
  proposed_by: string;
  proposed_at: string;
  status: "proposed" | "applied" | "rejected";
};

type Page<T> = { items: T[]; next_cursor: string | null };

export default function QuotaSupplementsPage() {
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [cases, setCases] = useState<Case[]>([]);
  const [receiptCursor, setReceiptCursor] = useState<string | null>(null);
  const [caseCursor, setCaseCursor] = useState<string | null>(null);
  const [selectedReceiptId, setSelectedReceiptId] = useState("");
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [confirmedTotal, setConfirmedTotal] = useState("");
  const [evidenceDigest, setEvidenceDigest] = useState("");
  const [evidenceReference, setEvidenceReference] = useState("");
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
        throw new Error("A signed-in global AI administrator is required. Development-mode identity cannot approve billing corrections.");
      }
      const [receiptPage, casePage] = await Promise.all([
        apiFetch<Page<Receipt>>("/ai/authoring-quota/supplement-candidates?limit=50"),
        apiFetch<Page<Case>>("/ai/authoring-quota/supplements?state=proposed&limit=50"),
      ]);
      if (current !== requestId.current) return;
      setPrincipal(nextPrincipal);
      setReceipts(receiptPage.items);
      setReceiptCursor(receiptPage.next_cursor);
      setCases(casePage.items);
      setCaseCursor(casePage.next_cursor);
      setSelectedReceiptId((old) => receiptPage.items.some((row) => row.id === old)
        ? old : receiptPage.items[0]?.id ?? "");
      setSelectedCaseId((old) => casePage.items.some((row) => row.id === old)
        ? old : casePage.items[0]?.id ?? "");
    } catch (error) {
      if (current !== requestId.current) return;
      setPrincipal(null);
      setReceipts([]);
      setCases([]);
      setMessage(error instanceof Error ? error.message : "Unable to load supplemental billing review.");
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

  async function loadMore(kind: "receipts" | "cases") {
    const cursor = kind === "receipts" ? receiptCursor : caseCursor;
    if (!cursor || working) return;
    setWorking(true);
    setMessage(null);
    try {
      if (kind === "receipts") {
        const page = await apiFetch<Page<Receipt>>(`/ai/authoring-quota/supplement-candidates?limit=50&cursor=${encodeURIComponent(cursor)}`);
        setReceipts((old) => [...old, ...page.items]);
        setReceiptCursor(page.next_cursor);
        setSelectedReceiptId((old) => old || page.items[0]?.id || "");
      } else {
        const page = await apiFetch<Page<Case>>(`/ai/authoring-quota/supplements?state=proposed&limit=50&cursor=${encodeURIComponent(cursor)}`);
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
    const total = Number(confirmedTotal.trim());
    if (!Number.isSafeInteger(total) || total < 0 || total > 1_000_000_000) {
      setMessage("Confirmed total must be a whole token count between 0 and 1,000,000,000.");
      return;
    }
    const selected = receipts.find((row) => row.id === selectedReceiptId);
    if (selected && total < selected.known_tokens) {
      setMessage("Confirmed total cannot be below known model usage.");
      return;
    }
    if (!/^[0-9a-f]{64}$/.test(evidenceDigest.trim())) {
      setMessage("Enter the lowercase SHA-256 digest of the exact corrected billing evidence.");
      return;
    }
    setWorking(true);
    setMessage(null);
    try {
      await apiFetch("/ai/authoring-quota/supplements", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({
          reservation_id: selectedReceiptId,
          confirmed_total_tokens: total,
          evidence_sha256: evidenceDigest.trim(),
          evidence_reference: evidenceReference.trim(),
          reason: proposalReason.trim(),
        }),
      });
      setConfirmedTotal(""); setEvidenceDigest(""); setEvidenceReference(""); setProposalReason("");
      await load();
      setMessage("Supplemental correction proposed. A different administrator must review the new evidence and previous ledger head.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to propose supplemental correction.");
    } finally {
      setWorking(false);
    }
  }

  async function review(decision: "approve" | "reject") {
    if (!selectedCaseId || working || !principal) return;
    if (reviewReason.trim().length < 10) {
      setMessage("Review reason must contain at least 10 characters.");
      return;
    }
    setWorking(true);
    setMessage(null);
    try {
      await apiFetch(`/ai/authoring-quota/supplements/${selectedCaseId}/review`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ decision, reason: reviewReason.trim() }),
      });
      setReviewReason("");
      await load();
      setMessage(decision === "approve"
        ? "Independent review appended a signed counter adjustment; earlier receipts and decisions remain sealed."
        : "Supplemental proposal rejected; no counters changed.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to review supplemental correction.");
    } finally {
      setWorking(false);
    }
  }

  const selectedReceipt = receipts.find((row) => row.id === selectedReceiptId);
  const selectedCase = cases.find((row) => row.id === selectedCaseId);
  const cannotSelfReview = Boolean(selectedCase && principal && (
    selectedCase.proposed_by_principal_id === principal.principal_id || selectedCase.actor === principal.subject
  ));

  return <main className="min-h-screen bg-[#f3f4f7] px-4 py-8 text-[#2c384a] sm:px-6">
    <div className="mx-auto max-w-5xl">
      <Link href="/settings/ai/authoring-quota" className="inline-flex items-center gap-2 text-sm text-[#5856d6] hover:underline"><ArrowLeft className="size-4" /> AI model-call quota</Link>
      <div className="mt-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-semibold"><FileClock className="size-7 text-[#5856d6]" /> Supplemental billing corrections</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-[#627084]">Use this when new provider evidence contradicts an already approved adjustment. Each proposal binds the exact previous adjustment and token total; a different administrator must verify the evidence. Approval adds only the signed difference. The original receipt and every earlier adjustment stay sealed.</p>
        </div>
        <Button variant="outline" disabled={loading || working} onClick={() => void load()}><RefreshCw className="size-4" /> Refresh</Button>
      </div>
      {message && <p role="status" className="mt-5 rounded-lg border bg-white p-3 text-sm">{message}</p>}
      {loading && <p className="mt-5 text-sm text-[#627084]">Loading correction queue…</p>}
      {principal && <div className="mt-6 grid gap-5 lg:grid-cols-2">
        <section className="rounded-lg border bg-white p-5">
          <h2 className="font-semibold">Propose another correction</h2>
          <p className="mt-2 text-xs leading-5 text-[#627084]">Only receipts with an approved first adjustment appear here. Compare the current counted total with the new provider statement. This page records a human attestation; iCheck does not authenticate the uploaded digest or fetch the statement.</p>
          <form onSubmit={(event) => void propose(event)} className="mt-4 space-y-3">
            <label className="block text-xs font-medium">Adjusted receipt
              <select className="mt-1 block h-10 w-full rounded-md border px-2 text-sm" value={selectedReceiptId} onChange={(event) => setSelectedReceiptId(event.target.value)} required>
                {receipts.length === 0 && <option value="">No adjusted receipts in this page</option>}
                {receipts.map((row) => <option key={row.id} value={row.id}>{row.actor} · {row.id.slice(0, 8)} · current {row.effective_charged_tokens}</option>)}
              </select>
            </label>
            {receiptCursor && <Button type="button" variant="outline" disabled={working} onClick={() => void loadMore("receipts")}>Load more receipts</Button>}
            {selectedReceipt && <p className="break-all text-xs leading-5 text-[#627084]">Receipt {selectedReceipt.id} · UTC day {selectedReceipt.period_start} · source {selectedReceipt.source_entity_type ?? "legacy"} {selectedReceipt.source_entity_id ?? ""}{selectedReceipt.source_step !== null ? ` · step ${selectedReceipt.source_step}` : ""} · original hold {selectedReceipt.charged_tokens.toLocaleString()} · current counted {selectedReceipt.effective_charged_tokens.toLocaleString()} · supplements {selectedReceipt.supplemental_adjustment_count} · head {selectedReceipt.latest_adjustment_id}</p>}
            <label className="block text-xs font-medium">New confirmed total tokens<Input className="mt-1" inputMode="numeric" value={confirmedTotal} onChange={(event) => setConfirmedTotal(event.target.value)} required /></label>
            <label className="block text-xs font-medium">Exact new evidence SHA-256<Input className="mt-1 font-mono" value={evidenceDigest} onChange={(event) => setEvidenceDigest(event.target.value)} minLength={64} maxLength={64} required /></label>
            <label className="block text-xs font-medium">Corrected provider billing reference<Input className="mt-1" value={evidenceReference} onChange={(event) => setEvidenceReference(event.target.value)} minLength={10} maxLength={255} required /></label>
            <label className="block text-xs font-medium">Reason<Textarea className="mt-1" value={proposalReason} onChange={(event) => setProposalReason(event.target.value)} minLength={10} maxLength={1000} required /></label>
            <Button type="submit" disabled={!selectedReceiptId || working}>Submit for independent review</Button>
          </form>
        </section>
        <section className="rounded-lg border bg-white p-5">
          <h2 className="font-semibold">Awaiting independent review</h2>
          <p className="mt-2 text-xs leading-5 text-[#627084]">The proposer and original model-call actor cannot approve. Compare the previous ledger head, exact evidence digest/reference, new total and any late usage reports before deciding.</p>
          <label className="mt-4 block text-xs font-medium">Proposal
            <select className="mt-1 block h-10 w-full rounded-md border px-2 text-sm" value={selectedCaseId} onChange={(event) => setSelectedCaseId(event.target.value)}>
              {cases.length === 0 && <option value="">No proposals awaiting review</option>}
              {cases.map((row) => <option key={row.id} value={row.id}>{row.proposed_by} · {row.reservation_id.slice(0, 8)} · delta {row.delta_tokens}</option>)}
            </select>
          </label>
          {caseCursor && <Button type="button" variant="outline" className="mt-3" disabled={working} onClick={() => void loadMore("cases")}>Load more proposals</Button>}
          {selectedCase && <div className="mt-4 space-y-2 rounded-md bg-[#f7f8fb] p-3 text-xs leading-5">
            <p>Actor {selectedCase.actor} · proposer {selectedCase.proposed_by} · {new Date(selectedCase.proposed_at).toLocaleString()}</p>
            <p className="break-all">Receipt {selectedCase.reservation_id} · UTC day {selectedCase.period_start}</p>
            <p className="break-all">Source {selectedCase.source_entity_type ?? "legacy"} {selectedCase.source_entity_id ?? ""}{selectedCase.source_step !== null ? ` · step ${selectedCase.source_step}` : ""}</p>
            <p className="break-all">Revision {selectedCase.sequence} · predecessor {selectedCase.base_adjustment_id}</p>
            <p>Previous {selectedCase.previous_total_tokens.toLocaleString()} · new {selectedCase.confirmed_total_tokens.toLocaleString()} · signed delta {selectedCase.delta_tokens.toLocaleString()}</p>
            <p className="break-all">Reference {selectedCase.evidence_reference}</p>
            <p className="break-all font-mono">SHA-256 {selectedCase.evidence_sha256}</p>
            <p>Proposer reason: {selectedCase.reason}</p>
          </div>}
          {selectedCase && <div className="mt-4 space-y-3">
            {cannotSelfReview && <p className="text-xs text-amber-700">Independent review is required; this account cannot decide this proposal.</p>}
            <label className="block text-xs font-medium">Independent review reason<Textarea className="mt-1" value={reviewReason} onChange={(event) => setReviewReason(event.target.value)} minLength={10} maxLength={1000} /></label>
            <div className="flex flex-wrap gap-2">
              <Button disabled={working || cannotSelfReview} onClick={() => void review("approve")}>Append adjustment</Button>
              <Button variant="outline" disabled={working || cannotSelfReview} onClick={() => void review("reject")}>Reject proposal</Button>
            </div>
          </div>}
        </section>
      </div>}
      {principal && <p className="mt-5 text-xs leading-5 text-[#627084]">Need to make the first correction? Use <Link href="/settings/ai/quota-reconciliation" className="text-[#5856d6] underline">manual billing adjustment review</Link>. A later contradictory model report is retained in that page&apos;s conflict queue.</p>}
    </div>
  </main>;
}
