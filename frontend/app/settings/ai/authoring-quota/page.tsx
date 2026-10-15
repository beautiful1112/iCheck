"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, Gauge, RefreshCw, Save } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";

type Quota = {
  period_start: string;
  actor: string;
  namespace_limit: number | null;
  namespace_used: number;
  namespace_available: number | null;
  actor_limit: number | null;
  actor_used: number;
  actor_available: number | null;
  pending_requests: number;
  unknown_charge_requests: number;
  policy_revision: number;
};

type Principal = {
  permissions: string[];
  authorization_scope: Record<string, unknown>;
};

type Reservation = {
  id: string;
  source_entity_type: string | null;
  source_entity_id: string | null;
  source_step: number | null;
  actor: string;
  period_start: string;
  reserved_tokens: number;
  known_tokens: number;
  charged_tokens: number;
  effective_charged_tokens: number;
  adjustment_id: string | null;
  latest_adjustment_id: string | null;
  supplemental_adjustment_count: number;
  status: "reserved" | "settled";
  external_charge_unknown: boolean;
  created_at: string;
};

type ReservationPage = {
  items: Reservation[];
  next_cursor: string | null;
};

function optionalLimit(value: string): number | null {
  if (!value.trim()) return null;
  const number = Number(value.trim());
  if (!Number.isSafeInteger(number) || number < 1 || number > 1_000_000_000_000) {
    throw new Error("Quota limits must be positive whole tokens up to 1,000,000,000,000.");
  }
  return number;
}

export default function AuthoringQuotaPage() {
  const [quota, setQuota] = useState<Quota | null>(null);
  const [canManage, setCanManage] = useState(false);
  const [namespaceLimit, setNamespaceLimit] = useState("");
  const [actorLimit, setActorLimit] = useState("");
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const requestId = useRef(0);
  const [reservationScope, setReservationScope] = useState<"mine" | "namespace">("mine");
  const [reservationState, setReservationState] = useState<"attention" | "pending" | "uncertain" | "all">("attention");
  const [sourceFilter, setSourceFilter] = useState("");
  const [staleOnly, setStaleOnly] = useState(false);
  const [reservations, setReservations] = useState<Reservation[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [reservationLoading, setReservationLoading] = useState(false);
  const [reservationError, setReservationError] = useState<string | null>(null);
  const reservationRequestId = useRef(0);

  const loadReservations = useCallback(async (cursor?: string) => {
    const current = ++reservationRequestId.current;
    setReservationLoading(true);
    setReservationError(null);
    const query = new URLSearchParams({
      scope: reservationScope, state: reservationState, limit: "20",
    });
    if (sourceFilter.trim()) query.set("source_entity_id", sourceFilter.trim());
    if (staleOnly) query.set("older_than_minutes", "15");
    if (cursor) query.set("cursor", cursor);
    try {
      const page = await apiFetch<ReservationPage>(`/ai/authoring-quota/reservations?${query}`);
      if (current !== reservationRequestId.current) return;
      setReservations((prior) => cursor ? [...prior, ...page.items] : page.items);
      setNextCursor(page.next_cursor);
    } catch (error) {
      if (current !== reservationRequestId.current) return;
      if (!cursor) { setReservations([]); setNextCursor(null); }
      setReservationError(error instanceof Error ? error.message : "Unable to load AI quota receipts.");
    } finally {
      if (current === reservationRequestId.current) setReservationLoading(false);
    }
  }, [reservationScope, reservationState, sourceFilter, staleOnly]);

  const load = useCallback(async () => {
    const current = ++requestId.current;
    setLoading(true);
    setMessage(null);
    try {
      const [next, principal] = await Promise.all([
        apiFetch<Quota>("/ai/authoring-quota"),
        apiFetch<Principal>("/auth/me"),
      ]);
      if (current !== requestId.current) return;
      setQuota(next);
      setNamespaceLimit(next.namespace_limit?.toString() ?? "");
      setActorLimit(next.actor_limit?.toString() ?? "");
      const nextCanManage = (
        principal.authorization_scope.all === true &&
        (principal.permissions.includes("*") || principal.permissions.includes("ai.manage"))
      );
      setCanManage(nextCanManage);
      if (!nextCanManage) setReservationScope("mine");
    } catch (error) {
      if (current !== requestId.current) return;
      setQuota(null);
      setMessage(error instanceof Error ? error.message : "Unable to load authoring quota.");
    } finally {
      if (current === requestId.current) setLoading(false);
    }
  }, []);

  const invalidateQuotaRequests = useCallback(() => { ++requestId.current; }, []);
  const invalidateReservationRequests = useCallback(() => { ++reservationRequestId.current; }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    const onNamespaceChange = () => { setQuota(null); void load(); };
    window.addEventListener("icheck:namespace-changed", onNamespaceChange);
    return () => {
      invalidateQuotaRequests();
      window.clearTimeout(timer);
      window.removeEventListener("icheck:namespace-changed", onNamespaceChange);
    };
  }, [load, invalidateQuotaRequests]);

  useEffect(() => {
    const sourceId = new URLSearchParams(window.location.search).get("source_entity_id");
    if (!sourceId || sourceId.length > 36) return;
    const timer = window.setTimeout(() => setSourceFilter(sourceId), 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadReservations(), 0);
    const onNamespaceChange = () => { setReservations([]); setNextCursor(null); void loadReservations(); };
    window.addEventListener("icheck:namespace-changed", onNamespaceChange);
    return () => {
      invalidateReservationRequests();
      window.clearTimeout(timer);
      window.removeEventListener("icheck:namespace-changed", onNamespaceChange);
    };
  }, [loadReservations, invalidateReservationRequests]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!quota || saving || !canManage) return;
    let dailyTokenLimit: number | null;
    let actorDailyTokenLimit: number | null;
    try {
      dailyTokenLimit = optionalLimit(namespaceLimit);
      actorDailyTokenLimit = optionalLimit(actorLimit);
      if (reason.trim().length < 10 || reason.length > 1000) {
        throw new Error("Change reason must contain 10–1000 characters.");
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Invalid quota policy.");
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      const next = await apiFetch<Quota>("/ai/authoring-quota", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          expected_revision: quota.policy_revision,
          daily_token_limit: dailyTokenLimit,
          actor_daily_token_limit: actorDailyTokenLimit,
          reason: reason.trim(),
        }),
      });
      setQuota(next);
      setReason("");
      setMessage("Quota policy updated. Existing reservations remain accounted for.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Quota update failed. Refresh and retry.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#f3f4f7] px-4 py-8 text-[#2c384a] sm:px-6">
      <div className="mx-auto max-w-4xl">
        <Link href="/settings/ai" className="inline-flex items-center gap-2 text-sm text-[#5856d6] hover:underline">
          <ArrowLeft className="size-4" /> AI settings
        </Link>
        <div className="mt-5 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="flex items-center gap-3 text-2xl font-semibold"><Gauge className="size-7 text-[#5856d6]" /> AI model-call admission quota</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-[#627084]">
              Applies to structured authoring and Agent investigations in this tenant and region,
              including Capability Studio, AI activation drafts, and workflow Agent loops. Each
              model call reserves its available token budget before contacting a provider.
              Confirmed unused tokens are released; an unknown charge retains the reservation.
              This is not a provider billing or monetary cap.
            </p>
          </div>
          <Button variant="outline" onClick={() => { void load(); void loadReservations(); }} disabled={loading || saving}><RefreshCw className="size-4" /> Refresh</Button>
        </div>
        {message && <p role="status" className="mt-5 rounded-lg border bg-white p-3 text-sm">{message}</p>}
        {loading && <p className="mt-5 text-sm text-[#627084]">Loading quota…</p>}
        {quota && <>
          <div className="mt-6 grid gap-4 sm:grid-cols-2">
            <section className="rounded-lg border bg-white p-5">
              <h2 className="font-semibold">Tenant and region · UTC {quota.period_start}</h2>
              <p className="mt-3 text-2xl font-semibold">{quota.namespace_used.toLocaleString()} <span className="text-sm font-normal text-[#627084]">used or reserved tokens</span></p>
              <p className="mt-2 text-sm text-[#627084]">Limit: {quota.namespace_limit?.toLocaleString() ?? "Not set"} · Available: {quota.namespace_available?.toLocaleString() ?? "Unbounded"}</p>
            </section>
            <section className="rounded-lg border bg-white p-5">
              <h2 className="font-semibold">Your account · {quota.actor}</h2>
              <p className="mt-3 text-2xl font-semibold">{quota.actor_used.toLocaleString()} <span className="text-sm font-normal text-[#627084]">used or reserved tokens</span></p>
              <p className="mt-2 text-sm text-[#627084]">Limit: {quota.actor_limit?.toLocaleString() ?? "Not set"} · Available: {quota.actor_available?.toLocaleString() ?? "Unbounded"}</p>
              <p className="mt-2 text-xs text-[#627084]">{quota.pending_requests} pending · {quota.unknown_charge_requests} settled with unknown external charge</p>
            </section>
          </div>
          {canManage && <form onSubmit={(event) => void save(event)} className="mt-6 space-y-4 rounded-lg border bg-white p-5">
            <h2 className="font-semibold">Configure admission limits</h2>
            <p className="text-xs text-[#627084]">Blank means no limit. A limit smaller than the selected route budget rejects new calls. Lowering a limit below current usage blocks new admission; it does not erase history. Revision {quota.policy_revision}.</p>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="text-sm font-medium">Tenant and region daily tokens<Input className="mt-1" inputMode="numeric" value={namespaceLimit} onChange={(event) => setNamespaceLimit(event.target.value)} placeholder="No limit" /></label>
              <label className="text-sm font-medium">Per-account daily tokens<Input className="mt-1" inputMode="numeric" value={actorLimit} onChange={(event) => setActorLimit(event.target.value)} placeholder="No limit" /></label>
            </div>
            <label className="block text-sm font-medium">Reason for change<Textarea className="mt-1" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={1000} placeholder="Explain the operational quota change" /></label>
            <Button type="submit" disabled={saving}><Save className="size-4" /> {saving ? "Saving…" : "Save limits"}</Button>
            <p className="text-xs text-[#627084]">Uncertain settled charges require independent human review before any correction. <Link href="/settings/ai/quota-reconciliation" className="text-[#5856d6] underline">First billing adjustment</Link> · <Link href="/settings/ai/quota-supplements" className="text-[#5856d6] underline">Supplemental corrections</Link> · <Link href="/settings/ai/quota-recovery" className="text-[#5856d6] underline">Review abandoned holds</Link></p>
          </form>}
          <section className="mt-6 rounded-lg border bg-white p-5">
            <h2 className="font-semibold">Model-call receipts</h2>
            <p className="mt-2 text-xs leading-5 text-[#627084]">
              Pending calls may still be running. A receipt older than 15 minutes needs investigation;
              an unknown provider charge remains held. This view is read-only and never releases
              tokens without independently reviewed billing evidence.
            </p>
            <div className="mt-4 flex flex-wrap items-end gap-3">
              {canManage && <label className="text-xs font-medium">Visibility
                <select className="mt-1 block h-9 rounded-md border px-2 text-sm" value={reservationScope} onChange={(event) => setReservationScope(event.target.value as "mine" | "namespace")}>
                  <option value="mine">My calls</option><option value="namespace">Tenant and region</option>
                </select>
              </label>}
              <label className="text-xs font-medium">State
                <select className="mt-1 block h-9 rounded-md border px-2 text-sm" value={reservationState} onChange={(event) => setReservationState(event.target.value as "attention" | "pending" | "uncertain" | "all")}>
                  <option value="attention">Needs attention</option><option value="pending">Pending</option><option value="uncertain">Unknown charge</option><option value="all">All</option>
                </select>
              </label>
              <label className="min-w-56 flex-1 text-xs font-medium">Source ID
                <Input className="mt-1" value={sourceFilter} maxLength={36} onChange={(event) => setSourceFilter(event.target.value)} placeholder="Investigation or draft ID" />
              </label>
              <label className="flex h-9 items-center gap-2 text-xs"><input type="checkbox" checked={staleOnly} onChange={(event) => setStaleOnly(event.target.checked)} /> Older than 15 minutes</label>
            </div>
            {reservationError && <p role="alert" className="mt-4 text-sm text-red-700">{reservationError}</p>}
            <div className="mt-4 overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-xs">
                <thead className="border-b text-[#627084]"><tr><th className="py-2 pr-3">Source</th><th className="py-2 pr-3">Actor</th><th className="py-2 pr-3">UTC day</th><th className="py-2 pr-3">State</th><th className="py-2 pr-3 text-right">Held / known</th></tr></thead>
                <tbody>
                  {reservations.map((receipt) => <tr key={receipt.id} className="border-b align-top last:border-0">
                    <td className="py-3 pr-3">
                      <span className="font-medium">{receipt.source_entity_type ?? "Legacy unattributed call"}</span>
                      {receipt.source_entity_id && <span className="block break-all font-mono text-[11px] text-[#627084]">{receipt.source_entity_id}{receipt.source_step !== null ? ` · step ${receipt.source_step}` : ""}</span>}
                      <span className="block break-all font-mono text-[10px] text-muted-foreground">Receipt {receipt.id}</span>
                      <span className="block text-[11px] text-[#627084]">{new Date(receipt.created_at).toLocaleString()}</span>
                    </td>
                    <td className="py-3 pr-3 break-all">{receipt.actor}</td>
                    <td className="py-3 pr-3">{receipt.period_start}</td>
                    <td className="py-3 pr-3">{receipt.status === "reserved" ? "Pending · charge unconfirmed" : receipt.supplemental_adjustment_count > 0 ? `Manually adjusted · ${receipt.supplemental_adjustment_count} supplemental correction${receipt.supplemental_adjustment_count === 1 ? "" : "s"}` : receipt.adjustment_id ? "Manually adjusted · original charge uncertain" : receipt.external_charge_unknown ? "Settled · charge unknown" : "Settled · usage known"}</td>
                    <td className="py-3 pr-3 text-right tabular-nums">{receipt.effective_charged_tokens.toLocaleString()} / {receipt.known_tokens.toLocaleString()}{receipt.adjustment_id && <span className="block text-[10px] text-[#627084]">original hold {receipt.charged_tokens.toLocaleString()}</span>}</td>
                  </tr>)}
                </tbody>
              </table>
              {!reservationLoading && reservations.length === 0 && !reservationError && <p className="py-5 text-sm text-[#627084]">No receipts match these filters.</p>}
            </div>
            {nextCursor && <Button variant="outline" className="mt-4" disabled={reservationLoading} onClick={() => void loadReservations(nextCursor)}>Load more</Button>}
            {reservationLoading && <p className="mt-3 text-xs text-[#627084]">Loading receipts…</p>}
          </section>
        </>}
      </div>
    </main>
  );
}
