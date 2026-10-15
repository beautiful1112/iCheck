"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, RefreshCw, ShieldAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";

type RecoveryRecord = {
  id: string;
  actor: string;
  device_id: string | null;
  brief: string;
  protocol: string;
  status: "generating" | "failed" | "succeeded";
  created_at: string;
  recovery_available_at: string;
  request_sha256: string;
};

const base = "/assets/activation-policy-proposals";

export default function ProposalRecoveryPage() {
  const [rows, setRows] = useState<RecoveryRecord[]>([]);
  const [actor, setActor] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [clock, setClock] = useState<number | null>(null);

  const load = useCallback(async (owner = actor, device = deviceId) => {
    setLoading(true);
    setMessage(null);
    try {
      const query = new URLSearchParams({ limit: "100" });
      if (owner.trim()) query.set("actor", owner.trim());
      if (device.trim()) query.set("device_id", device.trim());
      setRows(await apiFetch<RecoveryRecord[]>(`${base}/admin/recovery?${query}`));
    } catch (error) {
      setRows([]);
      setMessage(error instanceof Error ? error.message : "Unable to load recovery requests.");
    } finally {
      setLoading(false);
    }
  }, [actor, deviceId]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load("", ""), 0);
    const interval = window.setInterval(() => setClock(Date.now()), 30_000);
    const initial = window.setTimeout(() => setClock(Date.now()), 0);
    return () => {
      window.clearTimeout(timer);
      window.clearTimeout(initial);
      window.clearInterval(interval);
    };
    // Initial load is deliberately unfiltered; later filtering requires Submit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function interrupt(row: RecoveryRecord) {
    setBusy(row.id);
    setMessage(null);
    try {
      await apiFetch(`${base}/${encodeURIComponent(row.id)}/admin-interrupt`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          expected_request_sha256: row.request_sha256,
          reason: reasons[row.id]?.trim() || "",
        }),
      });
      setRows((current) => current.filter((item) => item.id !== row.id));
      setMessage(`Request ${row.id} marked interrupted. External provider charge remains unknown.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Recovery failed; refresh and retry.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="min-h-screen bg-[#f3f4f7] px-4 py-8 text-[#2c384a] sm:px-6">
      <div className="mx-auto max-w-5xl">
        <Link href="/settings/ai" className="inline-flex items-center gap-2 text-sm text-[#5856d6] hover:underline">
          <ArrowLeft className="size-4" /> AI settings
        </Link>
        <div className="mt-5 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="flex items-center gap-3 text-2xl font-semibold">
              <ShieldAlert className="size-7 text-[#5856d6]" /> Orphaned proposal recovery
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-[#627084]">
              Global administrators can close a request that has been generating for over two hours
              when its original operator cannot act. This does not cancel the provider call, refund
              tokens, create a policy, or retry generation. The request key remains spent.
            </p>
          </div>
          <Button variant="outline" onClick={() => void load()} disabled={loading || busy !== null}>
            <RefreshCw className="size-4" /> Refresh
          </Button>
        </div>

        <form className="mt-6 flex flex-wrap items-end gap-3 rounded-lg border bg-white p-4" onSubmit={(event) => { event.preventDefault(); void load(); }}>
          <label className="min-w-64 flex-1 text-sm font-medium">
            Owner account
            <Input className="mt-1" value={actor} onChange={(event) => setActor(event.target.value)} placeholder="Exact account, optional" />
          </label>
          <label className="min-w-64 flex-1 text-sm font-medium">
            Device ID
            <Input className="mt-1" value={deviceId} onChange={(event) => setDeviceId(event.target.value)} placeholder="Exact ID, optional" />
          </label>
          <Button type="submit" disabled={loading || busy !== null}>Filter</Button>
        </form>

        {message && <p role="status" className="mt-4 rounded-lg border bg-white p-3 text-sm">{message}</p>}
        <p className="mt-5 text-sm text-[#627084]">
          {loading ? "Loading requests…" : `${rows.length} generating request${rows.length === 1 ? "" : "s"} shown (maximum 100, oldest first).`}
        </p>
        <div className="mt-3 space-y-4">
          {rows.map((row) => {
            const eligible = clock !== null && clock >= Date.parse(row.recovery_available_at);
            const reason = reasons[row.id] || "";
            return (
              <section key={row.id} className="rounded-lg border border-[#d8dbe0] bg-white p-5 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h2 className="font-semibold">{row.actor}</h2>
                    <p className="mt-1 text-xs text-[#627084]">Request {row.id} · {row.protocol}{row.device_id ? ` · Device ${row.device_id}` : ""}</p>
                  </div>
                  <span className="rounded bg-[#f3f4f7] px-2 py-1 text-xs font-medium">
                    {eligible ? "Eligible for recovery" : `Available ${new Date(row.recovery_available_at).toLocaleString()}`}
                  </span>
                </div>
                <p className="mt-3 whitespace-pre-wrap text-sm">{row.brief}</p>
                <p className="mt-2 break-all font-mono text-xs text-[#627084]">SHA-256: {row.request_sha256}</p>
                <p className="mt-1 text-xs text-[#627084]">Started {new Date(row.created_at).toLocaleString()}</p>
                <label className="mt-4 block text-sm font-medium" htmlFor={`reason-${row.id}`}>Incident reason (minimum 10 characters)</label>
                <Textarea
                  id={`reason-${row.id}`}
                  className="mt-1"
                  value={reason}
                  onChange={(event) => setReasons((current) => ({ ...current, [row.id]: event.target.value }))}
                  placeholder="Why the original operator cannot recover this request"
                  maxLength={1000}
                  disabled={!eligible || busy !== null}
                />
                <Button
                  className="mt-3"
                  variant="destructive"
                  disabled={!eligible || reason.trim().length < 10 || busy !== null}
                  onClick={() => void interrupt(row)}
                >
                  {busy === row.id ? "Closing…" : "Mark request interrupted"}
                </Button>
              </section>
            );
          })}
        </div>
      </div>
    </main>
  );
}
