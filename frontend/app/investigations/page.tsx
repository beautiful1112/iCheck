"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowUpRight,
  FileSearch,
  Loader2,
  Plus,
  RefreshCw,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type InvestigationStatus =
  | "pending"
  | "running"
  | "waiting_approval"
  | "completed"
  | "escalated"
  | "failed"
  | "cancelled";

type Investigation = {
  id: string;
  title: string;
  objective: string;
  status: InvestigationStatus;
  conclusion: string | null;
  confidence: number | null;
  iterations_used: number;
  tool_calls_used: number;
  created_at: string;
  updated_at: string;
};

type InvestigationPage = {
  items: Investigation[];
  next_cursor: string | null;
};

const statusOptions: Array<{ value: InvestigationStatus | ""; label: string }> = [
  { value: "", label: "All statuses" },
  { value: "pending", label: "Pending" },
  { value: "running", label: "Running" },
  { value: "waiting_approval", label: "Waiting for approval" },
  { value: "completed", label: "Completed" },
  { value: "escalated", label: "Escalated" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
];

function statusTone(status: InvestigationStatus): string {
  if (status === "completed") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (status === "running") return "border-violet-200 bg-violet-50 text-violet-700";
  if (status === "failed" || status === "escalated") return "border-red-200 bg-red-50 text-red-700";
  if (status === "waiting_approval") return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-slate-200 bg-slate-50 text-slate-600";
}

function displayStatus(status: InvestigationStatus): string {
  return status.replaceAll("_", " ");
}

function displayDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

export default function InvestigationHistoryPage() {
  const [status, setStatus] = useState<InvestigationStatus | "">("");
  const [items, setItems] = useState<Investigation[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestGeneration = useRef(0);

  const loadPage = useCallback(async (cursor?: string) => {
    const generation = ++requestGeneration.current;
    const append = Boolean(cursor);
    if (append) setLoadingMore(true);
    else {
      setLoading(true);
      setItems([]);
      setNextCursor(null);
    }
    setError(null);
    const query = new URLSearchParams({ limit: "50" });
    if (status) query.set("status", status);
    if (cursor) query.set("cursor", cursor);
    try {
      const page = await apiFetch<InvestigationPage>(
        `/agent/investigations/page?${query.toString()}`,
      );
      if (requestGeneration.current !== generation) return;
      setItems((current) => {
        if (!append) return page.items;
        const seen = new Set(current.map((item) => item.id));
        return [...current, ...page.items.filter((item) => !seen.has(item.id))];
      });
      setNextCursor(page.next_cursor);
    } catch (caught) {
      if (requestGeneration.current !== generation) return;
      setError(caught instanceof Error ? caught.message : "Unable to load investigation history");
    } finally {
      if (requestGeneration.current === generation) {
        setLoading(false);
        setLoadingMore(false);
      }
    }
  }, [status]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadPage(), 0);
    return () => {
      window.clearTimeout(timer);
      requestGeneration.current += 1;
    };
  }, [loadPage]);

  return (
    <main className="min-h-screen bg-[#f5f6f8] px-4 py-8 text-slate-900 sm:px-6 lg:px-10">
      <div className="mx-auto max-w-5xl">
        <div className="mb-7 flex flex-wrap items-start justify-between gap-4">
          <div>
            <Link href="/" className="mb-4 inline-flex items-center gap-1.5 text-xs font-medium text-violet-700 hover:underline">
              <ArrowLeft className="size-3.5" /> AI operator
            </Link>
            <div className="flex items-center gap-3">
              <span className="grid size-10 place-items-center rounded-xl bg-violet-100 text-violet-700">
                <FileSearch className="size-5" />
              </span>
              <div>
                <h1 className="text-2xl font-semibold tracking-tight">Investigation history</h1>
                <p className="mt-1 text-sm text-muted-foreground">Durable sessions, conclusions, and evidence-backed operator work.</p>
              </div>
            </div>
          </div>
          <Button asChild className="gap-2 bg-violet-600 text-white hover:bg-violet-700">
            <Link href="/">
              <Plus className="size-4" /> New investigation
            </Link>
          </Button>
        </div>

        <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm" aria-labelledby="history-heading">
          <div className="flex flex-wrap items-end justify-between gap-4 border-b border-slate-100 px-5 py-4 sm:px-6">
            <div>
              <h2 id="history-heading" className="text-sm font-semibold">Operator sessions</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                {items.length} loaded{nextCursor ? " · more available" : ""}. Open a session to inspect its live trace, evidence, and tool calls.
              </p>
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <label className="flex flex-col gap-1 text-xs font-medium text-slate-600">
                Status
                <select
                  value={status}
                  onChange={(event) => setStatus(event.target.value as InvestigationStatus | "")}
                  className="h-9 min-w-40 rounded-lg border border-slate-200 bg-white px-3 text-xs text-slate-800 outline-none focus:border-violet-400"
                >
                  {statusOptions.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
              <Button variant="outline" size="sm" onClick={() => void loadPage()} disabled={loading || loadingMore} aria-label="Refresh investigation history">
                <RefreshCw className={cn("size-3.5", loading && "animate-spin")} /> Refresh
              </Button>
            </div>
          </div>

          {error ? (
            <div role="alert" className="m-5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
              {error}
            </div>
          ) : null}
          {loading ? (
            <div className="grid min-h-48 place-items-center text-sm text-muted-foreground">
              <span className="flex items-center gap-2"><Loader2 className="size-4 animate-spin" /> Loading history…</span>
            </div>
          ) : items.length ? (
            <div className="divide-y divide-slate-100">
              {items.map((item) => (
                <Link
                  key={item.id}
                  href={`/?investigation=${encodeURIComponent(item.id)}`}
                  className="group flex flex-col gap-3 px-5 py-4 transition-colors hover:bg-slate-50 focus-visible:bg-violet-50 sm:flex-row sm:items-start sm:justify-between sm:px-6"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="truncate text-sm font-semibold text-slate-800 group-hover:text-violet-700">{item.title}</h3>
                      <Badge variant="outline" className={cn("capitalize", statusTone(item.status))}>{displayStatus(item.status)}</Badge>
                    </div>
                    <p className="mt-1 line-clamp-2 text-xs leading-5 text-muted-foreground">{item.conclusion || item.objective}</p>
                    <p className="mt-2 text-[11px] text-muted-foreground">Started {displayDate(item.created_at)} · Updated {displayDate(item.updated_at)}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-3 text-[11px] text-muted-foreground">
                    <span>{item.iterations_used} iteration{item.iterations_used === 1 ? "" : "s"} · {item.tool_calls_used} tool{item.tool_calls_used === 1 ? "" : "s"}</span>
                    {item.confidence !== null ? <span>{Math.round(item.confidence * 100)}% confidence</span> : null}
                    <ArrowUpRight className="size-4 text-muted-foreground group-hover:text-violet-700" />
                  </div>
                </Link>
              ))}
            </div>
          ) : !error ? (
            <div className="px-5 py-14 text-center text-sm text-muted-foreground">No investigations match this status yet.</div>
          ) : null}

          {nextCursor && !loading ? (
            <div className="border-t border-slate-100 px-5 py-4 text-center">
              <Button variant="outline" onClick={() => void loadPage(nextCursor)} disabled={loadingMore}>
                {loadingMore ? <Loader2 className="size-4 animate-spin" /> : null} Load more
              </Button>
            </div>
          ) : null}
        </section>
      </div>
    </main>
  );
}
