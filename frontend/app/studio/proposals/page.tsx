"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  FileSearch,
  GitBranch,
  Loader2,
  Network,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type ProposalStatus = "proposed" | "published" | "rejected";

type TopologyProposal = {
  id: string;
  investigation_id: string;
  status: ProposalStatus;
  rationale: string;
  spec: {
    artifact_name: string;
    description: string;
    node_types: string[];
    edge_types: string[];
    device_kinds: string[];
    knowledge_entity_types: string[];
    knowledge_relationship_types: string[];
    sites: string[];
    layout: string;
    group_by: string;
    max_nodes: number;
    max_edges: number;
  };
  validation_report: {
    preview: {
      nodes: Array<{ id: string; label: string; node_type: string; group: string | null }>;
      edges: Array<{ id: string; source: string; target: string; edge_type: string }>;
      node_count: number;
      edge_count: number;
      nodes_truncated: boolean;
      edges_truncated: boolean;
    };
  };
  uncertainty: string[];
  authorization_scope: Record<string, unknown>;
  evidence: Array<{
    evidence_reference_id: string;
    evidence_type: string;
    evidence_id: string;
    summary: string;
    observed_at: string | null;
  }>;
  reviewed_by: string | null;
  review_reason: string | null;
  reviewed_at: string | null;
  artifact_id: string | null;
  artifact_version_id: string | null;
  created_at: string;
};

function statusClass(status: ProposalStatus) {
  if (status === "published") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (status === "rejected") return "border-slate-200 bg-slate-50 text-muted-foreground";
  return "border-amber-200 bg-amber-50 text-amber-700";
}

export default function TopologyProposalReviewPage() {
  const [proposals, setProposals] = useState<TopologyProposal[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<"all" | ProposalStatus>("all");
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const query = statusFilter === "all" ? "" : `?status=${statusFilter}`;
      const data = await apiFetch<TopologyProposal[]>(`/topology/proposals${query}`);
      setProposals(data);
      setSelectedId((current) => data.some((item) => item.id === current) ? current : data[0]?.id || null);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load topology proposals");
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const selected = useMemo(
    () => proposals.find((item) => item.id === selectedId) || null,
    [proposals, selectedId],
  );

  async function review(decision: "publish" | "reject") {
    if (!selected || reason.trim().length < 3) return;
    setBusy(decision);
    try {
      const updated = await apiFetch<TopologyProposal>(`/topology/proposals/${selected.id}/${decision}`, {
        method: "POST",
        body: JSON.stringify({ actor: "web.capability-reviewer", reason }),
      });
      setProposals((current) => current.map((item) => item.id === updated.id ? updated : item));
      setReason("");
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : `Unable to ${decision} proposal`);
    } finally {
      setBusy(null);
    }
  }

  const preview = selected?.validation_report.preview;

  return (
    <main className="min-h-screen bg-[#f5f6f8] text-slate-900">
      <header className="flex h-16 items-center justify-between border-b border-slate-200 bg-white px-5">
        <div className="flex items-center gap-3">
          <Link href="/studio" className="rounded-md p-2 text-muted-foreground hover:bg-slate-100" aria-label="Back to Capability Studio"><ArrowLeft className="size-4" /></Link>
          <span className="grid size-9 place-items-center rounded-xl bg-sky-600 text-white"><ShieldCheck className="size-4" /></span>
          <div><h1 className="text-sm font-semibold">AI topology proposal review</h1><p className="text-xs text-muted-foreground">Evidence → scoped preview → reasoned human publish → immutable Artifact</p></div>
        </div>
        <div className="flex items-center gap-2">
          <select aria-label="Proposal state filter" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as "all" | ProposalStatus)} className="h-9 rounded-md border border-slate-200 bg-white px-3 text-xs"><option value="all">All states</option><option value="proposed">Proposed</option><option value="published">Published</option><option value="rejected">Rejected</option></select>
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}><RefreshCw className={cn("size-3.5", loading && "animate-spin")} /> Refresh</Button>
        </div>
      </header>
      {error ? <div className="flex items-center gap-2 border-b border-red-200 bg-red-50 px-5 py-2 text-xs text-red-700"><XCircle className="size-4" />{error}</div> : null}

      <div className="grid min-h-[calc(100vh-64px)] grid-cols-[340px_minmax(0,1fr)]">
        <aside className="border-r border-slate-200 bg-white p-3">
          <div className="space-y-2">{proposals.map((proposal) => <button key={proposal.id} onClick={() => { setSelectedId(proposal.id); setReason(""); }} className={cn("w-full rounded-xl border p-3 text-left", selectedId === proposal.id ? "border-sky-300 bg-sky-50" : "border-slate-100 hover:bg-slate-50")}><div className="flex items-start justify-between gap-2"><span className="text-xs font-semibold">{proposal.spec.artifact_name}</span><Badge variant="outline" className={cn("text-[9px]", statusClass(proposal.status))}>{proposal.status}</Badge></div><p className="mt-2 line-clamp-2 text-[10px] leading-4 text-muted-foreground">{proposal.rationale}</p><p className="mt-2 font-mono text-[9px] text-muted-foreground">Investigation {proposal.investigation_id.slice(0, 8)} · {proposal.evidence.length} evidence</p></button>)}</div>
          {!loading && !proposals.length ? <div className="py-20 text-center text-xs text-muted-foreground"><FileSearch className="mx-auto mb-3 size-6 text-slate-300" />No topology proposals in this state.</div> : null}
        </aside>

        <section className="p-6 lg:p-8">
          {selected && preview ? <div className="mx-auto max-w-6xl space-y-5">
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm"><div className="flex flex-wrap items-start justify-between gap-4"><div><div className="flex gap-2"><Badge variant="outline" className={statusClass(selected.status)}>{selected.status}</Badge><Badge variant="outline">AI proposal · not deterministic truth</Badge></div><h2 className="mt-3 text-xl font-semibold">{selected.spec.artifact_name}</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">{selected.spec.description}</p><p className="mt-3 text-xs leading-5 text-muted-foreground">{selected.rationale}</p></div><Network className="size-7 text-sky-600" /></div></div>

            <div className="grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
              <div className="rounded-2xl border border-slate-200 bg-white shadow-sm"><div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h3 className="text-sm font-semibold">Scoped validation preview</h3><p className="mt-1 text-[11px] text-muted-foreground">Generated under the Investigation authorization snapshot</p></div><Badge variant="outline">{preview.node_count} nodes · {preview.edge_count} edges</Badge></div><div className="grid gap-2 p-4 sm:grid-cols-2">{preview.nodes.slice(0, 20).map((node) => <div key={node.id} className="flex items-center gap-3 rounded-xl border border-slate-100 bg-slate-50/60 p-3"><span className="grid size-8 place-items-center rounded-lg bg-white text-sky-600 shadow-sm"><GitBranch className="size-4" /></span><div className="min-w-0"><p className="truncate text-xs font-medium">{node.label}</p><p className="mt-0.5 text-[9px] text-muted-foreground">{node.node_type}{node.group ? ` · ${node.group}` : ""}</p></div></div>)}</div>{preview.nodes_truncated || preview.edges_truncated ? <p className="border-t border-amber-100 bg-amber-50 px-5 py-2 text-[10px] text-amber-700">Preview is bounded; publication revalidates against current inventory.</p> : null}</div>

              <div className="space-y-5"><div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><h3 className="text-sm font-semibold">Declarative contract</h3><div className="mt-4 space-y-3 text-xs"><div><p className="text-[9px] uppercase tracking-wide text-muted-foreground">Nodes</p><p className="mt-1 text-slate-700">{selected.spec.node_types.join(" · ")}</p></div><div><p className="text-[9px] uppercase tracking-wide text-muted-foreground">Edges</p><p className="mt-1 text-slate-700">{selected.spec.edge_types.join(" · ") || "none"}</p></div><div><p className="text-[9px] uppercase tracking-wide text-muted-foreground">Selectors</p><p className="mt-1 text-slate-700">{[...selected.spec.sites, ...selected.spec.device_kinds, ...selected.spec.knowledge_entity_types].join(" · ") || "current authorized inventory"}</p></div><div><p className="text-[9px] uppercase tracking-wide text-muted-foreground">Layout and caps</p><p className="mt-1 text-slate-700">{selected.spec.layout} · group {selected.spec.group_by} · {selected.spec.max_nodes}/{selected.spec.max_edges}</p></div></div></div>
              <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><h3 className="text-sm font-semibold">Cited Investigation evidence</h3><div className="mt-3 space-y-2">{selected.evidence.map((item) => <div key={item.evidence_reference_id} className="rounded-lg bg-slate-50 px-3 py-2 text-[10px] leading-4 text-slate-600"><span className="font-semibold text-emerald-600">{item.evidence_type}</span> · {item.summary}</div>)}</div>{selected.uncertainty.length ? <p className="mt-3 text-[10px] leading-4 text-amber-700">Uncertainty: {selected.uncertainty.join(" · ")}</p> : null}</div></div>
            </div>

            {selected.status === "proposed" ? <div className="rounded-2xl border border-amber-200 bg-amber-50/70 p-5"><div className="flex flex-col gap-3 lg:flex-row lg:items-center"><div className="flex-1"><h3 className="text-sm font-semibold text-amber-900">Human governance gate</h3><p className="mt-1 text-[11px] text-amber-800">A reason is required. Publish atomically creates, validates, and publishes an ordinary immutable Topology Artifact.</p></div><Input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Required review reason" className="bg-white text-xs lg:max-w-md" /><Button variant="outline" disabled={reason.trim().length < 3 || busy !== null} onClick={() => void review("reject")}>Reject</Button><Button className="bg-emerald-600 hover:bg-emerald-700" disabled={reason.trim().length < 3 || busy !== null} onClick={() => void review("publish")}>{busy === "publish" ? <Loader2 className="size-4 animate-spin" /> : <CheckCircle2 className="size-4" />} Publish Artifact</Button></div></div> : <div className="rounded-2xl border border-slate-200 bg-white p-5 text-xs text-slate-600">Reviewed by {selected.reviewed_by}: {selected.review_reason}{selected.artifact_id ? <div className="mt-3 flex gap-2"><Button asChild variant="outline" size="sm"><Link href="/studio/artifacts">Open Artifact library</Link></Button><Button asChild size="sm"><Link href="/topology">Open live topology</Link></Button></div> : null}</div>}
          </div> : <div className="grid min-h-[520px] place-items-center text-center"><div><ShieldCheck className="mx-auto size-8 text-slate-300" /><h2 className="mt-3 text-sm font-semibold">No proposal selected</h2><p className="mt-1 text-xs text-muted-foreground">Topology proposals appear only after an evidence-backed Investigation completes.</p></div></div>}
        </section>
      </div>
    </main>
  );
}
