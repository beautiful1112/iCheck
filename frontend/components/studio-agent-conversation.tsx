"use client";
import {useEffect, useRef, useState} from "react";
import Link from "next/link";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";
import {GrafanaResult} from "@/components/grafana-result";
import {Textarea} from "@/components/ui/textarea";
import {proposalReference} from "@/lib/grafana-plugin";

type Run = {id: string; objective: string; scope?: Record<string, unknown>; status: string; conclusion: string | null; uncertainty: string[];
  escalation_reason: string | null; tokens_used: number; tool_calls_used: number};
type Call = {id: string; tool_name: string; status: string; result: Record<string, unknown>};
type Execution = {id: string; status: string};

/** Native LangGraph run display. It never owns an agent loop or a Grafana write. */
export function StudioAgentConversation({id, onRefine, onProposal}: {id: string; onRefine?: (content: string, changeId: string) => Promise<void>; onProposal?: (id: string) => void}) {
  const [run, setRun] = useState<Run | null>(null);
  const [calls, setCalls] = useState<Call[]>([]);
  const [execution, setExecution] = useState<Execution | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [refinement, setRefinement] = useState("");
  const epoch = useRef(0);
  useEffect(() => {
    const context = epoch;
    const current = ++context.current;
    let active = true;
    const controller = new AbortController();
    const reset = () => {active = false; context.current++; controller.abort(); setRun(null); setCalls([]); setExecution(null); setError(null); setBusy(false); setRefinement("");};
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    const load = async () => {
      try {
        const [next, tools, lease] = await Promise.all([
          apiFetch<Run>(`/agent/investigations/${id}`, {signal: controller.signal}),
          apiFetch<Call[]>(`/agent/investigations/${id}/tool-calls`, {signal: controller.signal}),
          apiFetch<Execution>(`/agent/investigations/${id}/execution`, {signal: controller.signal}).catch(() => null)]);
        if (!active || current !== context.current) return;
        setRun(next); setCalls(tools); setExecution(lease); setError(null);
      } catch (cause) {if (active && current === context.current) setError(cause instanceof Error ? cause.message : "Unable to read this run");}
    };
    const timer = window.setTimeout(() => void load(), 0);
    const interval = window.setInterval(() => void load(), 5000);
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => {reset(); window.clearTimeout(timer); window.clearInterval(interval); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage);};
  }, [id]);
  async function cancel() {
    if (!execution || busy) return;
    const current = epoch.current;
    setBusy(true);
    try {
      await apiFetch(`/agent/executions/${execution.id}/cancel`, {method: "POST", body: JSON.stringify({actor: "web.capabilityStudio", reason: "Operator cancelled the Studio run"})});
      if (current === epoch.current) setError("Cancellation requested; waiting for the worker to stop.");
    } catch (cause) {if (current === epoch.current) setError(cause instanceof Error ? cause.message : "Cancellation failed");}
    finally {if (current === epoch.current) setBusy(false);}
  }
  const proposal = [...calls].reverse().filter(call => call.status === "succeeded").map(call => proposalReference(call.result)).find(Boolean);
  const uncertain = proposal && ["unknown", "applying"].includes(proposal.status);
  const proposalId = proposal?.id;
  useEffect(() => {if (proposalId) onProposal?.(proposalId);}, [proposalId, onProposal]);
  return <section className="space-y-4 rounded-xl border bg-white p-5" aria-label="AI builder conversation">
    <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="font-semibold">AI builder conversation · {run?.status || "Loading"}</h2>
      {execution && ["queued", "running"].includes(execution.status) ? <Button variant="outline" disabled={busy} onClick={() => void cancel()}>Stop this run</Button> : null}</div>
    {error ? <p role="status" className="text-sm text-amber-800">{error}</p> : null}
    <p className="whitespace-pre-wrap break-words text-sm">{typeof run?.scope?.authoring_brief === "string" ? run.scope.authoring_brief : run?.objective}</p>
    <p className="text-xs text-muted-foreground">{run?.tool_calls_used || 0} tool calls · {run?.tokens_used || 0} known tokens. This run can propose a dashboard, not apply it.</p>
    <ul className="space-y-2 text-sm">{calls.slice(-12).map(call => <li key={call.id}><p>{call.tool_name} · {call.status}</p>
      {call.status === "succeeded" ? <GrafanaResult result={call.result} toolName={call.tool_name} /> : null}</li>)}</ul>
    {run?.conclusion ? <p className="whitespace-pre-wrap rounded bg-slate-50 p-4 text-sm">{run.conclusion}</p> : null}
    {run?.uncertainty?.length ? <p className="text-sm text-amber-800">Unknown: {run.uncertainty.join(" · ")}</p> : null}
    {run?.escalation_reason ? <p className="text-sm">Next action: {run.escalation_reason}</p> : null}
    {onRefine && proposal && run && ["completed", "escalated", "failed"].includes(run.status) ? <form className="space-y-2" onSubmit={event => {event.preventDefault(); if (busy || uncertain || !refinement.trim()) return; setBusy(true); void onRefine(refinement, proposal.id).finally(() => setBusy(false));}}>
      <label className="block text-sm">Tell AI how to revise this dashboard<Textarea className="mt-2" value={refinement} onChange={event => setRefinement(event.target.value)} minLength={1} maxLength={8000} rows={3} /></label>
      <Button variant="outline" disabled={busy || Boolean(uncertain) || !refinement.trim()}>Preview dashboard revision</Button>
      {uncertain ? <p className="text-xs text-amber-800">Inspect the uncertain write in Dashboard changes before proposing another revision.</p> : null}
    </form> : null}
    <div className="flex flex-wrap gap-4 text-sm"><Link className="text-violet-700 underline" href={`/dashboards`}>Review dashboard proposals</Link>
      <Link className="text-violet-700 underline" href={`/?investigation=${encodeURIComponent(id)}`}>Open full evidence in AI Operator</Link></div>
    <details><summary className="cursor-pointer text-sm">Advanced tool results</summary><pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(calls.slice(-12), null, 2)}</pre></details>
  </section>;
}
