"use client";

import {useCallback, useEffect, useRef, useState} from "react";
import Link from "next/link";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";
import {canAuthorDashboard, dashboardAuthoringRequest, type DashboardTarget} from "@/lib/dashboard-authoring";
import type {GrafanaConnection, GrafanaPrincipal} from "@/lib/grafana-plugin";
import {Button} from "@/components/ui/button";
import {Textarea} from "@/components/ui/textarea";
import {StudioAgentConversation} from "@/components/studio-agent-conversation";

type Run = {id: string; title: string; status: string; scope: Record<string, unknown>};
type History = {items: Run[]; next_cursor: string | null};

export function DashboardAiAuthoring({connection, principal, target, onNew, onProposal}: {
  connection: GrafanaConnection; principal: GrafanaPrincipal | null; target: DashboardTarget | null;
  onNew: () => void; onProposal: (id: string) => void;
}) {
  const [brief, setBrief] = useState("");
  const [runs, setRuns] = useState<Run[]>([]);
  const [selected, setSelected] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const epoch = useRef(0);
  const submitting = useRef(false);
  const mayAuthor = canAuthorDashboard(principal);
  const mayRead = principal?.permissions.some(value => ["*", "investigations.read"].includes(value));
  const history = useCallback((next?: string) => apiFetch<History>(
    `/agent/investigations/page?capability_task=grafana-dashboard&grafana_connection_id=${connection.id}&limit=20${next ? `&cursor=${next}` : ""}`), [connection.id]);

  useEffect(() => {
    const context = epoch;
    const current = ++context.current;
    const reset = () => {context.current++; setRuns([]); setSelected(""); setBrief(""); setCursor(null); setError("");};
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    const timer = window.setTimeout(() => {
      if (!mayRead) return;
      void (async () => {
        try {
          const result = await history();
          const id = new URLSearchParams(window.location.search).get("investigation");
          let chosen = result.items.find(row => row.id === id);
          if (id && /^[0-9a-f-]{36}$/.test(id) && !chosen) chosen = await apiFetch<Run>(`/agent/investigations/${id}`);
          if (chosen && (chosen.scope.capability_task !== "grafana-dashboard" || chosen.scope.grafana_connection_id !== connection.id)) chosen = undefined;
          if (current !== epoch.current) return;
          setRuns(chosen && !result.items.some(row => row.id === chosen.id) ? [chosen, ...result.items] : result.items);
          setCursor(result.next_cursor); setSelected(chosen?.id || "");
        } catch (cause) {if (current === epoch.current) setError(cause instanceof Error ? cause.message : "Unable to load AI conversations");}
      })();
    }, 0);
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => {context.current++; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage);};
  }, [history, connection.id, mayRead]);

  function choose(id: string) {
    setSelected(id);
    const params = new URLSearchParams(window.location.search);
    params.set("connection", connection.id); params.delete("change");
    if (id) params.set("investigation", id); else params.delete("investigation");
    window.history.replaceState(null, "", `/dashboards?${params}`);
  }
  async function author(content: string, changeId?: string) {
    if (submitting.current || !mayAuthor || !content.trim()) return;
    submitting.current = true; setBusy(true); setError("");
    const current = epoch.current;
    try {
      const created = await apiFetch<Run>("/agent/investigations", {method: "POST",
        body: JSON.stringify(dashboardAuthoringRequest(connection.id, content, target, changeId))});
      if (current !== epoch.current) return;
      setRuns(old => [created, ...old.filter(row => row.id !== created.id)]); choose(created.id);
      await apiFetch(`/agent/investigations/${created.id}/start`, {method: "POST", body: JSON.stringify({actor: "web.dashboards"})});
      if (current === epoch.current) setBrief("");
    } catch (cause) {if (current === epoch.current) setError(cause instanceof Error ? cause.message : "Unable to start AI authoring; inspect the saved conversation before retrying");}
    finally {submitting.current = false; if (current === epoch.current) setBusy(false);}
  }
  async function older() {
    if (!cursor || busy) return;
    const current = epoch.current; setBusy(true);
    try {const result = await history(cursor); if (current === epoch.current) {
      setRuns(old => [...old, ...result.items.filter(row => !old.some(item => item.id === row.id))]); setCursor(result.next_cursor);
    }} catch (cause) {if (current === epoch.current) setError(cause instanceof Error ? cause.message : "Unable to load older conversations");}
    finally {if (current === epoch.current) setBusy(false);}
  }
  return <section id="dashboard-ai" className="space-y-4 rounded-xl border bg-white p-5" aria-label="Customize dashboards with AI">
    <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="font-semibold">{target ? `Edit with AI: ${target.title}` : "Create a dashboard with AI"}</h2>
      {target && <Button variant="outline" disabled={busy} onClick={onNew}>Create new instead</Button>}</div>
    <form className="space-y-3" onSubmit={event => {event.preventDefault(); void author(brief);}}>
      <label className="block text-sm">{target ? "What would you like to change?" : "What should this dashboard show?"}
        <Textarea className="mt-2" rows={3} minLength={1} maxLength={8000} required value={brief} disabled={busy}
          onChange={event => setBrief(event.target.value)} placeholder={target ? "Add interface error rates and a device filter. Keep the existing panels." : "Show network interface traffic, errors and availability, grouped by device."}/></label>
      <p className="text-xs text-muted-foreground">AI discovers available metrics and prepares a proposal. Model charges may apply within your configured budgets. Nothing is applied to Grafana until you review and confirm below.</p>
      <Button disabled={busy || !mayAuthor || !brief.trim()}>{busy ? "Starting…" : target ? "Ask AI to revise" : "Create with AI"}</Button>
      {!mayAuthor && <p className="text-xs">Requires workspace-wide metric-read and investigation read/create permissions.</p>}
    </form>
    {error && <p role="alert" className="text-sm text-amber-800">{error}</p>}
    {mayRead && <details><summary className="cursor-pointer text-sm">Saved AI conversations ({runs.length}{cursor ? "+" : ""})</summary>
      <div className="mt-3 space-y-2"><label className="block text-sm">Open a conversation<select className="mt-1 w-full min-w-0 max-w-full rounded border p-2" value={selected} disabled={busy} onChange={event => choose(event.target.value)}>
        <option value="">Choose a saved conversation</option>{runs.map(row => <option key={row.id} value={row.id}>{row.title}</option>)}</select></label>
        {cursor && <Button variant="outline" disabled={busy} onClick={() => void older()}>Load older conversations</Button>}
        <p className="text-xs text-muted-foreground">Conversations from this page are saved here. Earlier Studio and general chat runs remain in <Link className="underline" href="/">AI Operator</Link>.</p>
      </div></details>}
    {selected && <StudioAgentConversation key={selected} id={selected} onProposal={onProposal}
      onRefine={mayAuthor ? (content, changeId) => author(content, changeId) : undefined}/>}
  </section>;
}
