"use client";

import Link from "next/link";
import {useEffect, useState} from "react";
import {apiFetch} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";
import {Textarea} from "@/components/ui/textarea";

type Need = {id: string; description: string; reason: string; kind: string; studio_url: string};
export function InvestigationAssistance({id, status, parentId, canContinue, onContinued}: {
  id: string; status: string; parentId?: string | null; canContinue: boolean; onContinued: (id: string) => void;
}) {
  const [requests, setRequests] = useState<Need[]>([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let current = true;
    apiFetch<Need[]>(`/autonomy/investigations/${id}/requests`).then(rows => {if (current) setRequests(rows);})
      .catch(cause => {if (current) setError(cause instanceof Error ? cause.message : "Unable to load capability requests");});
    return () => {current = false;};
  }, [id, status]);
  const terminal = !["pending", "running", "waiting_approval"].includes(status);
  async function continueRun() {
    if (!message.trim() || busy) return;
    setBusy(true); setError("");
    try {
      const next = await apiFetch<{id: string}>(`/autonomy/investigations/${id}/continue`, {
        method: "POST", body: JSON.stringify({message: message.trim()}),
      });
      onContinued(next.id);
    } catch (cause) {setError(cause instanceof Error ? cause.message : "Unable to continue");}
    finally {setBusy(false);}
  }
  async function saveSkill() {
    setBusy(true); setError("");
    try {
      const request = await apiFetch<Need>(`/autonomy/investigations/${id}/save-skill`, {method: "POST"});
      setRequests(rows => [...rows.filter(row => row.id !== request.id), request]);
    } catch (cause) {setError(cause instanceof Error ? cause.message : "Unable to save Skill brief");}
    finally {setBusy(false);}
  }
  return <section className="space-y-3 border-b py-5" aria-label="Investigation continuation and capability requests">
    {parentId && <Link className="text-sm underline" href={`/?investigation=${parentId}`}>Previous run and evidence in this conversation</Link>}
    {requests.length > 0 && <div><h4 className="font-semibold">Capability requests</h4><ul className="mt-2 space-y-3">{requests.map(request =>
      <li key={request.id} className="rounded border p-3"><p>{request.description}</p><p className="mt-1 text-sm text-muted-foreground">{request.reason}</p>
        <Link className="text-sm underline" href={request.studio_url}>Review {request.kind} brief in Studio</Link>
        <p className="text-xs text-muted-foreground">A saved request is not installation proof. Review status in Studio, then return here after enabling the capability.</p></li>)}</ul></div>}
    {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
    {canContinue && terminal && <><label htmlFor={`followup-${id}`} className="block font-semibold">Continue this investigation</label>
      <Textarea id={`followup-${id}`} value={message} onChange={event => setMessage(event.target.value)} placeholder="Add context, ask a follow-up, or ask AI to continue after a missing tool is installed."/>
      <p className="text-xs text-muted-foreground">Starts a new bounded read-only run with linked historical context and current permissions. Model charges and relevant device checks may occur; previous approvals are not reused.</p>
      <div className="flex flex-wrap gap-3"><Button disabled={busy || !message.trim()} onClick={() => void continueRun()}>Continue with AI</Button>
        {status === "completed" && <Button variant="outline" disabled={busy} onClick={() => void saveSkill()}>Save approach as a Skill brief</Button>}</div></>}
  </section>;
}
