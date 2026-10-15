"use client";

import Link from "next/link";
import {useState} from "react";
import {StudioNav} from "@/components/studio-nav";
import {useStudioCatalog} from "@/components/use-studio-catalog";
import {Input} from "@/components/ui/input";
import {Button} from "@/components/ui/button";
import {isExtension} from "@/lib/studio-builder";

export default function StudioConversationsPage() {
  const {sessions, warnings, loading, reload} = useStudioCatalog("conversations");
  const [search, setSearch] = useState("");
  const rows = sessions.filter(row => `${row.title} ${row.brief}`.toLowerCase().includes(search.toLowerCase()));
  return <main className="min-h-screen bg-slate-50 p-4 text-slate-800 sm:p-8"><div className="mx-auto max-w-6xl space-y-6">
    <StudioNav current="conversations" /><header><h1 className="text-2xl font-semibold">Conversations</h1><p className="mt-2 text-sm text-slate-500">Reopen an authoring session to continue refining the same capability. Installation status lives in the library.</p></header>
    <div className="flex items-end gap-3"><label className="flex-1 text-sm">Search conversations<Input type="search" className="mt-2 bg-white" value={search} onChange={e => setSearch(e.target.value)} /></label><Button variant="outline" disabled={loading} onClick={() => void reload()}>Refresh</Button></div>
    {warnings.map(message => <p role="status" key={message}>{message}</p>)}
    {loading ? <p role="status">Loading conversations…</p> : <ul className="space-y-3">{rows.map(row => <li key={row.id} className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-5">
      <div className="min-w-0 flex-1"><Link href={`/studio/builder?session=${row.id}`} className="break-words font-medium text-violet-700">{row.title}</Link><p className="mt-2 text-xs text-slate-500">{isExtension(row) ? "MCP server" : row.artifact_kind} · {row.status} · Updated {new Date(row.updated_at).toLocaleString()}</p></div>
      <Link className="text-sm text-violet-700 underline" href={`/studio/builder?session=${row.id}`}>Continue conversation</Link>
    </li>)}</ul>}
    {!loading && !rows.length && <p>No conversations in the loaded results.</p>}
    <p className="text-sm text-slate-500">Grafana authoring uses native agent sessions. <Link className="text-violet-700 underline" href="/investigations">Open AI Operator history</Link> to revisit those runs.</p>
  </div></main>;
}
