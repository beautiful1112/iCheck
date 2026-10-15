"use client";

import Link from "next/link";
import {useState} from "react";
import {StudioNav} from "@/components/studio-nav";
import {StudioMCPTools} from "@/components/studio-mcp-tools";
import {useStudioCatalog} from "@/components/use-studio-catalog";
import {Input} from "@/components/ui/input";
import {Button} from "@/components/ui/button";
import {runtimeLink, publishedVersion} from "@/lib/studio-builder";
import {categories, categoryOf, capabilityState, conversationLink, latestVersion, partitionMCPDrafts, type Category} from "@/lib/studio-library";

export function StudioLibrary() {
  const {artifacts, extensions, tools, servers, warnings, loading, reload} = useStudioCatalog("library");
  const [category, setCategory] = useState<Category | "all">("all"), [search, setSearch] = useState("");
  const [visible, setVisible] = useState(24);
  const {capabilities, drafts} = partitionMCPDrafts(artifacts, extensions);
  const matches = (name: string, description = "") => `${name} ${description}`.toLowerCase().includes(search.trim().toLowerCase());
  const count = (id: Category) => capabilities.filter(row => categoryOf(row) === id).length + (id === "tools" ? tools.length : id === "mcp" ? servers.length : 0);
  return <main className="min-h-screen bg-slate-50 p-4 text-slate-800 sm:p-8"><div className="mx-auto max-w-6xl space-y-6">
    <StudioNav current="library" />
    <header className="flex flex-wrap items-start justify-between gap-4"><div><h1 className="text-2xl font-semibold">Capability Studio</h1><p className="mt-2 text-sm text-slate-500">Your platform’s capabilities, organized by what they do.</p></div>
      <Link href="/studio/builder" className="rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-violet-700">+ Create with AI</Link></header>
    <div className="flex flex-wrap gap-2" aria-label="Capability categories">{[{id: "all", label: "All capabilities"}, ...categories].map(item => <Button key={item.id} variant={category === item.id ? "default" : "outline"}
      aria-pressed={category === item.id} onClick={() => {setCategory(item.id as typeof category); setVisible(24);}}>{item.label}{!loading && <span className="ml-2 text-xs opacity-70">{item.id === "all" ? capabilities.length + tools.length + servers.length : count(item.id as Category)}</span>}</Button>)}</div>
    <div className="flex items-end gap-3"><label className="block flex-1 text-sm">Search capabilities<Input type="search" className="mt-2 bg-white" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by name or description" /></label><Button variant="outline" disabled={loading} onClick={() => void reload()}>Refresh</Button></div>
    {warnings.map(message => <p key={message} role="status" className="rounded-lg bg-amber-50 p-3 text-sm text-amber-900">{message}</p>)}
    {loading ? <p role="status">Loading capability registries…</p> : categories.filter(group => category === "all" || category === group.id).map(group => {
      const packages = capabilities.filter(row => categoryOf(row) === group.id && matches(row.name, row.description));
      const functions = group.id === "tools" ? tools.filter(row => matches(row.name, row.description)) : [];
      const connections = group.id === "mcp" ? servers.filter(row => matches(row.name)) : [];
      const limit = category === "all" ? 6 : visible, total = packages.length + functions.length + connections.length;
      return <section key={group.id} aria-label={group.label} className="space-y-4">
        <header><h2 className="text-lg font-semibold">{group.label} <span className="ml-1 text-sm font-normal text-slate-400">{packages.length + functions.length + connections.length}</span></h2><p className="mt-1 text-sm text-slate-500">{group.hint}</p></header>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{packages.slice(0, limit).map(row => {
          const installed = extensions?.find(item => item.artifact_id === row.id), latest = latestVersion(row), published = publishedVersion(row), use = runtimeLink(row), conversation = conversationLink(row);
          return <article key={row.id} className="flex min-w-0 flex-col gap-3 rounded-xl border border-slate-200 bg-white p-5">
            <span className="w-fit rounded bg-slate-100 px-2 py-1 text-xs font-medium">{capabilityState(row, extensions)}</span>
            <h3 className="break-words font-semibold">{row.name}</h3><p className="line-clamp-3 text-sm text-slate-500">{row.description}</p>
            <p className="text-xs text-slate-500">{group.id === "mcp" ? "Generated MCP package" : row.kind}{latest ? ` · Latest v${latest.version} (${latest.status})` : " · No version"}{published && published.id !== latest?.id ? ` · Published v${published.version}` : ""}</p>
            {group.id === "mcp" && <StudioMCPTools version={latest} />}
            {installed && <p className="text-xs">Active v{row.versions.find(v => v.id === installed.active_version_id)?.version ?? "unknown"} · Last runtime check: {installed.last_health_status}{installed.active_version_id !== latest?.id ? " · Latest draft is not active" : ""}</p>}
            <div className="mt-auto flex flex-wrap gap-4 pt-2 text-sm text-violet-700">
              {group.id === "mcp" ? <Link className="font-medium underline" href={`/studio/mcp?artifact=${row.id}`}>Manage server</Link> : use && <Link className="underline" href={use}>{row.kind === "collector" ? "Choose target" : "Use capability"}</Link>}
              {conversation && <Link className="underline" href={conversation}>Conversation</Link>}
              <Link className="underline" href={`/studio/artifacts?artifact=${row.id}`}>Versions</Link>
            </div>
          </article>;
        })}{connections.slice(0, Math.max(0, limit-packages.length)).map(row => <article key={row.id} className="space-y-3 rounded-xl border border-slate-200 bg-white p-5"><span className="rounded bg-slate-100 px-2 py-1 text-xs">External connection · {row.enabled ? "Enabled" : "Disabled"}</span><h3 className="break-words font-semibold">{row.name}</h3><p className="text-sm text-slate-500">Last health check: {row.last_health_status || "Not checked"} · {row.last_tool_count ?? "Unknown"} discovered tools</p><Link className="inline-block text-sm text-violet-700 underline" href="/settings/mcp">Manage connection</Link></article>)}
          {functions.slice(0, Math.max(0, limit-packages.length)).map(row => <article key={row.id} className="space-y-3 rounded-xl border border-slate-200 bg-white p-5"><span className="rounded bg-slate-100 px-2 py-1 text-xs">Registered · {row.enabled ? "Enabled" : "Disabled"}</span><h3 className="break-words font-semibold">{row.name}</h3><p className="line-clamp-3 text-sm text-slate-500">{row.description}</p><p className="text-xs text-slate-500">{row.transport === "internal" ? "Built-in function" : "MCP function"} · {row.read_only ? "Read-only" : "Change approval required"}</p><Link className="inline-block text-sm text-violet-700 underline" href="/settings/agents">Agent access settings</Link></article>)}
        </div>
        {total > limit && <Button variant="outline" onClick={() => {if (category === "all") {setCategory(group.id); setVisible(24);} else setVisible(value => value + 24);}}>{category === "all" ? `View all ${total} ${group.label.toLowerCase()}` : `Show more (${Math.min(limit,total)} of ${total})`}</Button>}
        {!packages.length && !functions.length && !connections.length && <p className="rounded-xl border border-dashed border-slate-300 p-5 text-sm text-slate-500">{warnings.length ? "No entries available in the loaded results." : search ? "No matches in this category." : group.id === "mcp" ? "No validated or installed server packages. Unvalidated drafts are retained below." : "No capabilities in this category yet."}</p>}
        {group.id === "mcp" && drafts.length > 0 && <details className="rounded-xl border border-dashed border-slate-300 bg-white p-4"><summary className="cursor-pointer text-sm font-medium">Unvalidated MCP drafts ({drafts.filter(row => matches(row.name,row.description)).length})</summary>
          <p className="mt-3 text-sm text-slate-500">These drafts have never passed package validation. They are retained for revision and history, not counted as server packages above. Tools inside a draft are not separate servers.</p>
          <ul className="mt-3 space-y-3">{drafts.filter(row => matches(row.name,row.description)).map(row => <li key={row.id} className="space-y-2 border-t border-slate-100 pt-3"><p className="break-words text-sm font-medium">{row.name}</p><p className="text-xs text-slate-500">Unvalidated draft · {capabilityState(row, extensions)}</p><div className="flex flex-wrap gap-4 text-sm text-violet-700">{conversationLink(row) && <Link className="underline" href={conversationLink(row)!}>Review draft conversation</Link>}<Link className="underline" href={`/studio/artifacts?artifact=${row.id}`}>Draft history</Link></div></li>)}</ul>
        </details>}
      </section>;
    })}
    <footer className="flex flex-wrap gap-5 border-t border-slate-200 pt-5 text-sm text-slate-500"><Link href="/studio/workflows">Workflow runs & triggers</Link><Link href="/settings/mcp">External MCP connections</Link><Link href="/settings/ai">AI settings</Link><Link href="/studio/artifacts">Advanced version library</Link></footer>
  </div></main>;
}
