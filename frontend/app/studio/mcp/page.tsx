"use client";

import Link from "next/link";
import {useState} from "react";
import {StudioNav} from "@/components/studio-nav";
import {StudioExtension} from "@/components/studio-extension";
import {StudioMCPTools} from "@/components/studio-mcp-tools";
import {useStudioCatalog} from "@/components/use-studio-catalog";
import {permits} from "@/lib/studio-builder";
import {categoryOf, capabilityState, conversationLink} from "@/lib/studio-library";

export default function StudioMCPPage() {
  const {artifacts, principal, extensions, warnings, loading, reload} = useStudioCatalog("mcp");
  const [chosen, setChosen] = useState("");
  const artifact = artifacts[0], versions = [...(artifact?.versions || [])].sort((a,b) => b.version-a.version);
  const version = versions.find(row => row.id === chosen) || versions[0];
  const definition = version?.definition, spec = definition?.spec;
  const manage = Boolean(principal?.authorization_scope.all && ["capabilities.manage", "assets.activate", "assets.read", "tools.admin"].every(permission => permits(principal, permission)));
  const conversation = artifact && conversationLink(artifact);
  return <main className="min-h-screen bg-slate-50 p-4 text-slate-800 sm:p-8"><div className="mx-auto max-w-5xl space-y-6">
    <StudioNav current="mcp" />
    <header><p className="mb-2 text-sm text-slate-500">MCP server</p><h1 className="break-words text-2xl font-semibold">{artifact?.name || "Generated MCP server"}</h1><p className="mt-2 text-sm text-slate-500">Review what AI created, approve once, and use its tools across your authorized inventory.</p></header>
    {warnings.map(message => <p key={message} role="status" className="rounded-lg bg-amber-50 p-3 text-sm">{message}</p>)}
    {loading && <p role="status">Loading package and installation status…</p>}
    {!artifact || categoryOf(artifact) !== "mcp" ? !loading && <p role="alert">No generated MCP package found. Choose a server from the <Link className="underline" href="/studio">library</Link>.</p> : <>
      <section aria-label="MCP package status" className="space-y-4 rounded-xl border border-slate-200 bg-white p-5"><h2 className="text-lg font-semibold">{capabilityState(artifact, extensions)}</h2><p className="text-sm text-slate-500">{artifact.description}</p>
        <div className="flex flex-wrap gap-4 text-sm text-violet-700">{conversation && <Link className="underline" href={conversation}>Edit in conversation</Link>}<Link className="underline" href={`/studio/artifacts?artifact=${artifact.id}`}>Source, versions & export</Link></div>
        <p className="text-sm text-slate-500">Version {version?.version} · {version?.status}</p>
        <StudioMCPTools version={version} />
        <details><summary className="cursor-pointer text-sm text-slate-500">Review a different version</summary><label className="mt-2 block text-sm">Package version<select className="mt-2 block w-full rounded border border-slate-300 bg-white p-2" value={version?.id || ""} onChange={e => setChosen(e.target.value)}>{versions.map(row => <option key={row.id} value={row.id}>Version {row.version} · {row.status}</option>)}</select></label><p className="mt-2 text-xs">Editing or selecting a version does not change the installed version.</p></details>
      </section>
      {version && spec && typeof spec === "object" && definition?.format_version === "icheck.mcp-extension/v1" && ["validated", "published"].includes(version.status) ? <StudioExtension key={`${principal?.subject}:${artifact.id}:${version.id}`}
        artifactId={artifact.id} versionId={version.id} spec={spec as Record<string, unknown>} canWrite={manage} canDownload={permits(principal, "assets.read") && permits(principal, "capabilities.manage")} onChanged={reload} /> : <p className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm">This version has no validated executable package. Continue its conversation to resolve validation before installing.</p>}
    </>}
  </div></main>;
}
