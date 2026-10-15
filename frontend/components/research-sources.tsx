import {researchSources} from "@/lib/research";

export function ResearchSources({content}: {content: Record<string, unknown>}) {
  const sources = researchSources(content);
  const research = content.public_research as {status?: string; warning?: string}|undefined;
  if (!sources.length && !research) return null;
  return <details className="mt-3 rounded-lg border border-slate-200 p-3 text-xs">
    <summary className="cursor-pointer font-medium">Research references · {sources.length} sources{research?.status && research.status !== "ok" ? ` · ${research.status.replaceAll("_", " ")}` : ""}</summary>
    <p className="mt-2 text-slate-500">Public reference material, not proof that a device supports these features.</p>
    {research?.warning && <p className="mt-2 text-amber-800">{research.warning}</p>}
    <ul className="mt-2 space-y-2">{sources.map(source => <li key={source.url}>
      <a className="break-all text-violet-700 underline" href={source.url} target="_blank" rel="noopener noreferrer">{source.title}</a>
      {source.retrieved_at && <span className="ml-2 text-slate-500">Read {new Date(source.retrieved_at).toLocaleString()}</span>}
      {source.sha256 && <p className="mt-1 break-all font-mono text-slate-400">SHA-256 {source.sha256}</p>}
    </li>)}</ul>
  </details>;
}
