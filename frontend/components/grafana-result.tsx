import Link from "next/link";
import { grafanaResourceLinks, proposalReference } from "@/lib/grafana-plugin";

export function GrafanaResult({result, toolName}: {result: unknown; toolName?: string}) {
  const proposal = proposalReference(result);
  const links = grafanaResourceLinks(result, toolName);
  if (!proposal && !links.length) return null;
  return <aside className="mt-4 rounded-xl border border-violet-200 bg-violet-50 p-4 text-sm">
    <p className="font-medium">Grafana: {proposal?.title || "Saved resources"}</p>
    {proposal ? <><p className="mt-1 text-xs text-muted-foreground">{proposal.status === "proposed" ?
      "Ready for your review. Grafana has not been changed." : `Recorded state: ${proposal.status}. Review the retained result.`}</p>
      <Link className="mt-2 inline-block text-violet-700 underline" href={`/dashboards?change=${proposal.id}`}>Review dashboard change</Link></> : null}
    {links.map(link => <p key={link.url} className="mt-2"><a className="text-violet-700 underline" href={link.url}>{link.title}</a></p>)}
    {links.length ? <p className="mt-2 text-xs text-muted-foreground">Saved Grafana URLs are not evidence of fresh collection. Variables filter the shared dataset; they do not enforce device isolation.</p> : null}
  </aside>;
}
